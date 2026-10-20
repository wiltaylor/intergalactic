//! End-to-end: a lighthouse and several engines on loopback, with in-memory
//! TUN devices standing in for the operating system.

use ig_core::packet::{build_tcp, build_udp, TCP_SYN};
use ig_core::tun::channel::{ChannelTun, OsSide};
use ig_core::{Engine, EngineConfig, EngineEvent, Membership, NoProtector, TunScope};
use ig_lighthouse::{Lighthouse, LighthouseConfig};
use ig_proto::admin::{AdminRequest, AdminResponse};
use ig_proto::control::NetworkInfo;
use ig_proto::ipc::PeerPath;
use ig_proto::{Invite, Keypair, Policy, Rule};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_test_writer()
        .try_init();
}

async fn lighthouse() -> Lighthouse {
    let lh = Lighthouse::start(LighthouseConfig {
        keypair: Keypair::generate(),
        listen: "127.0.0.1:0".parse().unwrap(),
        public_host: "127.0.0.1".into(),
        public_port: 0,
        state_path: None,
    })
    .await
    .unwrap();
    lh
}

fn create_network(lh: &Lighthouse, name: &str, cidr: &str) {
    match lh.admin(AdminRequest::NetworkCreate { name: name.into(), cidr: cidr.parse().unwrap() }) {
        AdminResponse::Networks(_) => {}
        other => panic!("create failed: {other:?}"),
    }
}

fn invite(lh: &Lighthouse, network: &str, uses: u32) -> Invite {
    match lh.admin(AdminRequest::InviteCreate { network: network.into(), uses, ttl_secs: 3600, label: String::new() }) {
        AdminResponse::Invite { invite, .. } => {
            let mut inv: Invite = invite.parse().unwrap();
            // The in-memory lighthouse bound port 0; patch in the real port.
            inv.port = lh.local_addr().port();
            inv
        }
        other => panic!("invite failed: {other:?}"),
    }
}

struct Node {
    engine: Engine,
    events: mpsc::Receiver<EngineEvent>,
    keypair: Keypair,
}

async fn node(name: &str, memberships: Vec<Membership>, relay_only: bool) -> Node {
    node_with_key(name, Keypair::generate(), memberships, relay_only).await
}

async fn node_with_key(name: &str, keypair: Keypair, memberships: Vec<Membership>, relay_only: bool) -> Node {
    let (engine, events) = Engine::start(
        EngineConfig {
            keypair: keypair.clone(),
            hostname: name.into(),
            os: "test".into(),
            udp_port: 0,
            memberships,
            persistent_keepalive: Some(25),
            relay_only,
        },
        Arc::new(NoProtector),
    )
    .await
    .unwrap();
    Node { engine, events, keypair }
}

/// Join and attach a per-network channel TUN. Returns the OS side.
async fn join_with_tun(n: &Node, inv: &Invite) -> (NetworkInfo, OsSide) {
    let info = n.engine.join(inv).await.expect("join");
    let (tun, os) = ChannelTun::new(&format!("tun-{}", info.name));
    n.engine.attach_tun(TunScope::Network(info.id), Arc::new(tun)).unwrap();
    (info, os)
}

async fn wait_for<F: FnMut() -> bool>(what: &str, mut f: F) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !f() {
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for {what}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn recv_packet(os: &mut OsSide, timeout: Duration) -> Option<Vec<u8>> {
    tokio::time::timeout(timeout, os.from_tun.recv()).await.ok().flatten()
}

/// Send until a packet shows up on the other side (the first packet of a
/// session is queued behind the handshake, so retries are normal).
async fn deliver(from: &OsSide, to: &mut OsSide, pkt: Vec<u8>) -> Vec<u8> {
    for _ in 0..40 {
        from.to_tun.send(pkt.clone()).await.unwrap();
        if let Some(p) = recv_packet(to, Duration::from_millis(250)).await {
            return p;
        }
    }
    panic!("packet never delivered");
}

#[tokio::test]
async fn two_nodes_exchange_packets_and_go_direct() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "dev", "10.90.0.0/24");
    let inv = invite(&lh, "dev", 2);

    let a = node("alpha", vec![], false).await;
    let b = node("bravo", vec![], false).await;
    let (ia, os_a) = join_with_tun(&a, &inv).await;
    let (ib, mut os_b) = join_with_tun(&b, &inv).await;
    assert_eq!(ia.id, ib.id);
    assert_ne!(ia.address, ib.address);
    assert!(ia.cidr.contains(&ia.address));

    wait_for("peers visible", || a.engine.status().peers.len() == 1 && b.engine.status().peers.len() == 1).await;

    let pkt = build_udp(ia.address, 5000, ib.address, 6000, b"hello from alpha");
    let got = deliver(&os_a, &mut os_b, pkt.clone()).await;
    assert_eq!(got, pkt);

    // Reply direction.
    let reply = build_udp(ib.address, 6000, ia.address, 5000, b"hello from bravo");
    let mut os_a = os_a;
    let got = deliver(&os_b, &mut os_a, reply.clone()).await;
    assert_eq!(got, reply);

    wait_for("direct path", || {
        a.engine.status().peers[0].path == PeerPath::Direct && b.engine.status().peers[0].path == PeerPath::Direct
    })
    .await;
    let st = a.engine.status();
    assert!(st.peers[0].tx_bytes > 0 && st.peers[0].rx_bytes > 0);
    assert_eq!(st.peers[0].hostname, "bravo");
    assert!(st.networks[0].lighthouse_connected);

    // A third node cannot use the exhausted invite.
    let c = node("charlie", vec![], false).await;
    let err = c.engine.join(&inv).await.err().expect("invite should be used up");
    assert!(err.to_string().contains("invite"), "{err}");

    a.engine.shutdown().await;
    b.engine.shutdown().await;
    c.engine.shutdown().await;
    lh.shutdown().await;
}

#[tokio::test]
async fn relay_only_nodes_still_talk() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "dev", "10.91.0.0/24");
    let inv = invite(&lh, "dev", 2);
    let a = node("alpha", vec![], true).await;
    let b = node("bravo", vec![], true).await;
    let (ia, os_a) = join_with_tun(&a, &inv).await;
    let (ib, mut os_b) = join_with_tun(&b, &inv).await;
    wait_for("peers visible", || a.engine.status().peers.len() == 1 && b.engine.status().peers.len() == 1).await;
    // The lighthouse must know both UDP addresses before it can relay; probes
    // are sent as soon as the control channel is up.
    let pkt = build_udp(ia.address, 1, ib.address, 2, b"via relay");
    let got = deliver(&os_a, &mut os_b, pkt.clone()).await;
    assert_eq!(got, pkt);
    wait_for("relay path reported", || a.engine.status().peers[0].path == PeerPath::Relay).await;
    assert_eq!(a.engine.status().peers[0].endpoint, None);
    a.engine.shutdown().await;
    b.engine.shutdown().await;
    lh.shutdown().await;
}

#[tokio::test]
async fn policy_blocks_unsolicited_traffic_but_allows_rules_and_replies() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "game", "10.92.0.0/24");
    let inv = invite(&lh, "game", 2);
    let a = node("alpha", vec![], false).await;
    let b = node("bravo", vec![], false).await;
    let (ia, mut os_a) = join_with_tun(&a, &inv).await;
    let (ib, mut os_b) = join_with_tun(&b, &inv).await;
    wait_for("peers visible", || a.engine.status().peers.len() == 1 && b.engine.status().peers.len() == 1).await;

    // Establish the session while the policy is open.
    let warm = build_udp(ia.address, 1, ib.address, 2, b"warm");
    deliver(&os_a, &mut os_b, warm).await;

    // Lock the network down to SSH only.
    let policy = Policy { rules: vec!["tcp:22".parse::<Rule>().unwrap()] };
    assert!(matches!(lh.admin(AdminRequest::NetworkSetPolicy { network: "game".into(), policy: policy.clone() }), AdminResponse::Ok));
    wait_for("policy pushed", || {
        a.engine.status().networks[0].info.policy == policy && b.engine.status().networks[0].info.policy == policy
    })
    .await;

    // Unsolicited UDP is dropped.
    os_a.to_tun.send(build_udp(ia.address, 1, ib.address, 2, b"blocked")).await.unwrap();
    assert!(recv_packet(&mut os_b, Duration::from_millis(500)).await.is_none());

    // SSH SYN is allowed...
    let syn = build_tcp(ia.address, 40000, ib.address, 22, TCP_SYN);
    assert_eq!(deliver(&os_a, &mut os_b, syn.clone()).await, syn);
    // ...and so is the SYN-ACK coming back (a reply to a tracked flow).
    let synack = build_tcp(ib.address, 22, ia.address, 40000, TCP_SYN | 0x10);
    assert_eq!(deliver(&os_b, &mut os_a, synack.clone()).await, synack);

    // HTTP SYN is not.
    os_a.to_tun.send(build_tcp(ia.address, 40001, ib.address, 80, TCP_SYN)).await.unwrap();
    assert!(recv_packet(&mut os_b, Duration::from_millis(500)).await.is_none());

    a.engine.shutdown().await;
    b.engine.shutdown().await;
    lh.shutdown().await;
}

#[tokio::test]
async fn networks_are_isolated_and_a_node_can_be_in_several() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "dev", "10.93.0.0/24");
    create_network(&lh, "game", "10.94.0.0/24");
    let dev_inv = invite(&lh, "dev", 5);
    let game_inv = invite(&lh, "game", 5);

    let a = node("alpha", vec![], false).await; // dev + game
    let b = node("bravo", vec![], false).await; // dev only
    let c = node("charlie", vec![], false).await; // game only
    let (a_dev, mut os_a_dev) = join_with_tun(&a, &dev_inv).await;
    let (a_game, mut os_a_game) = join_with_tun(&a, &game_inv).await;
    let (b_dev, os_b) = join_with_tun(&b, &dev_inv).await;
    let (c_game, os_c) = join_with_tun(&c, &game_inv).await;

    wait_for("alpha sees two peers", || a.engine.status().peers.len() == 2).await;
    wait_for("bravo and charlie see one peer each", || {
        b.engine.status().peers.len() == 1 && c.engine.status().peers.len() == 1
    })
    .await;
    assert_eq!(a.engine.memberships().len(), 2);

    // bravo -> alpha over dev lands on alpha's dev interface.
    let p1 = build_udp(b_dev.address, 1, a_dev.address, 2, b"dev");
    assert_eq!(deliver(&os_b, &mut os_a_dev, p1.clone()).await, p1);
    // charlie -> alpha over game lands on alpha's game interface.
    let p2 = build_udp(c_game.address, 1, a_game.address, 2, b"game");
    assert_eq!(deliver(&os_c, &mut os_a_game, p2.clone()).await, p2);

    // charlie has no route to the dev network at all.
    os_c.to_tun.send(build_udp(c_game.address, 1, a_dev.address, 2, b"leak?")).await.unwrap();
    assert!(recv_packet(&mut os_a_dev, Duration::from_millis(400)).await.is_none());
    // charlie cannot spoof a dev source address either: alpha only accepts
    // charlie's game address as a source.
    os_c.to_tun.send(build_udp(Ipv4Addr::new(10, 93, 0, 200), 1, a_game.address, 2, b"spoof")).await.unwrap();
    assert!(recv_packet(&mut os_a_game, Duration::from_millis(400)).await.is_none());

    // Leaving game removes charlie from alpha's view.
    a.engine.leave(a_game.id).await.unwrap();
    wait_for("alpha down to one peer", || a.engine.status().peers.len() == 1).await;
    wait_for("charlie has no peers", || c.engine.status().peers.is_empty()).await;
    assert_eq!(a.engine.memberships().len(), 1);

    a.engine.shutdown().await;
    b.engine.shutdown().await;
    c.engine.shutdown().await;
    lh.shutdown().await;
}

#[tokio::test]
async fn restart_resumes_memberships_and_admin_can_kick() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "dev", "10.95.0.0/24");
    let inv = invite(&lh, "dev", 5);
    let mut a = node("alpha", vec![], false).await;
    let b = node("bravo", vec![], false).await;
    let (ia, _os_a) = join_with_tun(&a, &inv).await;
    let (_ib, _os_b) = join_with_tun(&b, &inv).await;

    // The embedder learns about memberships through events.
    let mut saved: Vec<Membership> = Vec::new();
    while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(300), a.events.recv()).await {
        if let EngineEvent::MembershipsChanged(m) = ev {
            saved = m;
        }
    }
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].network.address, ia.address);

    a.engine.shutdown().await;
    let key = a.keypair.clone();
    let a2 = node_with_key("alpha", key, saved, false).await;
    assert_eq!(a2.engine.memberships().len(), 1);
    wait_for("resumed node sees bravo", || a2.engine.status().peers.len() == 1).await;
    wait_for("same address kept", || a2.engine.status().networks[0].info.address == ia.address).await;

    // Admin removes bravo; alpha loses the peer, bravo loses the network.
    let r = lh.admin(AdminRequest::NodeRemove { network: "dev".into(), node: b.engine.node_id() });
    assert!(matches!(r, AdminResponse::Ok));
    wait_for("alpha has no peers", || a2.engine.status().peers.is_empty()).await;
    wait_for("bravo has no networks", || b.engine.memberships().is_empty()).await;

    match lh.admin(AdminRequest::NodeList { network: None }) {
        AdminResponse::Nodes(nodes) => {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].hostname, "alpha");
            assert!(nodes[0].online);
        }
        other => panic!("{other:?}"),
    }
    a2.engine.shutdown().await;
    b.engine.shutdown().await;
    lh.shutdown().await;
}
