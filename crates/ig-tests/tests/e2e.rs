//! End-to-end: a lighthouse and several engines on loopback, with in-memory
//! TUN devices standing in for the operating system.

use ig_core::packet::{build_tcp, build_udp, TCP_SYN};
use ig_core::tun::channel::{ChannelTun, OsSide};
use ig_core::{Engine, EngineConfig, EngineEvent, Membership, NoProtector, TunScope};
use ig_lighthouse::{Lighthouse, LighthouseConfig};
use ig_proto::admin::{AdminRequest, AdminResponse};
use ig_proto::control::NetworkInfo;
use ig_proto::ipc::PeerPath;
use ig_proto::{Invite, Keypair, Policy, RelayLimit, Rule};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_test_writer()
        .try_init();
}

async fn lighthouse() -> Lighthouse {
    Lighthouse::start(LighthouseConfig {
        keypair: Keypair::generate(),
        listen: "127.0.0.1:0".parse().unwrap(),
        public_host: "127.0.0.1".into(),
        public_port: 0,
        state_path: None,
        dns_domain: "ig.test".into(),
        default_relay_limit: RelayLimit::unlimited(),
    })
    .await
    .unwrap()
}

fn create_network(lh: &Lighthouse, name: &str, cidr: &str, cidr6: Option<&str>) {
    let req = AdminRequest::NetworkCreate {
        name: name.into(),
        cidr: cidr.parse().unwrap(),
        cidr6: cidr6.map(|c| c.parse().unwrap()),
    };
    match lh.admin(req) {
        AdminResponse::Networks(_) => {}
        other => panic!("create failed: {other:?}"),
    }
}

fn invite(lh: &Lighthouse, network: &str, uses: u32) -> Invite {
    match lh.admin(AdminRequest::InviteCreate {
        network: network.into(),
        uses,
        ttl_secs: 3600,
        label: String::new(),
    }) {
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

async fn node_with_key(
    name: &str,
    keypair: Keypair,
    memberships: Vec<Membership>,
    relay_only: bool,
) -> Node {
    let (engine, events) = Engine::start(
        EngineConfig {
            keypair: keypair.clone(),
            hostname: name.into(),
            os: "test".into(),
            udp_port: 0,
            memberships,
            persistent_keepalive: Some(25),
            relay_only,
            gateway: false,
        },
        Arc::new(NoProtector),
    )
    .await
    .unwrap();
    Node {
        engine,
        events,
        keypair,
    }
}

/// Join and attach a per-network channel TUN. Returns the OS side.
async fn join_with_tun(n: &Node, inv: &Invite) -> (NetworkInfo, OsSide) {
    let info = n.engine.join(inv).await.expect("join");
    let (tun, os) = ChannelTun::new(&format!("tun-{}", info.name));
    n.engine
        .attach_tun(TunScope::Network(info.id), Arc::new(tun))
        .unwrap();
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
    tokio::time::timeout(timeout, os.from_tun.recv())
        .await
        .ok()
        .flatten()
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

fn v4(info: &NetworkInfo) -> IpAddr {
    IpAddr::V4(info.address)
}

fn v6(info: &NetworkInfo) -> IpAddr {
    IpAddr::V6(info.address6.expect("network has IPv6"))
}

#[tokio::test]
async fn two_nodes_exchange_packets_and_go_direct() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "dev", "10.90.0.0/24", None);
    let inv = invite(&lh, "dev", 2);

    let a = node("alpha", vec![], false).await;
    let b = node("bravo", vec![], false).await;
    let (ia, os_a) = join_with_tun(&a, &inv).await;
    let (ib, mut os_b) = join_with_tun(&b, &inv).await;
    assert_eq!(ia.id, ib.id);
    assert_ne!(ia.address, ib.address);
    assert!(ia.cidr.contains(&ia.address));
    // First host is the DNS responder, never a member.
    assert_ne!(ia.address, ia.dns_server_v4());
    assert_ne!(ib.address, ib.dns_server_v4());
    assert_eq!(ia.dns_domain, "ig.test");
    assert_eq!(ia.fqdn(), "alpha.dev.ig.test");

    wait_for("peers visible", || {
        a.engine.status().peers.len() == 1 && b.engine.status().peers.len() == 1
    })
    .await;

    let pkt = build_udp(v4(&ia), 5000, v4(&ib), 6000, b"hello from alpha");
    let got = deliver(&os_a, &mut os_b, pkt.clone()).await;
    assert_eq!(got, pkt);

    // Reply direction.
    let reply = build_udp(v4(&ib), 6000, v4(&ia), 5000, b"hello from bravo");
    let mut os_a = os_a;
    let got = deliver(&os_b, &mut os_a, reply.clone()).await;
    assert_eq!(got, reply);

    wait_for("direct path", || {
        a.engine.status().peers[0].path == PeerPath::Direct
            && b.engine.status().peers[0].path == PeerPath::Direct
    })
    .await;
    let st = a.engine.status();
    assert!(st.peers[0].tx_bytes > 0 && st.peers[0].rx_bytes > 0);
    assert_eq!(st.peers[0].hostname, "bravo");
    assert_eq!(
        st.peers[0].names,
        vec![(ia.id, "bravo.dev.ig.test".to_string())]
    );
    assert!(st.networks[0].lighthouse_connected);

    // A third node cannot use the exhausted invite.
    let c = node("charlie", vec![], false).await;
    let err = c
        .engine
        .join(&inv)
        .await
        .expect_err("invite should be used up");
    assert!(err.to_string().contains("invite"), "{err}");

    a.engine.shutdown().await;
    b.engine.shutdown().await;
    c.engine.shutdown().await;
    lh.shutdown().await;
}

#[tokio::test]
async fn ipv6_addresses_work_end_to_end() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "six", "10.96.0.0/24", Some("fd96:1::/64"));
    let inv = invite(&lh, "six", 2);
    let a = node("alpha", vec![], false).await;
    let b = node("bravo", vec![], false).await;
    let (ia, os_a) = join_with_tun(&a, &inv).await;
    let (ib, mut os_b) = join_with_tun(&b, &inv).await;
    // v4 and v6 host numbers line up.
    let host = u32::from(ia.address) - u32::from(ia.cidr.network());
    assert_eq!(
        u128::from(ia.address6.unwrap()) - u128::from(ia.cidr6.unwrap().network()),
        host as u128
    );
    wait_for("peers visible", || {
        a.engine.status().peers.len() == 1 && b.engine.status().peers.len() == 1
    })
    .await;
    let pkt = build_udp(v6(&ia), 7000, v6(&ib), 7001, b"over six");
    assert_eq!(deliver(&os_a, &mut os_b, pkt.clone()).await, pkt);
    // v4 still works in the same session.
    let pkt4 = build_udp(v4(&ia), 7000, v4(&ib), 7001, b"over four");
    assert_eq!(deliver(&os_a, &mut os_b, pkt4.clone()).await, pkt4);
    // Peer status lists both families.
    let st = a.engine.status();
    assert_eq!(st.peers[0].addresses.len(), 2);
    a.engine.shutdown().await;
    b.engine.shutdown().await;
    lh.shutdown().await;
}

fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut q = vec![0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

#[tokio::test]
async fn dns_names_resolve_through_the_tun() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "Dev Net", "10.97.0.0/24", Some("fd97::/64"));
    let inv = invite(&lh, "Dev Net", 2);
    let a = node("Alpha Laptop", vec![], false).await;
    let b = node("bravo", vec![], false).await;
    let (ia, mut os_a) = join_with_tun(&a, &inv).await;
    let (ib, _os_b) = join_with_tun(&b, &inv).await;
    assert_eq!(ia.fqdn(), "alpha-laptop.dev-net.ig.test");
    wait_for("peers visible", || a.engine.status().peers.len() == 1).await;

    // A query for bravo's full name, sent to the network's DNS address.
    let dns4 = IpAddr::V4(ia.dns_server_v4());
    let q = build_udp(
        v4(&ia),
        40000,
        dns4,
        53,
        &dns_query("bravo.dev-net.ig.test", 1),
    );
    os_a.to_tun.send(q).await.unwrap();
    let reply = recv_packet(&mut os_a, Duration::from_secs(2))
        .await
        .expect("dns reply");
    let f = ig_core::packet::parse_flow(&reply).unwrap();
    assert_eq!((f.src, f.dst, f.sport, f.dport), (dns4, v4(&ia), 53, 40000));
    let payload = &reply[f.l4_offset + 8..];
    assert_eq!(&payload[0..2], &[0xbe, 0xef]);
    assert_eq!(payload[3] & 0x0f, 0, "NOERROR");
    assert_eq!(&payload[payload.len() - 4..], &ib.address.octets());

    // AAAA over the IPv6 responder, using the short name.
    let dns6 = IpAddr::V6(ia.dns_server_v6().unwrap());
    let q6 = build_udp(v6(&ia), 40001, dns6, 53, &dns_query("bravo.ig.test", 28));
    os_a.to_tun.send(q6).await.unwrap();
    let reply6 = recv_packet(&mut os_a, Duration::from_secs(2))
        .await
        .expect("dns reply v6");
    let f6 = ig_core::packet::parse_flow(&reply6).unwrap();
    assert_eq!((f6.src, f6.dst), (dns6, v6(&ia)));
    let payload6 = &reply6[f6.l4_offset + 8..];
    assert_eq!(
        &payload6[payload6.len() - 16..],
        &ib.address6.unwrap().octets()
    );

    // Our own name resolves too; unknown names are NXDOMAIN.
    let qs = build_udp(
        v4(&ia),
        40002,
        dns4,
        53,
        &dns_query("alpha-laptop.dev-net.ig.test", 1),
    );
    os_a.to_tun.send(qs).await.unwrap();
    let rs = recv_packet(&mut os_a, Duration::from_secs(2))
        .await
        .unwrap();
    let fs = ig_core::packet::parse_flow(&rs).unwrap();
    assert_eq!(&rs[rs.len() - 4..], &ia.address.octets());
    assert_eq!(fs.dport, 40002);
    let qn = build_udp(
        v4(&ia),
        40003,
        dns4,
        53,
        &dns_query("nobody.dev-net.ig.test", 1),
    );
    os_a.to_tun.send(qn).await.unwrap();
    let rn = recv_packet(&mut os_a, Duration::from_secs(2))
        .await
        .unwrap();
    let fn_ = ig_core::packet::parse_flow(&rn).unwrap();
    assert_eq!(rn[fn_.l4_offset + 8 + 3] & 0x0f, 3, "NXDOMAIN");

    a.engine.shutdown().await;
    b.engine.shutdown().await;
    lh.shutdown().await;
}

#[tokio::test]
async fn relay_only_nodes_still_talk() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "dev", "10.91.0.0/24", None);
    let inv = invite(&lh, "dev", 2);
    let a = node("alpha", vec![], true).await;
    let b = node("bravo", vec![], true).await;
    let (ia, os_a) = join_with_tun(&a, &inv).await;
    let (ib, mut os_b) = join_with_tun(&b, &inv).await;
    wait_for("peers visible", || {
        a.engine.status().peers.len() == 1 && b.engine.status().peers.len() == 1
    })
    .await;
    let pkt = build_udp(v4(&ia), 1, v4(&ib), 2, b"via relay");
    let got = deliver(&os_a, &mut os_b, pkt.clone()).await;
    assert_eq!(got, pkt);
    wait_for("relay path reported", || {
        a.engine.status().peers[0].path == PeerPath::Relay
    })
    .await;
    assert_eq!(a.engine.status().peers[0].endpoint, None);
    a.engine.shutdown().await;
    b.engine.shutdown().await;
    lh.shutdown().await;
}

#[tokio::test]
async fn relay_limit_caps_relayed_traffic_per_network() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "slow", "10.98.0.0/24", None);
    let inv = invite(&lh, "slow", 2);
    let a = node("alpha", vec![], true).await;
    let b = node("bravo", vec![], true).await;
    let (ia, os_a) = join_with_tun(&a, &inv).await;
    let (ib, mut os_b) = join_with_tun(&b, &inv).await;
    wait_for("peers visible", || {
        a.engine.status().peers.len() == 1 && b.engine.status().peers.len() == 1
    })
    .await;
    // Warm the session while unlimited.
    deliver(&os_a, &mut os_b, build_udp(v4(&ia), 1, v4(&ib), 2, b"warm")).await;

    // 64 kbit/s per node: one second of burst is 8000 bytes, about 7 of our packets.
    let limit = RelayLimit {
        per_node_kbps: 64,
        total_kbps: 0,
    };
    assert!(matches!(
        lh.admin(AdminRequest::NetworkSetRelayLimit {
            network: "slow".into(),
            limit
        }),
        AdminResponse::Ok
    ));
    wait_for("limit pushed", || {
        a.engine.status().networks[0].info.relay_limit == limit
    })
    .await;

    let payload = vec![0u8; 1000];
    for i in 0..100u16 {
        os_a.to_tun
            .send(build_udp(v4(&ia), 100 + i, v4(&ib), 2, &payload))
            .await
            .unwrap();
    }
    let mut delivered = 0;
    while recv_packet(&mut os_b, Duration::from_millis(300))
        .await
        .is_some()
    {
        delivered += 1;
    }
    assert!(delivered > 0, "some packets must pass");
    assert!(
        delivered < 40,
        "limit should drop most of 100 packets, got {delivered}"
    );

    // Back to unlimited: everything passes again.
    let open = RelayLimit::unlimited();
    assert!(matches!(
        lh.admin(AdminRequest::NetworkSetRelayLimit {
            network: "slow".into(),
            limit: open
        }),
        AdminResponse::Ok
    ));
    wait_for("limit lifted", || {
        a.engine.status().networks[0].info.relay_limit == open
    })
    .await;
    for i in 0..30u16 {
        os_a.to_tun
            .send(build_udp(v4(&ia), 300 + i, v4(&ib), 2, &payload))
            .await
            .unwrap();
    }
    let mut delivered = 0;
    while recv_packet(&mut os_b, Duration::from_millis(300))
        .await
        .is_some()
    {
        delivered += 1;
    }
    assert!(
        delivered >= 25,
        "unlimited relay should pass nearly all, got {delivered}"
    );

    a.engine.shutdown().await;
    b.engine.shutdown().await;
    lh.shutdown().await;
}

#[tokio::test]
async fn policy_blocks_unsolicited_traffic_but_allows_rules_and_replies() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "game", "10.92.0.0/24", None);
    let inv = invite(&lh, "game", 2);
    let a = node("alpha", vec![], false).await;
    let b = node("bravo", vec![], false).await;
    let (ia, mut os_a) = join_with_tun(&a, &inv).await;
    let (ib, mut os_b) = join_with_tun(&b, &inv).await;
    wait_for("peers visible", || {
        a.engine.status().peers.len() == 1 && b.engine.status().peers.len() == 1
    })
    .await;

    // Establish the session while the policy is open.
    let warm = build_udp(v4(&ia), 1, v4(&ib), 2, b"warm");
    deliver(&os_a, &mut os_b, warm).await;

    // Lock the network down to SSH only.
    let policy = Policy {
        rules: vec!["tcp:22".parse::<Rule>().unwrap()],
    };
    assert!(matches!(
        lh.admin(AdminRequest::NetworkSetPolicy {
            network: "game".into(),
            policy: policy.clone()
        }),
        AdminResponse::Ok
    ));
    wait_for("policy pushed", || {
        a.engine.status().networks[0].info.policy == policy
            && b.engine.status().networks[0].info.policy == policy
    })
    .await;

    // Unsolicited UDP is dropped.
    os_a.to_tun
        .send(build_udp(v4(&ia), 1, v4(&ib), 2, b"blocked"))
        .await
        .unwrap();
    assert!(recv_packet(&mut os_b, Duration::from_millis(500))
        .await
        .is_none());

    // SSH SYN is allowed...
    let syn = build_tcp(v4(&ia), 40000, v4(&ib), 22, TCP_SYN);
    assert_eq!(deliver(&os_a, &mut os_b, syn.clone()).await, syn);
    // ...and so is the SYN-ACK coming back (a reply to a tracked flow).
    let synack = build_tcp(v4(&ib), 22, v4(&ia), 40000, TCP_SYN | 0x10);
    assert_eq!(deliver(&os_b, &mut os_a, synack.clone()).await, synack);

    // HTTP SYN is not.
    os_a.to_tun
        .send(build_tcp(v4(&ia), 40001, v4(&ib), 80, TCP_SYN))
        .await
        .unwrap();
    assert!(recv_packet(&mut os_b, Duration::from_millis(500))
        .await
        .is_none());

    a.engine.shutdown().await;
    b.engine.shutdown().await;
    lh.shutdown().await;
}

#[tokio::test]
async fn networks_are_isolated_and_a_node_can_be_in_several() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "dev", "10.93.0.0/24", None);
    create_network(&lh, "game", "10.94.0.0/24", None);
    let dev_inv = invite(&lh, "dev", 5);
    let game_inv = invite(&lh, "game", 5);

    let a = node("alpha", vec![], false).await; // dev + game
    let b = node("bravo", vec![], false).await; // dev only
    let c = node("charlie", vec![], false).await; // game only
    let (a_dev, mut os_a_dev) = join_with_tun(&a, &dev_inv).await;
    let (a_game, mut os_a_game) = join_with_tun(&a, &game_inv).await;
    let (b_dev, os_b) = join_with_tun(&b, &dev_inv).await;
    let (c_game, os_c) = join_with_tun(&c, &game_inv).await;

    wait_for("alpha sees two peers", || {
        a.engine.status().peers.len() == 2
    })
    .await;
    wait_for("bravo and charlie see one peer each", || {
        b.engine.status().peers.len() == 1 && c.engine.status().peers.len() == 1
    })
    .await;
    assert_eq!(a.engine.memberships().len(), 2);

    // bravo -> alpha over dev lands on alpha's dev interface.
    let p1 = build_udp(v4(&b_dev), 1, v4(&a_dev), 2, b"dev");
    assert_eq!(deliver(&os_b, &mut os_a_dev, p1.clone()).await, p1);
    // charlie -> alpha over game lands on alpha's game interface.
    let p2 = build_udp(v4(&c_game), 1, v4(&a_game), 2, b"game");
    assert_eq!(deliver(&os_c, &mut os_a_game, p2.clone()).await, p2);

    // charlie has no route to the dev network at all.
    os_c.to_tun
        .send(build_udp(v4(&c_game), 1, v4(&a_dev), 2, b"leak?"))
        .await
        .unwrap();
    assert!(recv_packet(&mut os_a_dev, Duration::from_millis(400))
        .await
        .is_none());
    // charlie cannot spoof a dev source address either: alpha only accepts
    // charlie's game address as a source.
    let spoof: IpAddr = "10.93.0.200".parse().unwrap();
    os_c.to_tun
        .send(build_udp(spoof, 1, v4(&a_game), 2, b"spoof"))
        .await
        .unwrap();
    assert!(recv_packet(&mut os_a_game, Duration::from_millis(400))
        .await
        .is_none());

    // Leaving game removes charlie from alpha's view.
    a.engine.leave(a_game.id).await.unwrap();
    wait_for("alpha down to one peer", || {
        a.engine.status().peers.len() == 1
    })
    .await;
    wait_for("charlie has no peers", || {
        c.engine.status().peers.is_empty()
    })
    .await;
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
    create_network(&lh, "dev", "10.95.0.0/24", None);
    let inv = invite(&lh, "dev", 5);
    let mut a = node("alpha", vec![], false).await;
    let b = node("bravo", vec![], false).await;
    let (ia, _os_a) = join_with_tun(&a, &inv).await;
    let (_ib, _os_b) = join_with_tun(&b, &inv).await;

    // The embedder learns about memberships through events.
    let mut saved: Vec<Membership> = Vec::new();
    while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(300), a.events.recv()).await
    {
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
    wait_for("resumed node sees bravo", || {
        a2.engine.status().peers.len() == 1
    })
    .await;
    wait_for("same address kept", || {
        a2.engine.status().networks[0].info.address == ia.address
    })
    .await;

    // Admin removes bravo; alpha loses the peer, bravo loses the network.
    let r = lh.admin(AdminRequest::NodeRemove {
        network: "dev".into(),
        node: b.engine.node_id(),
    });
    assert!(matches!(r, AdminResponse::Ok));
    wait_for("alpha has no peers", || a2.engine.status().peers.is_empty()).await;
    wait_for("bravo has no networks", || {
        b.engine.memberships().is_empty()
    })
    .await;

    match lh.admin(AdminRequest::NodeList { network: None }) {
        AdminResponse::Nodes(nodes) => {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].hostname, "alpha");
            assert_eq!(nodes[0].dns_name, "alpha");
            assert!(nodes[0].online);
        }
        other => panic!("{other:?}"),
    }
    a2.engine.shutdown().await;
    b.engine.shutdown().await;
    lh.shutdown().await;
}

#[tokio::test]
async fn gateway_translates_device_traffic_and_fails_over() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "office", "10.99.0.0/24", None);
    let inv = invite(&lh, "office", 5);

    // alpha and bravo offer to be gateways; charlie is a plain member.
    let mk = |name: &'static str, gateway: bool| async move {
        let (engine, events) = Engine::start(
            EngineConfig {
                keypair: Keypair::generate(),
                hostname: name.into(),
                os: "test".into(),
                udp_port: 0,
                memberships: vec![],
                persistent_keepalive: Some(25),
                relay_only: false,
                gateway,
            },
            Arc::new(NoProtector),
        )
        .await
        .unwrap();
        Node {
            engine,
            events,
            keypair: Keypair::generate(),
        }
    };
    let alpha = mk("alpha", true).await;
    let bravo = mk("bravo", true).await;
    let charlie = mk("charlie", false).await;
    let (ia, mut os_a) = join_with_tun(&alpha, &inv).await;
    let (ib, mut os_b) = join_with_tun(&bravo, &inv).await;
    let (ic, mut os_c) = join_with_tun(&charlie, &inv).await;
    wait_for("peers visible", || charlie.engine.status().peers.len() == 2).await;

    // Register a printer on a LAN this host is on (the test process reports its
    // real interfaces), preferring alpha then bravo explicitly.
    let target: std::net::Ipv4Addr = "192.0.2.50".parse().unwrap();
    let r = lh.admin(AdminRequest::DeviceAdd {
        network: "office".into(),
        name: "printer".into(),
        target,
        gateways: vec![alpha.engine.node_id(), bravo.engine.node_id()],
    });
    let dev_addr = match r {
        AdminResponse::Devices(list) => list[0].address,
        other => panic!("{other:?}"),
    };
    wait_for("device pushed with alpha as gateway", || {
        charlie.engine.status().networks[0]
            .info
            .devices
            .first()
            .is_some_and(|d| d.gateway == Some(alpha.engine.node_id()))
    })
    .await;

    // charlie -> printer: arrives at alpha's TUN with the physical destination.
    let q = build_udp(v4(&ic), 4000, IpAddr::V4(dev_addr), 9100, b"print this");
    let got = deliver(&os_c, &mut os_a, q).await;
    let f = ig_core::packet::parse_flow(&got).unwrap();
    assert_eq!((f.src, f.dst, f.dport), (v4(&ic), IpAddr::V4(target), 9100));
    // The printer's reply comes back from alpha's kernel with the physical
    // source; charlie sees the overlay address.
    let reply = build_udp(IpAddr::V4(target), 9100, v4(&ic), 4000, b"ok");
    let got = deliver(&os_a, &mut os_c, reply).await;
    let f = ig_core::packet::parse_flow(&got).unwrap();
    assert_eq!(
        (f.src, f.dst, f.sport),
        (IpAddr::V4(dev_addr), v4(&ic), 9100)
    );

    // bravo (also a gateway, but not active) reaches the printer through alpha.
    let q = build_udp(v4(&ib), 4001, IpAddr::V4(dev_addr), 9100, b"from bravo");
    let got = deliver(&os_b, &mut os_a, q).await;
    assert_eq!(ig_core::packet::dst(&got), Some(IpAddr::V4(target)));

    // DNS: the device has a name.
    let dns4 = IpAddr::V4(ic.dns_server_v4());
    os_c.to_tun
        .send(build_udp(
            v4(&ic),
            5300,
            dns4,
            53,
            &dns_query("printer.office.ig.test", 1),
        ))
        .await
        .unwrap();
    let ans = recv_packet(&mut os_c, Duration::from_secs(2))
        .await
        .expect("dns reply");
    assert_eq!(&ans[ans.len() - 4..], &dev_addr.octets());

    // alpha goes away: bravo takes over.
    alpha.engine.shutdown().await;
    wait_for("failover to bravo", || {
        charlie.engine.status().networks[0]
            .info
            .devices
            .first()
            .is_some_and(|d| d.gateway == Some(bravo.engine.node_id()))
    })
    .await;
    let q = build_udp(v4(&ic), 4002, IpAddr::V4(dev_addr), 9100, b"after failover");
    let got = deliver(&os_c, &mut os_b, q).await;
    assert_eq!(ig_core::packet::dst(&got), Some(IpAddr::V4(target)));
    // bravo talks to its own device: hairpin through its TUN with the physical address.
    os_b.to_tun
        .send(build_udp(
            v4(&ib),
            4003,
            IpAddr::V4(dev_addr),
            9100,
            b"local",
        ))
        .await
        .unwrap();
    let hp = recv_packet(&mut os_b, Duration::from_secs(2))
        .await
        .expect("hairpin");
    assert_eq!(ig_core::packet::dst(&hp), Some(IpAddr::V4(target)));

    let _ = ia;
    bravo.engine.shutdown().await;
    charlie.engine.shutdown().await;
    lh.shutdown().await;
}
