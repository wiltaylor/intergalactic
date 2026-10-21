//! End-to-end: a lighthouse and several engines on loopback, with in-memory
//! TUN devices standing in for the operating system.

use ig_core::packet::{build_tcp, build_udp, TCP_SYN};
use ig_core::tun::channel::{ChannelTun, OsSide};
use ig_core::{Engine, EngineConfig, EngineEvent, Membership, NoProtector, TunScope};
use ig_lighthouse::server::Overlay;
use ig_lighthouse::{Lighthouse, LighthouseConfig};
use ig_proto::admin::{AdminRequest, AdminResponse};
use ig_proto::control::NetworkInfo;
use ig_proto::ipc::PeerPath;
use ig_proto::{Invite, Keypair, Policy, RelayLimit, Rule};
use parking_lot::Mutex as PlMutex;
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

/// OS sides of the TUNs the lighthouse's embedded engine attached, by network name.
type LhTuns = Arc<PlMutex<std::collections::HashMap<String, OsSide>>>;

fn lighthouse_config(name: &str) -> (LighthouseConfig, LhTuns) {
    let tuns: LhTuns = Arc::new(PlMutex::new(std::collections::HashMap::new()));
    let sink = tuns.clone();
    let factory: ig_lighthouse::server::TunFactory = Arc::new(move |info: &NetworkInfo| {
        let (tun, os) = ChannelTun::new(&format!("lh-{}", info.name));
        sink.lock().insert(info.name.clone(), os);
        Ok(Arc::new(tun) as Arc<dyn ig_core::TunDevice>)
    });
    let cfg = LighthouseConfig {
        keypair: Keypair::generate(),
        listen: "127.0.0.1:0".parse().unwrap(),
        public_host: "127.0.0.1".into(),
        public_port: 0,
        state_path: None,
        dns_domain: "ig.test".into(),
        default_relay_limit: RelayLimit::unlimited(),
        forward_range: (30000, 30099),
        name: name.into(),
        overlay: Overlay::Custom(factory),
    };
    (cfg, tuns)
}

async fn lighthouse() -> Lighthouse {
    let (cfg, _) = lighthouse_config("lh");
    Lighthouse::start(cfg).await.unwrap()
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
            upstream_dns: Vec::new(),
            start_paused: false,
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

fn first_member(engine: &Engine) -> ig_proto::ipc::PeerStatus {
    engine
        .status()
        .peers
        .into_iter()
        .find(|p| p.hostname != "lh" && p.hostname != "beacon" && !p.hostname.starts_with("lh-"))
        .expect("a member peer")
}

/// Peers that are nodes, not lighthouses (which are members too).
fn member_peers(engine: &Engine) -> usize {
    engine
        .status()
        .peers
        .iter()
        .filter(|p| p.hostname != "lh" && p.hostname != "beacon" && !p.hostname.starts_with("lh-"))
        .count()
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
        member_peers(&a.engine) == 1 && member_peers(&b.engine) == 1
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
        first_member(&a.engine).path == PeerPath::Direct
            && first_member(&b.engine).path == PeerPath::Direct
    })
    .await;
    let st = a.engine.status();
    let bravo_peer = first_member(&a.engine);
    assert!(bravo_peer.tx_bytes > 0 && bravo_peer.rx_bytes > 0);
    assert_eq!(bravo_peer.hostname, "bravo");
    assert_eq!(
        bravo_peer.names,
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
        member_peers(&a.engine) == 1 && member_peers(&b.engine) == 1
    })
    .await;
    let pkt = build_udp(v6(&ia), 7000, v6(&ib), 7001, b"over six");
    assert_eq!(deliver(&os_a, &mut os_b, pkt.clone()).await, pkt);
    // v4 still works in the same session.
    let pkt4 = build_udp(v4(&ia), 7000, v4(&ib), 7001, b"over four");
    assert_eq!(deliver(&os_a, &mut os_b, pkt4.clone()).await, pkt4);
    // Peer status lists both families.
    assert_eq!(first_member(&a.engine).addresses.len(), 2);
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
    wait_for("peers visible", || member_peers(&a.engine) == 1).await;

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
        member_peers(&a.engine) == 1 && member_peers(&b.engine) == 1
    })
    .await;
    let pkt = build_udp(v4(&ia), 1, v4(&ib), 2, b"via relay");
    let got = deliver(&os_a, &mut os_b, pkt.clone()).await;
    assert_eq!(got, pkt);
    wait_for("relay path reported", || {
        first_member(&a.engine).path == PeerPath::Relay
    })
    .await;
    assert_eq!(first_member(&a.engine).endpoint, None);
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
        member_peers(&a.engine) == 1 && member_peers(&b.engine) == 1
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
        member_peers(&a.engine) == 1 && member_peers(&b.engine) == 1
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

    wait_for("alpha sees two peers", || member_peers(&a.engine) == 2).await;
    wait_for("bravo and charlie see one peer each", || {
        member_peers(&b.engine) == 1 && member_peers(&c.engine) == 1
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
    wait_for("alpha down to one peer", || member_peers(&a.engine) == 1).await;
    wait_for("charlie has no peers", || member_peers(&c.engine) == 0).await;
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
    wait_for("resumed node sees bravo", || member_peers(&a2.engine) == 1).await;
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
    wait_for("alpha has no peers", || member_peers(&a2.engine) == 0).await;
    wait_for("bravo has no networks", || {
        b.engine.memberships().is_empty()
    })
    .await;

    match lh.admin(AdminRequest::NodeList { network: None }) {
        AdminResponse::Nodes(nodes) => {
            let members: Vec<_> = nodes.iter().filter(|n| n.os != "lighthouse").collect();
            assert_eq!(members.len(), 1);
            assert_eq!(members[0].hostname, "alpha");
            assert_eq!(members[0].dns_name, "alpha");
            assert!(members[0].online);
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
                upstream_dns: Vec::new(),
                start_paused: false,
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
    wait_for("peers visible", || member_peers(&charlie.engine) == 2).await;

    // Register a printer on a LAN this host is on (the test process reports its
    // real interfaces), preferring alpha then bravo explicitly.
    let target: std::net::Ipv4Addr = "192.0.2.50".parse().unwrap();
    let r = lh.admin(AdminRequest::DeviceAdd {
        network: "office".into(),
        name: "printer".into(),
        target,
        target6: None,
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

#[tokio::test]
async fn ipv6_devices_are_translated_too() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "lab", "10.98.0.0/24", Some("fd98::/64"));
    let inv = invite(&lh, "lab", 5);
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
                upstream_dns: Vec::new(),
                start_paused: false,
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
    let gw = mk("gw", true).await;
    let client = mk("client", false).await;
    let (_ig, mut os_gw) = join_with_tun(&gw, &inv).await;
    let (ic, mut os_c) = join_with_tun(&client, &inv).await;
    wait_for("peer visible", || member_peers(&client.engine) == 1).await;

    // IPv6 devices need the network's IPv6 prefix; the overlay v6 address gets
    // the same host number as the v4 one.
    let target6: std::net::Ipv6Addr = "fd70::60".parse().unwrap();
    let r = lh.admin(AdminRequest::DeviceAdd {
        network: "lab".into(),
        name: "nas".into(),
        target: "192.0.2.60".parse().unwrap(),
        target6: Some(target6),
        gateways: vec![gw.engine.node_id()],
    });
    let (addr4, addr6) = match r {
        AdminResponse::Devices(list) => (
            list[0].address,
            list[0].address6.expect("v6 overlay address"),
        ),
        other => panic!("{other:?}"),
    };
    let host = u32::from(addr4) - u32::from("10.98.0.0".parse::<std::net::Ipv4Addr>().unwrap());
    assert_eq!(u128::from(addr6) & 0xffff_ffff, host as u128);
    wait_for("device pushed", || {
        client.engine.status().networks[0]
            .info
            .devices
            .first()
            .is_some_and(|d| d.gateway.is_some())
    })
    .await;

    // client -> nas over IPv6 arrives at the gateway with the physical v6 destination.
    let q = build_udp(v6(&ic), 4000, IpAddr::V6(addr6), 445, b"smb");
    let got = deliver(&os_c, &mut os_gw, q).await;
    let f = ig_core::packet::parse_flow(&got).unwrap();
    assert_eq!((f.src, f.dst, f.dport), (v6(&ic), IpAddr::V6(target6), 445));
    // Reply from the physical address comes back with the overlay v6 source.
    let reply = build_udp(IpAddr::V6(target6), 445, v6(&ic), 4000, b"ok");
    let got = deliver(&os_gw, &mut os_c, reply).await;
    let f = ig_core::packet::parse_flow(&got).unwrap();
    assert_eq!((f.src, f.dst), (IpAddr::V6(addr6), v6(&ic)));
    // AAAA for the device name.
    let dns6 = IpAddr::V6(ic.dns_server_v6().unwrap());
    os_c.to_tun
        .send(build_udp(
            v6(&ic),
            5300,
            dns6,
            53,
            &dns_query("nas.lab.ig.test", 28),
        ))
        .await
        .unwrap();
    let ans = recv_packet(&mut os_c, Duration::from_secs(2))
        .await
        .expect("dns reply");
    assert_eq!(&ans[ans.len() - 16..], &addr6.octets());
    // A network without an IPv6 prefix refuses IPv6 devices.
    create_network(&lh, "v4only", "10.97.0.0/24", None);
    let r = lh.admin(AdminRequest::DeviceAdd {
        network: "v4only".into(),
        name: "x".into(),
        target: "192.0.2.1".parse().unwrap(),
        target6: Some(target6),
        gateways: vec![],
    });
    assert!(matches!(r, AdminResponse::Error { .. }));
    gw.engine.shutdown().await;
    client.engine.shutdown().await;
    lh.shutdown().await;
}

#[tokio::test]
async fn public_port_forwards_become_overlay_nat_rules() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "dev", "10.96.0.0/24", None);
    let inv = invite(&lh, "dev", 5);
    let a = node("alpha", vec![], false).await;
    let (ia, _os_a) = join_with_tun(&a, &inv).await;

    // Ephemeral TCP forward to the node's own overlay address.
    let f = a
        .engine
        .expose(
            ia.id,
            ig_proto::tunnel::ForwardProto::Tcp,
            None,
            "self:8080".into(),
            "web".into(),
            None,
        )
        .await
        .expect("expose");
    assert!((30000..=30099).contains(&f.public_port));
    assert_eq!(f.kind, ig_proto::tunnel::ForwardKind::Ephemeral);
    assert_eq!(f.lighthouse, lh.public_key());
    let rules = lh.forward_rules();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].dst, std::net::SocketAddr::new(v4(&ia), 8080));
    assert_eq!(rules[0].public_port, f.public_port);
    wait_for("forward in status", || {
        a.engine.status().networks[0].info.forwards.len() == 1
    })
    .await;

    // A device target resolves to the device's overlay address.
    lh.admin(AdminRequest::DeviceAdd {
        network: "dev".into(),
        name: "nas".into(),
        target: "192.0.2.9".parse().unwrap(),
        target6: None,
        gateways: vec![a.engine.node_id()],
    });
    let fu = a
        .engine
        .expose(
            ia.id,
            ig_proto::tunnel::ForwardProto::Udp,
            Some(30050),
            "nas:445".into(),
            String::new(),
            None,
        )
        .await
        .expect("expose device");
    let nas_addr = match lh.admin(AdminRequest::DeviceList {
        network: "dev".into(),
    }) {
        AdminResponse::Devices(d) => d[0].address,
        other => panic!("{other:?}"),
    };
    assert!(lh
        .forward_rules()
        .iter()
        .any(|r| r.public_port == 30050
            && r.dst == std::net::SocketAddr::new(IpAddr::V4(nas_addr), 445)));

    // Refusals: localhost targets, taken and out-of-range ports, denied network.
    assert!(a
        .engine
        .expose(
            ia.id,
            ig_proto::tunnel::ForwardProto::Tcp,
            None,
            "127.0.0.1:80".into(),
            String::new(),
            None
        )
        .await
        .is_err());
    assert!(a
        .engine
        .expose(
            ia.id,
            ig_proto::tunnel::ForwardProto::Udp,
            Some(30050),
            "self:1".into(),
            String::new(),
            None
        )
        .await
        .is_err());
    assert!(a
        .engine
        .expose(
            ia.id,
            ig_proto::tunnel::ForwardProto::Tcp,
            Some(40000),
            "self:1".into(),
            String::new(),
            None
        )
        .await
        .is_err());
    assert!(matches!(
        lh.admin(AdminRequest::NetworkSetExposes {
            network: "dev".into(),
            allowed: false
        }),
        AdminResponse::Ok
    ));
    wait_for("deny pushed", || {
        !a.engine.status().networks[0].info.exposes_allowed
    })
    .await;
    assert!(a
        .engine
        .expose(
            ia.id,
            ig_proto::tunnel::ForwardProto::Tcp,
            None,
            "self:1".into(),
            String::new(),
            None
        )
        .await
        .is_err());

    // Permanent forward survives the node going away; ephemeral ones vanish.
    let r = lh.admin(AdminRequest::ForwardAdd {
        network: "dev".into(),
        node: a.engine.node_id(),
        proto: ig_proto::tunnel::ForwardProto::Tcp,
        public_port: 30080,
        target: "self:22".into(),
        label: "ssh".into(),
        lighthouse: None,
    });
    assert!(matches!(r, AdminResponse::Forwards(_)), "{r:?}");
    assert_eq!(lh.forward_rules().len(), 3);
    a.engine.unexpose(&f.id).await.unwrap();
    wait_for("ephemeral tcp removed", || {
        lh.forward_rules()
            .iter()
            .all(|r| r.public_port != f.public_port)
    })
    .await;
    let _ = fu;
    a.engine.shutdown().await;
    wait_for("only the permanent rule stays", || {
        let r = lh.forward_rules();
        r.len() == 1 && r[0].public_port == 30080
    })
    .await;
    lh.shutdown().await;
}

#[tokio::test]
async fn lighthouse_is_a_member_of_its_networks() {
    init_tracing();
    let (cfg, lh_tuns) = lighthouse_config("beacon");
    let lh = Lighthouse::start(cfg).await.unwrap();
    create_network(&lh, "dev", "10.99.1.0/24", None);
    let inv = invite(&lh, "dev", 5);
    let a = node("alpha", vec![], false).await;
    let (ia, os_a) = join_with_tun(&a, &inv).await;

    // The lighthouse shows up as a peer with its own overlay address and name.
    wait_for("lighthouse peer visible", || {
        a.engine
            .status()
            .peers
            .iter()
            .any(|p| p.hostname == "beacon")
    })
    .await;
    let st = a.engine.status();
    let lh_peer = st.peers.iter().find(|p| p.hostname == "beacon").unwrap();
    assert_eq!(lh_peer.node, lh.public_key());
    let lh_addr = lh_peer.addresses[0].1;
    assert!(ia.cidr.contains(&match lh_addr {
        IpAddr::V4(a) => a,
        _ => panic!(),
    }));
    assert_eq!(lh_peer.names[0].1, "beacon.dev.ig.test");
    // Its own engine agrees, and has a TUN for the network.
    wait_for("lighthouse tun", || lh_tuns.lock().contains_key("dev")).await;
    let lh_status = lh.engine_status().unwrap();
    assert_eq!(
        lh_status.networks[0].info.address.to_string(),
        lh_addr.to_string()
    );

    // Traffic from a member reaches the lighthouse's TUN over WireGuard.
    let pkt = build_udp(v4(&ia), 5000, lh_addr, 53, b"hello beacon");
    let mut os_lh = lh_tuns.lock().remove("dev").unwrap();
    let got = deliver(&os_a, &mut os_lh, pkt.clone()).await;
    assert_eq!(got, pkt);
    // And back.
    let reply = build_udp(lh_addr, 53, v4(&ia), 5000, b"hello alpha");
    let mut os_a = os_a;
    let got = deliver(&os_lh, &mut os_a, reply.clone()).await;
    assert_eq!(got, reply);
    // Invites carry the lighthouse list; the network info does too.
    assert_eq!(a.engine.status().networks[0].info.lighthouses.len(), 1);
    a.engine.shutdown().await;
    lh.shutdown().await;
}

#[tokio::test]
async fn two_lighthouses_merge_state_and_each_serves_alone() {
    init_tracing();
    let dir = std::env::temp_dir().join(format!("ig-peer-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (mut acfg, _) = lighthouse_config("lh-a");
    acfg.state_path = Some(dir.join("a.json"));
    let a_key = acfg.keypair.public;
    let a_keypair = acfg.keypair.clone();
    let a = Lighthouse::start(acfg.clone()).await.unwrap();
    let (mut bcfg, _) = lighthouse_config("lh-b");
    bcfg.overlay = Overlay::Off;
    let b_key = bcfg.keypair.public;
    let b = Lighthouse::start(bcfg).await.unwrap();

    // Each side registers the other; the links come up and the stores merge.
    let r = a.admin(AdminRequest::LighthouseAdd {
        name: "lh-b".into(),
        host: "127.0.0.1".into(),
        port: b.local_addr().port(),
        key: b_key,
    });
    assert!(matches!(r, AdminResponse::Lighthouses(_)), "{r:?}");
    let r = b.admin(AdminRequest::LighthouseAdd {
        name: "lh-a".into(),
        host: "127.0.0.1".into(),
        port: a.local_addr().port(),
        key: a_key,
    });
    assert!(matches!(r, AdminResponse::Lighthouses(_)), "{r:?}");
    let linked = |lh: &Lighthouse| matches!(lh.admin(AdminRequest::LighthouseList), AdminResponse::Lighthouses(l) if l.len() == 2 && l.iter().all(|x| x.connected));
    wait_for("a linked to b", || linked(&a)).await;
    wait_for("b linked to a", || linked(&b)).await;

    // Writes on either side reach the other.
    create_network(&a, "dev", "10.99.2.0/24", None);
    create_network(&b, "ops", "10.99.3.0/24", None);
    let names = |lh: &Lighthouse| -> Vec<String> {
        match lh.admin(AdminRequest::NetworkList) {
            AdminResponse::Networks(n) => {
                let mut v: Vec<String> = n.into_iter().map(|x| x.name).collect();
                v.sort();
                v
            }
            _ => vec![],
        }
    };
    wait_for("b has both networks", || names(&b) == ["dev", "ops"]).await;
    wait_for("a has both networks", || names(&a) == ["dev", "ops"]).await;

    // The invite names both lighthouses.
    let inv = invite(&a, "dev", 5);
    assert_eq!(inv.extra_lighthouses.len(), 1);
    assert_eq!(inv.extra_lighthouses[0].key, b_key);

    // alpha joins through a; bravo's invite is rehosted so it joins through b,
    // which accepts the join itself and shares it with a.
    let alpha = node("alpha", vec![], false).await;
    let (ia, os_a) = join_with_tun(&alpha, &inv).await;
    let mut inv_b = inv.clone();
    inv_b.host = "127.0.0.1".into();
    inv_b.port = b.local_addr().port();
    inv_b.lighthouse = b_key;
    inv_b.extra_lighthouses = vec![ig_proto::control::LighthouseRef {
        host: "127.0.0.1".into(),
        port: a.local_addr().port(),
        key: a_key,
        name: "lh-a".into(),
    }];
    let bravo = node("bravo", vec![], false).await;
    let (ib, mut os_b) = join_with_tun(&bravo, &inv_b).await;
    assert_ne!(ia.address, ib.address);
    let members_of = |lh: &Lighthouse, net: &str| -> Vec<String> {
        match lh.admin(AdminRequest::NodeList {
            network: Some(net.into()),
        }) {
            AdminResponse::Nodes(n) => {
                let mut v: Vec<String> = n.into_iter().map(|x| x.hostname).collect();
                v.sort();
                v
            }
            _ => vec![],
        }
    };
    wait_for("a knows bravo", || {
        members_of(&a, "dev") == ["alpha", "bravo", "lh-a", "lh-b"]
    })
    .await;
    wait_for("alpha sees both lighthouses up", || {
        alpha.engine.status().networks[0]
            .lighthouses
            .iter()
            .filter(|(_, up)| *up)
            .count()
            == 2
    })
    .await;
    wait_for("peers", || {
        alpha
            .engine
            .status()
            .peers
            .iter()
            .any(|p| p.hostname == "bravo")
            && bravo
                .engine
                .status()
                .peers
                .iter()
                .any(|p| p.hostname == "alpha")
    })
    .await;
    let pkt = build_udp(v4(&ia), 1, v4(&ib), 2, b"via either");
    assert_eq!(deliver(&os_a, &mut os_b, pkt.clone()).await, pkt);

    // a goes down. Members keep talking, b keeps serving, and b accepts a new
    // join and an admin change on its own.
    a.shutdown().await;
    wait_for("a reported down", || {
        alpha.engine.status().networks[0]
            .lighthouses
            .iter()
            .any(|(_, up)| !*up)
    })
    .await;
    let pkt = build_udp(v4(&ia), 3, v4(&ib), 4, b"still works");
    assert_eq!(deliver(&os_a, &mut os_b, pkt.clone()).await, pkt);
    wait_for("b noticed a is gone", || {
        matches!(b.admin(AdminRequest::LighthouseList), AdminResponse::Lighthouses(l) if l.iter().any(|x| x.key == a_key && !x.connected))
    })
    .await;
    let charlie = node("charlie", vec![], false).await;
    let ic = charlie
        .engine
        .join(&inv_b)
        .await
        .expect("join through b alone");
    assert_ne!(ic.address, ia.address);
    assert_ne!(ic.address, ib.address);
    let r = b.admin(AdminRequest::DeviceAdd {
        network: "dev".into(),
        name: "nas".into(),
        target: "192.168.77.5".parse().unwrap(),
        target6: None,
        gateways: vec![],
    });
    assert!(matches!(r, AdminResponse::Devices(_)), "{r:?}");
    wait_for("bravo sees charlie through b", || {
        bravo
            .engine
            .status()
            .peers
            .iter()
            .any(|p| p.hostname == "charlie")
    })
    .await;

    // a comes back with its old key and state (on a new port) and learns what
    // happened while it was away.
    let (mut acfg2, _) = lighthouse_config("lh-a");
    acfg2.keypair = a_keypair;
    acfg2.state_path = acfg.state_path.clone();
    let a2 = Lighthouse::start(acfg2).await.unwrap();
    wait_for("a2 linked to b", || linked(&a2)).await;
    wait_for("a2 learned charlie and the device", || {
        members_of(&a2, "dev") == ["alpha", "bravo", "charlie", "lh-a", "lh-b"]
            && matches!(a2.admin(AdminRequest::DeviceList { network: "dev".into() }), AdminResponse::Devices(d) if d.len() == 1)
    })
    .await;
    wait_for("b learned a2's new port", || {
        matches!(b.admin(AdminRequest::LighthouseList), AdminResponse::Lighthouses(l) if l.iter().any(|x| x.key == a_key && x.port == a2.local_addr().port() && x.connected))
    })
    .await;

    alpha.engine.shutdown().await;
    bravo.engine.shutdown().await;
    charlie.engine.shutdown().await;
    a2.shutdown().await;
    b.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn forward_targets_stay_inside_the_callers_network() {
    init_tracing();
    let lh = lighthouse().await;
    create_network(&lh, "dev", "10.95.0.0/24", Some("fd95::/64"));
    create_network(&lh, "game", "10.94.0.0/24", Some("fd94::/64"));
    let inv_dev = invite(&lh, "dev", 5);
    let inv_game = invite(&lh, "game", 5);

    // alpha is in both networks; bravo only in `game`.
    let a = node("alpha", vec![], false).await;
    let (ia_dev, _os_a_dev) = join_with_tun(&a, &inv_dev).await;
    let (ia_game, _os_a_game) = join_with_tun(&a, &inv_game).await;
    let b = node("bravo", vec![], false).await;
    let (ib, _os_b) = join_with_tun(&b, &inv_game).await;
    let tcp = ig_proto::tunnel::ForwardProto::Tcp;

    // bravo cannot publish alpha's `dev` endpoint, over IPv4 or IPv6.
    for target in [
        format!("{}:22", v4(&ia_dev)),
        format!("[{}]:22", v6(&ia_dev)),
    ] {
        let err = b
            .engine
            .expose(ib.id, tcp, None, target.clone(), String::new(), None)
            .await
            .expect_err("cross-network target must be refused");
        assert!(
            err.to_string().contains("own overlay address"),
            "unexpected error for {target}: {err}"
        );
        assert!(lh.forward_rules().is_empty(), "no rule for {target}");
    }
    // Nor another member of its own network.
    assert!(b
        .engine
        .expose(
            ib.id,
            tcp,
            None,
            format!("{}:22", v4(&ia_game)),
            String::new(),
            None,
        )
        .await
        .is_err());
    assert!(lh.forward_rules().is_empty());
    assert!(b.engine.status().networks[0].info.forwards.is_empty());

    // Its own literal addresses, `self` and a device of the network still work.
    let f4 = b
        .engine
        .expose(
            ib.id,
            tcp,
            None,
            format!("{}:22", v4(&ib)),
            String::new(),
            None,
        )
        .await
        .expect("own v4 address");
    let f6 = b
        .engine
        .expose(
            ib.id,
            tcp,
            None,
            format!("[{}]:22", v6(&ib)),
            String::new(),
            None,
        )
        .await
        .expect("own v6 address");
    let fs = b
        .engine
        .expose(ib.id, tcp, None, "self:80".into(), String::new(), None)
        .await
        .expect("self");
    let rules = lh.forward_rules();
    assert_eq!(rules.len(), 3);
    assert!(rules.iter().any(
        |r| r.public_port == f4.public_port && r.dst == std::net::SocketAddr::new(v4(&ib), 22)
    ));
    assert!(rules.iter().any(
        |r| r.public_port == f6.public_port && r.dst == std::net::SocketAddr::new(v6(&ib), 22)
    ));
    assert!(rules.iter().any(
        |r| r.public_port == fs.public_port && r.dst == std::net::SocketAddr::new(v4(&ib), 80)
    ));
    assert!(matches!(
        lh.admin(AdminRequest::DeviceAdd {
            network: "game".into(),
            name: "console".into(),
            target: "192.0.2.7".parse().unwrap(),
            target6: None,
            gateways: vec![a.engine.node_id()],
        }),
        AdminResponse::Devices(_)
    ));
    let console = match lh.admin(AdminRequest::DeviceList {
        network: "game".into(),
    }) {
        AdminResponse::Devices(d) => d[0].address,
        other => panic!("{other:?}"),
    };
    b.engine
        .expose(
            ib.id,
            tcp,
            None,
            format!("{console}:3074"),
            String::new(),
            None,
        )
        .await
        .expect("device literal address");
    assert_eq!(lh.forward_rules().len(), 4);

    // The admin path applies the same check to permanent forwards.
    let r = lh.admin(AdminRequest::ForwardAdd {
        network: "game".into(),
        node: b.engine.node_id(),
        proto: tcp,
        public_port: 30090,
        target: format!("{}:22", v4(&ia_dev)),
        label: "leak".into(),
        lighthouse: None,
    });
    assert!(matches!(r, AdminResponse::Error { .. }), "{r:?}");
    let r = lh.admin(AdminRequest::ForwardAdd {
        network: "game".into(),
        node: b.engine.node_id(),
        proto: tcp,
        public_port: 30090,
        target: format!("[{}]:22", v6(&ia_dev)),
        label: "leak6".into(),
        lighthouse: None,
    });
    assert!(matches!(r, AdminResponse::Error { .. }), "{r:?}");
    assert_eq!(lh.forward_rules().len(), 4);
    assert!(matches!(
        lh.admin(AdminRequest::ForwardList),
        AdminResponse::Forwards(list) if list.iter().all(|f| f.info.label != "leak" && f.info.label != "leak6")
    ));
    let r = lh.admin(AdminRequest::ForwardAdd {
        network: "game".into(),
        node: b.engine.node_id(),
        proto: tcp,
        public_port: 30090,
        target: format!("{}:22", v4(&ib)),
        label: "ok".into(),
        lighthouse: None,
    });
    assert!(matches!(r, AdminResponse::Forwards(_)), "{r:?}");
    assert_eq!(lh.forward_rules().len(), 5);

    a.engine.shutdown().await;
    b.engine.shutdown().await;
    lh.shutdown().await;
}

/// Relay-only members keep talking when the lighthouse that relays for them
/// goes away, and again when it returns and the other one goes away. Nothing
/// is restarted on the node side.
#[tokio::test]
async fn relay_only_members_fail_over_between_lighthouses() {
    init_tracing();
    let dir = std::env::temp_dir().join(format!("ig-relay-failover-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (mut acfg, _) = lighthouse_config("lh-a");
    acfg.state_path = Some(dir.join("a.json"));
    let a_key = acfg.keypair.public;
    let a = Lighthouse::start(acfg.clone()).await.unwrap();
    let a_addr = a.local_addr();
    let (mut bcfg, _) = lighthouse_config("lh-b");
    bcfg.overlay = Overlay::Off;
    let b_key = bcfg.keypair.public;
    let b = Lighthouse::start(bcfg).await.unwrap();

    let r = a.admin(AdminRequest::LighthouseAdd {
        name: "lh-b".into(),
        host: "127.0.0.1".into(),
        port: b.local_addr().port(),
        key: b_key,
    });
    assert!(matches!(r, AdminResponse::Lighthouses(_)), "{r:?}");
    let r = b.admin(AdminRequest::LighthouseAdd {
        name: "lh-a".into(),
        host: "127.0.0.1".into(),
        port: a_addr.port(),
        key: a_key,
    });
    assert!(matches!(r, AdminResponse::Lighthouses(_)), "{r:?}");
    let linked = |lh: &Lighthouse| matches!(lh.admin(AdminRequest::LighthouseList), AdminResponse::Lighthouses(l) if l.len() == 2 && l.iter().all(|x| x.connected));
    wait_for("a linked to b", || linked(&a)).await;
    wait_for("b linked to a", || linked(&b)).await;
    create_network(&a, "dev", "10.99.4.0/24", None);
    wait_for(
        "b has the network",
        || matches!(b.admin(AdminRequest::NetworkList), AdminResponse::Networks(n) if n.len() == 1),
    )
    .await;

    // alpha joins through a, bravo through b; both can only be relayed.
    let inv = invite(&a, "dev", 5);
    assert_eq!(inv.extra_lighthouses.len(), 1);
    let alpha = node("alpha", vec![], true).await;
    let (ia, mut os_a) = join_with_tun(&alpha, &inv).await;
    let mut inv_b = inv.clone();
    inv_b.host = "127.0.0.1".into();
    inv_b.port = b.local_addr().port();
    inv_b.lighthouse = b_key;
    inv_b.extra_lighthouses = vec![ig_proto::control::LighthouseRef {
        host: "127.0.0.1".into(),
        port: a_addr.port(),
        key: a_key,
        name: "lh-a".into(),
    }];
    let bravo = node("bravo", vec![], true).await;
    let (ib, mut os_b) = join_with_tun(&bravo, &inv_b).await;
    assert_ne!(ia.address, ib.address);
    let lighthouses_up = |n: &Node| -> usize {
        n.engine.status().networks[0]
            .lighthouses
            .iter()
            .filter(|(_, up)| *up)
            .count()
    };
    wait_for("both nodes see both lighthouses up", || {
        lighthouses_up(&alpha) == 2 && lighthouses_up(&bravo) == 2
    })
    .await;
    wait_for("peers", || {
        alpha
            .engine
            .status()
            .peers
            .iter()
            .any(|p| p.hostname == "bravo")
            && bravo
                .engine
                .status()
                .peers
                .iter()
                .any(|p| p.hostname == "alpha")
    })
    .await;
    let pkt = build_udp(v4(&ia), 1, v4(&ib), 2, b"relayed");
    assert_eq!(deliver(&os_a, &mut os_b, pkt.clone()).await, pkt);
    wait_for("relay path reported", || {
        first_member(&alpha.engine).path == PeerPath::Relay
    })
    .await;

    // a goes down: the nodes keep their sessions and relay through b.
    a.shutdown().await;
    drop(a);
    wait_for("both nodes see a down", || {
        lighthouses_up(&alpha) == 1 && lighthouses_up(&bravo) == 1
    })
    .await;
    let pkt = build_udp(v4(&ia), 3, v4(&ib), 4, b"via b");
    assert_eq!(deliver(&os_a, &mut os_b, pkt.clone()).await, pkt);
    let pkt = build_udp(v4(&ib), 5, v4(&ia), 6, b"via b, back");
    assert_eq!(deliver(&os_b, &mut os_a, pkt.clone()).await, pkt);

    // a returns with its old key and state. (It gets a new port: the old
    // lighthouse's replication tasks keep its sockets open after shutdown.)
    // The nodes learn the new address from b and traffic still flows.
    let (mut acfg2, _) = lighthouse_config("lh-a");
    acfg2.keypair = acfg.keypair.clone();
    acfg2.state_path = acfg.state_path.clone();
    let a2 = Lighthouse::start(acfg2).await.unwrap();
    wait_for("a2 linked to b", || linked(&a2)).await;
    let a2_port = a2.local_addr().port().to_string();
    wait_for("nodes learned a2's address", || {
        [&alpha, &bravo].iter().all(|n| {
            n.engine.status().networks[0]
                .lighthouses
                .iter()
                .any(|(hp, _)| hp.ends_with(&a2_port))
        })
    })
    .await;
    let pkt = build_udp(v4(&ia), 7, v4(&ib), 8, b"a is back");
    assert_eq!(deliver(&os_a, &mut os_b, pkt.clone()).await, pkt);
    let pkt = build_udp(v4(&ib), 9, v4(&ia), 10, b"a is back, reverse");
    assert_eq!(deliver(&os_b, &mut os_a, pkt.clone()).await, pkt);

    alpha.engine.shutdown().await;
    bravo.engine.shutdown().await;
    a2.shutdown().await;
    b.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
