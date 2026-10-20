use anyhow::Context;
use clap::{Parser, Subcommand};
use ig_lighthouse::admin_socket;
use ig_lighthouse::server::{Overlay, Role};
use ig_lighthouse::{Lighthouse, LighthouseConfig};
use ig_proto::admin::{AdminRequest, AdminResponse};
use ig_proto::{
    Keypair, NodeId, Policy, PrivateKey, RelayLimit, Rule, DEFAULT_DNS_DOMAIN,
    DEFAULT_LIGHTHOUSE_PORT,
};
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ig-lighthouse",
    version,
    about = "Intergalactic lighthouse: coordination, NAT traversal and relay"
)]
struct Cli {
    /// Directory holding the key, state and admin socket.
    #[arg(long, env = "IG_LIGHTHOUSE_STATE", default_value = default_state_dir())]
    state_dir: PathBuf,
    /// Admin socket path (defaults to `<state-dir>/admin.sock`).
    #[arg(long, env = "IG_LIGHTHOUSE_ADMIN_SOCKET")]
    admin_socket: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

fn default_state_dir() -> &'static str {
    if cfg!(windows) {
        r"C:\ProgramData\Intergalactic\lighthouse"
    } else {
        "/var/lib/intergalactic/lighthouse"
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the lighthouse daemon.
    Serve {
        /// TCP and UDP listen address.
        #[arg(long, default_value_t = SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, DEFAULT_LIGHTHOUSE_PORT)))]
        listen: SocketAddr,
        /// Public host name or IP written into invites.
        #[arg(long)]
        public_host: String,
        /// Public port written into invites (defaults to the listen port).
        #[arg(long)]
        public_port: Option<u16>,
        /// DNS suffix for peer names. Pick something that is not a real internet domain.
        #[arg(long, default_value = DEFAULT_DNS_DOMAIN)]
        dns_domain: String,
        /// Default relay cap per member in kbit/s for networks without their own limit (0 = unlimited).
        #[arg(long, default_value_t = 0)]
        relay_limit_per_node_kbps: u32,
        /// Default relay cap per network in kbit/s for networks without their own limit (0 = unlimited).
        #[arg(long, default_value_t = 0)]
        relay_limit_total_kbps: u32,
        /// Public ports handed out for ephemeral forwards (`ig expose`), e.g. `20000-20999`.
        /// Open this range in the firewall. `none` disables ephemeral forwards.
        #[arg(long, default_value = "20000-20999")]
        forward_range: String,
        /// This lighthouse's name (its hostname and DNS label in every network).
        #[arg(long, default_value = "lighthouse")]
        name: String,
        /// Run as a replica of the primary at HOST:PORT. Requires --primary-key.
        #[arg(long)]
        replica_of: Option<String>,
        /// The primary's public key (printed by `ig-lighthouse info` there).
        #[arg(long)]
        primary_key: Option<NodeId>,
        /// Do not join the overlay (no TUN device). Public forwards are then unavailable.
        #[arg(long)]
        no_overlay: bool,
    },
    /// Show lighthouse identity and counters.
    Info,
    /// Manage overlay networks.
    Network {
        #[command(subcommand)]
        cmd: NetworkCmd,
    },
    /// Manage invites.
    Invite {
        #[command(subcommand)]
        cmd: InviteCmd,
    },
    /// Manage member nodes.
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
    /// Manage devices reached through gateway nodes.
    Device {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },
    /// Manage permanent public port forwards.
    Forward {
        #[command(subcommand)]
        cmd: ForwardCmd,
    },
    /// Manage replica lighthouses.
    Lighthouse {
        #[command(subcommand)]
        cmd: LighthouseCmd,
    },
}

#[derive(Subcommand)]
enum LighthouseCmd {
    /// Register a replica: `lighthouse add lh-eu lh-eu.example.com 7777 <its public key>`.
    /// Then start it with `serve --replica-of <this host>:7777 --primary-key <this key>`.
    Add {
        name: String,
        host: String,
        port: u16,
        key: NodeId,
    },
    List,
    Remove {
        key: NodeId,
    },
}

#[derive(Subcommand)]
enum ForwardCmd {
    /// Forward a public port to a target reached from a node:
    /// `forward add dev <node-id> 8443 127.0.0.1:443`.
    Add {
        network: String,
        node: NodeId,
        public_port: u16,
        /// Overlay target: `self:PORT` (the node's own address), `<device>:PORT` or `<overlay ip>:PORT`.
        target: String,
        #[arg(long)]
        udp: bool,
        #[arg(long, default_value = "")]
        label: String,
        /// Lighthouse that publishes the port, by name or key. Default: the primary.
        #[arg(long)]
        lighthouse: Option<String>,
    },
    /// List permanent and ephemeral forwards.
    List,
    Remove {
        id: String,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// Register a device: `device add dev printer 192.168.1.50`. Members reach it at an
    /// overlay address through a node started with `--gateway` on the same LAN.
    Add {
        network: String,
        name: String,
        target: std::net::Ipv4Addr,
        /// The device's IPv6 address on the LAN. The network needs an IPv6 prefix.
        #[arg(long = "ipv6")]
        target6: Option<std::net::Ipv6Addr>,
        /// Preferred gateway nodes in order (node ids). Default: any capable node on the LAN.
        #[arg(long = "via")]
        via: Vec<NodeId>,
    },
    List {
        network: String,
    },
    Remove {
        network: String,
        name: String,
    },
}

#[derive(Subcommand)]
enum NetworkCmd {
    /// Create a network, e.g. `network create dev 10.90.0.0/24 --ipv6 fd42:9a:1::/64`.
    Create {
        name: String,
        cidr: Ipv4Net,
        /// Optional IPv6 prefix (/120 or larger). Members get matching v4 and v6 host numbers.
        #[arg(long = "ipv6")]
        cidr6: Option<Ipv6Net>,
    },
    List,
    Delete {
        network: String,
    },
    /// Set the inbound policy. Without --allow the network allows everything.
    Policy {
        network: String,
        /// Allow rule, repeatable: `tcp:22,80`, `udp:27015-27030`, `icmp`.
        #[arg(long = "allow")]
        allow: Vec<Rule>,
    },
    /// Allow (default) or deny ephemeral forwards (`ig expose`) in a network.
    Expose {
        network: String,
        #[arg(long)]
        deny: bool,
    },
    /// Cap relayed traffic for one network. Without flags the network falls back
    /// to the lighthouse default.
    RelayLimit {
        network: String,
        /// kbit/s per member.
        #[arg(long, default_value_t = 0)]
        per_node_kbps: u32,
        /// kbit/s for the whole network.
        #[arg(long, default_value_t = 0)]
        total_kbps: u32,
    },
}

#[derive(Subcommand)]
enum InviteCmd {
    /// Create an invite for a network and print it.
    Create {
        network: String,
        /// How many nodes may use this invite.
        #[arg(long, default_value_t = 1)]
        uses: u32,
        /// Lifetime, e.g. `24h`, `7d`, `30m`.
        #[arg(long, default_value = "24h")]
        ttl: humantime::Duration,
        #[arg(long, default_value = "")]
        label: String,
    },
    List {
        network: String,
    },
    Revoke {
        network: String,
        invite_id: String,
    },
}

#[derive(Subcommand)]
enum NodeCmd {
    /// List members, optionally of one network.
    List { network: Option<String> },
    /// Remove a node from a network.
    Remove { network: String, node: NodeId },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let admin_sock = cli
        .admin_socket
        .clone()
        .unwrap_or_else(|| cli.state_dir.join("admin.sock"));

    match cli.cmd {
        Cmd::Serve {
            listen,
            public_host,
            public_port,
            dns_domain,
            relay_limit_per_node_kbps,
            relay_limit_total_kbps,
            forward_range,
            name,
            replica_of,
            primary_key,
            no_overlay,
        } => {
            std::fs::create_dir_all(&cli.state_dir)
                .with_context(|| format!("creating {}", cli.state_dir.display()))?;
            let keypair = load_or_create_key(&cli.state_dir.join("lighthouse.key"))?;
            let config = LighthouseConfig {
                keypair,
                listen,
                public_host,
                public_port: public_port.unwrap_or(listen.port()),
                state_path: Some(cli.state_dir.join("lighthouse.json")),
                dns_domain: dns_domain.trim_matches('.').to_string(),
                default_relay_limit: RelayLimit {
                    per_node_kbps: relay_limit_per_node_kbps,
                    total_kbps: relay_limit_total_kbps,
                },
                forward_range: parse_range(&forward_range)?,
                name: name.clone(),
                role: match (replica_of, primary_key) {
                    (Some(hp), Some(key)) => {
                        let (h, p) = hp
                            .rsplit_once(':')
                            .ok_or_else(|| anyhow::anyhow!("--replica-of must be HOST:PORT"))?;
                        Role::Replica(ig_proto::control::LighthouseRef {
                            host: h.to_string(),
                            port: p.parse()?,
                            key,
                            name: String::new(),
                        })
                    }
                    (None, None) => Role::Primary,
                    _ => anyhow::bail!("--replica-of and --primary-key go together"),
                },
                overlay: if no_overlay {
                    Overlay::Off
                } else {
                    Overlay::Kernel
                },
            };
            let lh = Lighthouse::start(config).await?;
            println!("lighthouse public key: {}", lh.public_key());
            let admin = tokio::spawn(admin_socket::serve(lh.clone(), admin_sock.clone()));
            tokio::signal::ctrl_c().await?;
            tracing::info!("shutting down");
            admin.abort();
            lh.shutdown().await;
            Ok(())
        }
        Cmd::Info => {
            let r = admin_socket::request(&admin_sock, &AdminRequest::Info).await?;
            if let AdminResponse::Info(i) = r {
                println!("public key   {}", i.public_key);
                println!("invite host  {}:{}", i.public_host, i.port);
                println!("role         {}", i.role);
                for (net, addr) in &i.overlay {
                    println!("overlay      {net} = {addr}");
                }
                println!("dns domain   {}", i.dns_domain);
                println!("networks     {}", i.networks);
                println!("nodes online {}", i.nodes_online);
                println!(
                    "uptime       {}",
                    humantime::format_duration(std::time::Duration::from_secs(i.uptime_secs))
                );
                Ok(())
            } else {
                fail(r)
            }
        }
        Cmd::Network { cmd } => match cmd {
            NetworkCmd::Create { name, cidr, cidr6 } => {
                let r = admin_socket::request(
                    &admin_sock,
                    &AdminRequest::NetworkCreate { name, cidr, cidr6 },
                )
                .await?;
                print_networks(r)
            }
            NetworkCmd::List => {
                let r = admin_socket::request(&admin_sock, &AdminRequest::NetworkList).await?;
                print_networks(r)
            }
            NetworkCmd::Delete { network } => expect_ok(
                admin_socket::request(&admin_sock, &AdminRequest::NetworkDelete { network })
                    .await?,
            ),
            NetworkCmd::Expose { network, deny } => expect_ok(
                admin_socket::request(
                    &admin_sock,
                    &AdminRequest::NetworkSetExposes {
                        network,
                        allowed: !deny,
                    },
                )
                .await?,
            ),
            NetworkCmd::RelayLimit {
                network,
                per_node_kbps,
                total_kbps,
            } => {
                let limit = RelayLimit {
                    per_node_kbps,
                    total_kbps,
                };
                expect_ok(
                    admin_socket::request(
                        &admin_sock,
                        &AdminRequest::NetworkSetRelayLimit { network, limit },
                    )
                    .await?,
                )
            }
            NetworkCmd::Policy { network, allow } => {
                let policy = Policy { rules: allow };
                expect_ok(
                    admin_socket::request(
                        &admin_sock,
                        &AdminRequest::NetworkSetPolicy { network, policy },
                    )
                    .await?,
                )
            }
        },
        Cmd::Invite { cmd } => match cmd {
            InviteCmd::Create {
                network,
                uses,
                ttl,
                label,
            } => {
                let r = admin_socket::request(
                    &admin_sock,
                    &AdminRequest::InviteCreate {
                        network,
                        uses,
                        ttl_secs: ttl.as_secs(),
                        label,
                    },
                )
                .await?;
                match r {
                    AdminResponse::Invite { invite, invite_id } => {
                        eprintln!("invite {invite_id} created. On the joining machine run:\n");
                        println!("ig join {invite}");
                        Ok(())
                    }
                    other => fail(other),
                }
            }
            InviteCmd::List { network } => {
                let r = admin_socket::request(&admin_sock, &AdminRequest::InviteList { network })
                    .await?;
                match r {
                    AdminResponse::Invites(list) => {
                        println!("{:<10} {:<8} {:<20} LABEL", "ID", "USES", "EXPIRES");
                        let now = ig_lighthouse::store::now_secs();
                        for i in list {
                            let left = i.expires_at.saturating_sub(now);
                            println!(
                                "{:<10} {:<8} {:<20} {}",
                                i.id,
                                i.uses_left,
                                format!(
                                    "in {}",
                                    humantime::format_duration(std::time::Duration::from_secs(
                                        left
                                    ))
                                ),
                                i.label
                            );
                        }
                        Ok(())
                    }
                    other => fail(other),
                }
            }
            InviteCmd::Revoke { network, invite_id } => expect_ok(
                admin_socket::request(
                    &admin_sock,
                    &AdminRequest::InviteRevoke { network, invite_id },
                )
                .await?,
            ),
        },
        Cmd::Forward { cmd } => match cmd {
            ForwardCmd::Add {
                network,
                node,
                public_port,
                target,
                udp,
                label,
                lighthouse,
            } => {
                let lighthouse = match lighthouse {
                    None => None,
                    Some(want) => {
                        if let Ok(k) = want.parse::<NodeId>() {
                            Some(k)
                        } else {
                            match admin_socket::request(&admin_sock, &AdminRequest::LighthouseList)
                                .await?
                            {
                                AdminResponse::Lighthouses(list) => Some(
                                    list.iter()
                                        .find(|l| l.name == want || l.host == want)
                                        .map(|l| l.key)
                                        .ok_or_else(|| {
                                            anyhow::anyhow!("no lighthouse named `{want}`")
                                        })?,
                                ),
                                other => return fail(other),
                            }
                        }
                    }
                };
                let proto = if udp {
                    ig_proto::tunnel::ForwardProto::Udp
                } else {
                    ig_proto::tunnel::ForwardProto::Tcp
                };
                let r = admin_socket::request(
                    &admin_sock,
                    &AdminRequest::ForwardAdd {
                        network,
                        node,
                        proto,
                        public_port,
                        target,
                        label,
                        lighthouse,
                    },
                )
                .await?;
                print_forwards(r)
            }
            ForwardCmd::List => print_forwards(
                admin_socket::request(&admin_sock, &AdminRequest::ForwardList).await?,
            ),
            ForwardCmd::Remove { id } => expect_ok(
                admin_socket::request(&admin_sock, &AdminRequest::ForwardRemove { id }).await?,
            ),
        },
        Cmd::Lighthouse { cmd } => match cmd {
            LighthouseCmd::Add {
                name,
                host,
                port,
                key,
            } => print_lighthouses(
                admin_socket::request(
                    &admin_sock,
                    &AdminRequest::LighthouseAdd {
                        name,
                        host,
                        port,
                        key,
                    },
                )
                .await?,
            ),
            LighthouseCmd::List => print_lighthouses(
                admin_socket::request(&admin_sock, &AdminRequest::LighthouseList).await?,
            ),
            LighthouseCmd::Remove { key } => expect_ok(
                admin_socket::request(&admin_sock, &AdminRequest::LighthouseRemove { key }).await?,
            ),
        },
        Cmd::Device { cmd } => match cmd {
            DeviceCmd::Add {
                network,
                name,
                target,
                target6,
                via,
            } => {
                let r = admin_socket::request(
                    &admin_sock,
                    &AdminRequest::DeviceAdd {
                        network,
                        name,
                        target,
                        target6,
                        gateways: via,
                    },
                )
                .await?;
                print_devices(r)
            }
            DeviceCmd::List { network } => {
                let r = admin_socket::request(&admin_sock, &AdminRequest::DeviceList { network })
                    .await?;
                print_devices(r)
            }
            DeviceCmd::Remove { network, name } => expect_ok(
                admin_socket::request(&admin_sock, &AdminRequest::DeviceRemove { network, name })
                    .await?,
            ),
        },
        Cmd::Node { cmd } => match cmd {
            NodeCmd::List { network } => {
                let r =
                    admin_socket::request(&admin_sock, &AdminRequest::NodeList { network }).await?;
                match r {
                    AdminResponse::Nodes(nodes) => {
                        println!(
                            "{:<12} {:<20} {:<9} {:<16} {:<30} {:<8} {:<8} ENDPOINTS",
                            "NODE",
                            "HOSTNAME",
                            "OS",
                            "ADDRESS",
                            "IPV6 / DNS NAME",
                            "NETWORK",
                            "STATE"
                        );
                        for n in nodes {
                            let state = if n.online {
                                "online".to_string()
                            } else {
                                match n.last_seen_secs_ago {
                                    Some(s) => format!(
                                        "{}ago",
                                        humantime::format_duration(std::time::Duration::from_secs(
                                            s.min(86400 * 365)
                                        ))
                                    ),
                                    None => "never".into(),
                                }
                            };
                            let eps: Vec<String> =
                                n.endpoints.iter().map(|e| e.to_string()).collect();
                            println!(
                                "{:<12} {:<20} {:<9} {:<16} {:<30} {:<8} {:<8} {}",
                                n.node.short(),
                                truncate(&n.hostname, 20),
                                truncate(&n.os, 9),
                                n.address.to_string(),
                                format!(
                                    "{} {}",
                                    n.address6
                                        .map(|a| a.to_string())
                                        .unwrap_or_else(|| "-".into()),
                                    n.dns_name
                                ),
                                truncate(&n.network_name, 8),
                                state,
                                eps.join(",")
                            );
                        }
                        Ok(())
                    }
                    other => fail(other),
                }
            }
            NodeCmd::Remove { network, node } => expect_ok(
                admin_socket::request(&admin_sock, &AdminRequest::NodeRemove { network, node })
                    .await?,
            ),
        },
    }
}

fn load_or_create_key(path: &std::path::Path) -> anyhow::Result<Keypair> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let key: PrivateKey =
                serde_json::from_slice(&bytes).context("parsing lighthouse.key")?;
            Ok(Keypair::from_private(key))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let kp = Keypair::generate();
            std::fs::write(path, serde_json::to_vec(&kp.private)?)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            tracing::info!(path = %path.display(), "generated new lighthouse key");
            Ok(kp)
        }
        Err(e) => Err(e.into()),
    }
}

fn print_networks(r: AdminResponse) -> anyhow::Result<()> {
    match r {
        AdminResponse::Networks(list) => {
            println!(
                "{:<16} {:<12} {:<18} {:<22} {:<7} {:<6} {:<22} POLICY",
                "ID", "NAME", "CIDR", "IPV6", "MEMBERS", "ONLINE", "RELAY LIMIT"
            );
            for n in list {
                let policy = if n.policy.is_allow_all() {
                    "allow all".to_string()
                } else {
                    n.policy
                        .rules
                        .iter()
                        .map(|r| r.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                println!(
                    "{:<16} {:<12} {:<18} {:<22} {:<7} {:<6} {:<22} {}",
                    n.id.to_string(),
                    truncate(&n.name, 12),
                    n.cidr.to_string(),
                    n.cidr6.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
                    n.members,
                    n.online,
                    n.relay_limit.to_string(),
                    policy
                );
            }
            Ok(())
        }
        other => fail(other),
    }
}

fn parse_range(s: &str) -> anyhow::Result<(u16, u16)> {
    if s.eq_ignore_ascii_case("none") {
        return Ok((1, 0));
    }
    let (a, b) = s
        .split_once('-')
        .ok_or_else(|| anyhow::anyhow!("--forward-range must be LOW-HIGH or none"))?;
    let lo: u16 = a.trim().parse()?;
    let hi: u16 = b.trim().parse()?;
    if lo > hi || lo < 1024 {
        anyhow::bail!("--forward-range must be within 1024-65535 and LOW <= HIGH");
    }
    Ok((lo, hi))
}

fn print_lighthouses(r: AdminResponse) -> anyhow::Result<()> {
    match r {
        AdminResponse::Lighthouses(list) => {
            println!(
                "{:<14} {:<30} {:<8} {:<10} KEY",
                "NAME", "HOST:PORT", "ROLE", "LINK"
            );
            for l in list {
                println!(
                    "{:<14} {:<30} {:<8} {:<10} {}",
                    truncate(&l.name, 14),
                    format!("{}:{}", l.host, l.port),
                    if l.primary { "primary" } else { "replica" },
                    if l.connected { "up" } else { "down" },
                    l.key
                );
            }
            Ok(())
        }
        other => fail(other),
    }
}

fn print_forwards(r: AdminResponse) -> anyhow::Result<()> {
    match r {
        AdminResponse::Forwards(list) => {
            println!(
                "{:<10} {:<10} {:<24} {:<6} {:<12} {:<18} {:<22} {:<12} LABEL",
                "ID", "KIND", "PUBLIC", "PROTO", "NETWORK", "NODE", "TARGET", "LIGHTHOUSE"
            );
            for f in list {
                let kind = match f.info.kind {
                    ig_proto::tunnel::ForwardKind::Permanent => "permanent",
                    ig_proto::tunnel::ForwardKind::Ephemeral => "ephemeral",
                };
                let node = format!(
                    "{}{}",
                    truncate(&f.node_hostname, 12),
                    if f.node_online { "" } else { " (off)" }
                );
                println!(
                    "{:<10} {:<10} {:<24} {:<6} {:<12} {:<18} {:<22} {:<12} {}",
                    f.info.id,
                    kind,
                    format!("{}:{}", f.info.public_host, f.info.public_port),
                    f.info.proto.to_string(),
                    truncate(&f.network_name, 12),
                    node,
                    truncate(&f.info.target, 22),
                    truncate(&f.lighthouse_name, 12),
                    f.info.label
                );
            }
            Ok(())
        }
        other => fail(other),
    }
}

fn print_devices(r: AdminResponse) -> anyhow::Result<()> {
    match r {
        AdminResponse::Devices(list) => {
            println!(
                "{:<12} {:<16} {:<16} {:<16} {:<24} {:<22} CANDIDATES",
                "NETWORK", "DEVICE", "ADDRESS", "TARGET", "DNS NAME", "ACTIVE GATEWAY"
            );
            for d in list {
                let active = d
                    .active
                    .map(|(n, h)| format!("{} ({})", h, n.short()))
                    .unwrap_or_else(|| "none".into());
                println!(
                    "{:<12} {:<16} {:<16} {:<16} {:<24} {:<22} {}",
                    truncate(&d.network_name, 12),
                    truncate(&d.name, 16),
                    match d.address6 {
                        Some(a6) => format!("{} {}", d.address, a6),
                        None => d.address.to_string(),
                    },
                    match d.target6 {
                        Some(t6) => format!("{} {}", d.target, t6),
                        None => d.target.to_string(),
                    },
                    truncate(&format!("{}.{}.", d.dns_name, d.network_name), 24),
                    truncate(&active, 22),
                    d.candidates.join(", ")
                );
            }
            Ok(())
        }
        other => fail(other),
    }
}

fn expect_ok(r: AdminResponse) -> anyhow::Result<()> {
    match r {
        AdminResponse::Ok => {
            println!("ok");
            Ok(())
        }
        other => fail(other),
    }
}

fn fail(r: AdminResponse) -> anyhow::Result<()> {
    match r {
        AdminResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n - 1).collect();
        t.push('…');
        t
    }
}
