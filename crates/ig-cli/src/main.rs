use clap::{Parser, Subcommand};
use ig_node::{ipc, paths};
use ig_proto::ipc::{IpcRequest, IpcResponse, PeerPath, StatusReport};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ig", version, about = "Intergalactic: join overlay networks")]
struct Cli {
    /// Control socket of the node daemon.
    #[arg(long, env = "IG_SOCKET", default_value_os_t = paths::default_socket())]
    socket: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Join a network using an invite string (`ig1:...`).
    Join { invite: String },
    /// Leave a network by name or id.
    Leave { network: String },
    /// Show networks and peers.
    Status,
    /// List peers only.
    Peers,
    /// List joined networks only.
    Networks,
    /// Inspect or rewrite invite strings (no daemon needed).
    Invite {
        #[command(subcommand)]
        cmd: InviteCmd,
    },
    /// Publish a local port on the lighthouse's public address while this node is up.
    /// `ig expose 8080` forwards <lighthouse>:<public port> to 127.0.0.1:8080.
    Expose {
        /// Local port (published as this node's overlay address), or
        /// `<device>:PORT` for a registered gateway device.
        target: String,
        /// Network whose lighthouse should publish it (default: the only or first one).
        #[arg(long)]
        network: Option<String>,
        /// Ask for a specific public port inside the lighthouse's range.
        #[arg(long)]
        public_port: Option<u16>,
        #[arg(long)]
        udp: bool,
        #[arg(long, default_value = "")]
        label: String,
        /// Lighthouse (name or host) that should publish the port. Default: the first connected one.
        #[arg(long)]
        lighthouse: Option<String>,
    },
    /// Remove an ephemeral forward by id.
    Unexpose { id: String },
    /// List forwards that point at this node.
    Exposes,
}

#[derive(Subcommand)]
enum InviteCmd {
    /// Show what an invite contains.
    Show { invite: String },
    /// Print the same invite with a different lighthouse host (and optional port),
    /// for a lighthouse that is reachable under another name from where you are.
    Rehost {
        invite: String,
        host: String,
        #[arg(long)]
        port: Option<u16>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Join { invite } => {
            match ipc::request(&cli.socket, &IpcRequest::Join { invite }).await? {
                IpcResponse::Joined(info) => {
                    println!("joined {} as {} ({})", info.name, info.address, info.cidr);
                    Ok(())
                }
                other => fail(other),
            }
        }
        Cmd::Leave { network } => {
            match ipc::request(&cli.socket, &IpcRequest::Leave { network }).await? {
                IpcResponse::Ok => {
                    println!("left");
                    Ok(())
                }
                other => fail(other),
            }
        }
        Cmd::Status => {
            let st = status(&cli.socket).await?;
            print_header(&st);
            print_networks(&st);
            print_devices(&st);
            if st.networks.iter().any(|n| !n.info.forwards.is_empty()) {
                print_forwards(&st);
            }
            println!();
            print_peers(&st);
            Ok(())
        }
        Cmd::Peers => {
            let st = status(&cli.socket).await?;
            print_peers(&st);
            Ok(())
        }
        Cmd::Networks => {
            let st = status(&cli.socket).await?;
            print_networks(&st);
            Ok(())
        }
        Cmd::Expose {
            target,
            network,
            public_port,
            udp,
            label,
            lighthouse,
        } => {
            let target = if target.contains(':') {
                target
            } else {
                format!("self:{target}")
            };
            let network = match network {
                Some(n) => n,
                None => {
                    let st = status(&cli.socket).await?;
                    st.networks
                        .first()
                        .map(|n| n.info.name.clone())
                        .ok_or_else(|| anyhow::anyhow!("not a member of any network"))?
                }
            };
            let proto = if udp {
                ig_proto::tunnel::ForwardProto::Udp
            } else {
                ig_proto::tunnel::ForwardProto::Tcp
            };
            match ipc::request(
                &cli.socket,
                &IpcRequest::Expose {
                    network,
                    proto,
                    public_port,
                    target,
                    label,
                    lighthouse,
                },
            )
            .await?
            {
                IpcResponse::Exposed(f) => {
                    println!(
                        "{}://{}:{}  ->  {}   (id {})",
                        f.proto, f.public_host, f.public_port, f.target, f.id
                    );
                    println!("ephemeral: gone when this node disconnects from that lighthouse or after `ig unexpose {}`", f.id);
                    if f.target.starts_with("self:") {
                        println!("note: the service must listen on this node's overlay address (or 0.0.0.0), not only on localhost");
                    }
                    Ok(())
                }
                other => fail(other),
            }
        }
        Cmd::Unexpose { id } => {
            match ipc::request(&cli.socket, &IpcRequest::Unexpose { id }).await? {
                IpcResponse::Ok => {
                    println!("removed");
                    Ok(())
                }
                other => fail(other),
            }
        }
        Cmd::Exposes => {
            let st = status(&cli.socket).await?;
            print_forwards(&st);
            Ok(())
        }
        Cmd::Invite { cmd } => match cmd {
            InviteCmd::Show { invite } => {
                let inv: ig_proto::Invite = invite.parse()?;
                println!("lighthouse {}:{}", inv.host, inv.port);
                println!("key        {}", inv.lighthouse);
                println!("network    {} ({})", inv.network_name, inv.network);
                Ok(())
            }
            InviteCmd::Rehost { invite, host, port } => {
                let mut inv: ig_proto::Invite = invite.parse()?;
                inv.host = host;
                if let Some(p) = port {
                    inv.port = p;
                }
                println!("{}", inv.encode());
                Ok(())
            }
        },
    }
}

async fn status(socket: &std::path::Path) -> anyhow::Result<StatusReport> {
    match ipc::request(socket, &IpcRequest::Status).await? {
        IpcResponse::Status(s) => Ok(s),
        other => {
            fail(other)?;
            unreachable!()
        }
    }
}

fn print_header(st: &StatusReport) {
    if let Some(n) = &st.node {
        println!("node     {n}");
    }
    println!("hostname {}", st.hostname);
    println!("udp port {}", st.udp_port);
    println!();
}

fn print_networks(st: &StatusReport) {
    if st.networks.is_empty() {
        println!("no networks joined. Use `ig join <invite>`.");
        return;
    }
    println!(
        "{:<12} {:<16} {:<24} {:<28} {:<10} {:<12} {:<20} LIGHTHOUSES",
        "NETWORK", "ADDRESS", "IPV6", "DNS NAME", "INTERFACE", "POLICY", "RELAY LIMIT"
    );
    for n in &st.networks {
        let policy = if n.info.policy.is_allow_all() {
            "allow all".to_string()
        } else {
            format!("{} rules", n.info.policy.rules.len())
        };
        let lhs: Vec<String> = n
            .lighthouses
            .iter()
            .map(|(h, up)| format!("{h}{}", if *up { "" } else { " (down)" }))
            .collect();
        println!(
            "{:<12} {:<16} {:<24} {:<28} {:<10} {:<12} {:<20} {}",
            truncate(&n.info.name, 12),
            format!("{}/{}", n.info.address, n.info.cidr.prefix_len()),
            n.info
                .address6
                .map(|a| format!(
                    "{}/{}",
                    a,
                    n.info.cidr6.map(|c| c.prefix_len()).unwrap_or(128)
                ))
                .unwrap_or_else(|| "-".into()),
            truncate(&n.info.fqdn(), 28),
            n.interface.clone().unwrap_or_else(|| "-".into()),
            policy,
            n.info.relay_limit.to_string(),
            if lhs.is_empty() {
                format!(
                    "{}{}",
                    n.lighthouse,
                    if n.lighthouse_connected {
                        ""
                    } else {
                        " (down)"
                    }
                )
            } else {
                lhs.join(", ")
            }
        );
    }
}

fn print_forwards(st: &StatusReport) {
    let mut any = false;
    for n in &st.networks {
        for f in &n.info.forwards {
            if !any {
                println!();
                println!(
                    "{:<10} {:<10} {:<6} {:<26} {:<22} {:<10} LABEL",
                    "FORWARD", "KIND", "PROTO", "PUBLIC", "TARGET", "NETWORK"
                );
                any = true;
            }
            let kind = match f.kind {
                ig_proto::tunnel::ForwardKind::Permanent => "permanent",
                ig_proto::tunnel::ForwardKind::Ephemeral => "ephemeral",
            };
            println!(
                "{:<10} {:<10} {:<6} {:<26} {:<22} {:<10} {}",
                f.id,
                kind,
                f.proto.to_string(),
                format!("{}:{}", f.public_host, f.public_port),
                truncate(&f.target, 22),
                truncate(&n.info.name, 10),
                f.label
            );
        }
    }
    if !any {
        println!("no forwards. Use `ig expose <port>`.");
    }
}

fn print_devices(st: &StatusReport) {
    let me = st.node;
    let mut any = false;
    for n in &st.networks {
        for d in &n.info.devices {
            if !any {
                println!();
                println!(
                    "{:<12} {:<16} {:<16} {:<16} {:<30} GATEWAY",
                    "NETWORK", "DEVICE", "ADDRESS", "TARGET", "DNS NAME"
                );
                any = true;
            }
            let gw = match d.gateway {
                Some(g) if Some(g) == me => "this node".to_string(),
                Some(g) => st
                    .peers
                    .iter()
                    .find(|p| p.node == g)
                    .map(|p| p.hostname.clone())
                    .unwrap_or_else(|| g.short()),
                None => "none (unreachable)".into(),
            };
            println!(
                "{:<12} {:<16} {:<16} {:<16} {:<30} {}",
                truncate(&n.info.name, 12),
                truncate(&d.name, 16),
                match d.address6 {
                    Some(a6) => format!("{} {}", d.address, a6),
                    None => d.address.to_string(),
                },
                match d.target6 {
                    Some(t6) => format!("{} {}", d.target, t6),
                    None => d.target.to_string(),
                },
                truncate(
                    &format!(
                        "{}.{}.{}",
                        d.dns_name,
                        ig_proto::control::dns_label(&n.info.name),
                        n.info.dns_domain
                    ),
                    30
                ),
                gw
            );
        }
    }
}

fn print_peers(st: &StatusReport) {
    if st.peers.is_empty() {
        println!("no peers.");
        return;
    }
    let net_names: std::collections::HashMap<_, _> = st
        .networks
        .iter()
        .map(|n| (n.info.id, n.info.name.clone()))
        .collect();
    println!(
        "{:<20} {:<30} {:<36} {:<7} {:<22} {:<10} {:<8} TX/RX",
        "PEER", "ADDRESSES", "DNS NAMES", "PATH", "ENDPOINT", "HANDSHAKE", "STATE"
    );
    for p in &st.peers {
        let addrs: Vec<String> = p
            .addresses
            .iter()
            .map(|(n, a)| {
                format!(
                    "{}={}",
                    net_names
                        .get(n)
                        .cloned()
                        .unwrap_or_else(|| n.short_string()),
                    a
                )
            })
            .collect();
        let path = match p.path {
            PeerPath::None => "-",
            PeerPath::Direct => "direct",
            PeerPath::Relay => "relay",
        };
        let hs = match p.last_handshake_secs_ago {
            Some(s) => format!(
                "{}",
                humantime::format_duration(std::time::Duration::from_secs(s))
            ),
            None => "-".into(),
        };
        let names: Vec<String> = p.names.iter().map(|(_, n)| n.clone()).collect();
        println!(
            "{:<20} {:<30} {:<36} {:<7} {:<22} {:<10} {:<8} {}/{}",
            truncate(&p.hostname, 20),
            truncate(&addrs.join(","), 30),
            truncate(&names.join(","), 36),
            path,
            p.endpoint
                .map(|e| e.to_string())
                .unwrap_or_else(|| "-".into()),
            hs,
            if p.online { "online" } else { "offline" },
            human_bytes(p.tx_bytes),
            human_bytes(p.rx_bytes),
        );
    }
}

trait ShortString {
    fn short_string(&self) -> String;
}
impl ShortString for ig_proto::NetworkId {
    fn short_string(&self) -> String {
        self.to_string()[..8].to_string()
    }
}

fn human_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b}{}", UNITS[0])
    } else {
        format!("{v:.1}{}", UNITS[i])
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

fn fail(r: IpcResponse) -> anyhow::Result<()> {
    match r {
        IpcResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}
