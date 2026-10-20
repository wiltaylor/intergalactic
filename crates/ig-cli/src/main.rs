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
        "{:<16} {:<16} {:<18} {:<12} {:<12} LIGHTHOUSE",
        "NETWORK", "ADDRESS", "CIDR", "INTERFACE", "POLICY"
    );
    for n in &st.networks {
        let policy = if n.info.policy.is_allow_all() {
            "allow all".to_string()
        } else {
            format!("{} rules", n.info.policy.rules.len())
        };
        println!(
            "{:<16} {:<16} {:<18} {:<12} {:<12} {}{}",
            n.info.name,
            n.info.address.to_string(),
            n.info.cidr.to_string(),
            n.interface.clone().unwrap_or_else(|| "-".into()),
            policy,
            n.lighthouse,
            if n.lighthouse_connected {
                ""
            } else {
                " (disconnected)"
            }
        );
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
        "{:<20} {:<28} {:<7} {:<22} {:<10} {:<12} TX/RX",
        "PEER", "ADDRESSES", "PATH", "ENDPOINT", "HANDSHAKE", "STATE"
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
        println!(
            "{:<20} {:<28} {:<7} {:<22} {:<10} {:<12} {}/{}",
            truncate(&p.hostname, 20),
            truncate(&addrs.join(","), 28),
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
