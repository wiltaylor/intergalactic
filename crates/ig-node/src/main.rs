use anyhow::Context;
use clap::{Parser, Subcommand};
use ig_core::{Engine, EngineConfig, EngineEvent, Membership, NoProtector, NodeState, TunScope};
use ig_node::tun::OsTun;
use ig_node::{ipc, paths};
use ig_proto::ipc::{IpcRequest, IpcResponse};
use ig_proto::{Invite, Keypair, NetworkId};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "ig-node", version, about = "Intergalactic node daemon")]
struct Cli {
    /// Directory holding node.json (identity and joined networks).
    #[arg(long, env = "IG_STATE_DIR", default_value_os_t = paths::default_state_dir())]
    state_dir: PathBuf,
    /// Control socket used by the `ig` CLI.
    #[arg(long, env = "IG_SOCKET", default_value_os_t = paths::default_socket())]
    socket: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon (foreground). Needs permission to create TUN devices.
    Run {
        /// UDP port for WireGuard traffic. 0 picks a random port.
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Send everything through lighthouse relays; never attempt direct paths.
        #[arg(long)]
        relay_only: bool,
        /// Override the hostname shown to other members.
        #[arg(long)]
        hostname: Option<String>,
    },
    /// Print this node's public key (creates an identity if needed).
    Identity,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let state_path = cli.state_dir.join("node.json");
    let state = match NodeState::load(&state_path)
        .with_context(|| format!("reading {}", state_path.display()))?
    {
        Some(s) => s,
        None => {
            let s = NodeState::generate();
            s.save(&state_path)
                .with_context(|| format!("writing {}", state_path.display()))?;
            tracing::info!(path = %state_path.display(), "created new node identity");
            s
        }
    };

    match cli.cmd {
        Cmd::Identity => {
            println!("{}", state.private_key.public());
            Ok(())
        }
        Cmd::Run {
            port,
            relay_only,
            hostname,
        } => run(state, state_path, cli.socket, port, relay_only, hostname).await,
    }
}

async fn run(
    state: NodeState,
    state_path: PathBuf,
    socket: PathBuf,
    port: u16,
    relay_only: bool,
    hostname: Option<String>,
) -> anyhow::Result<()> {
    let hostname =
        hostname.unwrap_or_else(|| gethostname::gethostname().to_string_lossy().into_owned());
    let keypair = Keypair::from_private(state.private_key.clone());
    let (engine, mut events) = Engine::start(
        EngineConfig {
            keypair,
            hostname,
            os: paths::os_tag().to_string(),
            udp_port: port,
            memberships: state.memberships.clone(),
            persistent_keepalive: Some(25),
            relay_only,
        },
        Arc::new(NoProtector),
    )
    .await?;
    println!(
        "node {} listening on udp/{}",
        engine.node_id(),
        engine.udp_port()
    );

    // Interfaces we created, by network. Reconciled on every membership change.
    let mut tuns: HashMap<NetworkId, Membership> = HashMap::new();
    reconcile(&engine, &mut tuns, engine.memberships());

    let ipc_engine = engine.clone();
    let ipc_task = tokio::spawn(async move {
        let engine = ipc_engine;
        ipc::serve(&socket, move |req| {
            let engine = engine.clone();
            async move { handle_ipc(&engine, req).await }
        })
        .await
    });

    let private_key = state.private_key.clone();
    loop {
        tokio::select! {
            _ = shutdown_signal() => break,
            ev = events.recv() => {
                let Some(ev) = ev else { break };
                match ev {
                    EngineEvent::MembershipsChanged(list) => {
                        let st = NodeState { private_key: private_key.clone(), memberships: list.clone() };
                        if let Err(e) = st.save(&state_path) {
                            tracing::error!(error = %e, "failed to save state");
                        }
                        reconcile(&engine, &mut tuns, list);
                    }
                    EngineEvent::PeersChanged => {}
                    EngineEvent::LighthouseStatus { lighthouse, connected } => {
                        tracing::info!(%lighthouse, connected, "lighthouse status");
                    }
                }
            }
        }
    }
    tracing::info!("shutting down");
    ipc_task.abort();
    engine.shutdown().await;
    Ok(())
}

/// Create TUNs for new memberships, drop TUNs for memberships that went away,
/// recreate TUNs whose address or prefix changed.
fn reconcile(
    engine: &Engine,
    tuns: &mut HashMap<NetworkId, Membership>,
    memberships: Vec<Membership>,
) {
    let wanted: HashMap<NetworkId, Membership> =
        memberships.into_iter().map(|m| (m.network.id, m)).collect();
    let stale: Vec<NetworkId> = tuns
        .iter()
        .filter(|(id, m)| {
            wanted.get(id).is_none_or(|w| {
                w.network.address != m.network.address || w.network.cidr != m.network.cidr
            })
        })
        .map(|(id, _)| *id)
        .collect();
    for id in stale {
        tracing::info!(network = %id, "removing interface");
        engine.detach_tun(TunScope::Network(id));
        tuns.remove(&id);
    }
    for (id, m) in wanted {
        if tuns.contains_key(&id) {
            continue;
        }
        match OsTun::create(&m.network) {
            Ok(tun) => {
                if let Err(e) = engine.attach_tun(TunScope::Network(id), Arc::new(tun)) {
                    tracing::error!(error = %e, "attach failed");
                    continue;
                }
                tuns.insert(id, m);
            }
            Err(e) => {
                tracing::error!(network = %m.network.name, error = %e, "cannot create tun device (need root/CAP_NET_ADMIN on Linux, wintun.dll + admin on Windows)");
            }
        }
    }
}

async fn handle_ipc(engine: &Engine, req: IpcRequest) -> IpcResponse {
    match req {
        IpcRequest::Status | IpcRequest::Peers => IpcResponse::Status(engine.status()),
        IpcRequest::Join { invite } => match invite.parse::<Invite>() {
            Ok(inv) => match engine.join(&inv).await {
                Ok(info) => IpcResponse::Joined(info),
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            },
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        IpcRequest::Leave { network } => {
            let id = engine
                .memberships()
                .into_iter()
                .find(|m| m.network.name == network || m.network.id.to_string() == network)
                .map(|m| m.network.id);
            match id {
                Some(id) => match engine.leave(id).await {
                    Ok(()) => IpcResponse::Ok,
                    Err(e) => IpcResponse::Error {
                        message: e.to_string(),
                    },
                },
                None => IpcResponse::Error {
                    message: format!("not a member of `{network}`"),
                },
            }
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("sigterm");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
