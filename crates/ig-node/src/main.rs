use anyhow::Context;
use clap::{Parser, Subcommand};
use ig_core::{Engine, EngineConfig, EngineEvent, Membership, NoProtector, NodeState, TunScope};
use ig_node::dns_os::{self, DnsMode, DnsPlan};
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

#[derive(Clone, clap::Args)]
struct RunOpts {
    /// UDP port for WireGuard traffic. 0 picks a random port.
    #[arg(long, default_value_t = 0)]
    port: u16,
    /// Send everything through lighthouse relays; never attempt direct paths.
    #[arg(long)]
    relay_only: bool,
    /// Override the hostname shown to other members.
    #[arg(long)]
    hostname: Option<String>,
    /// How to make peer names resolvable on this machine.
    #[arg(long, value_enum, default_value_t = DnsMode::Auto)]
    dns: DnsMode,
    /// Offer to forward traffic for devices registered on this host's LANs.
    /// The lighthouse picks one gateway per device and fails over when it leaves.
    #[arg(long)]
    gateway: bool,
    /// Internal: started by the Windows Service Control Manager.
    #[arg(long, hide = true)]
    service: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon (foreground). Needs permission to create TUN devices.
    Run(RunOpts),
    /// Print this node's public key (creates an identity if needed).
    Identity,
    /// Manage the Windows service (install, uninstall, start, stop).
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
}

#[derive(Subcommand, Clone)]
enum ServiceCmd {
    /// Register `ig-node` as a Windows service that starts at boot, and start it.
    Install {
        #[command(flatten)]
        opts: RunOpts,
    },
    Uninstall,
    Start,
    Stop,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let state_path = cli.state_dir.join("node.json");

    match cli.cmd {
        Cmd::Identity => {
            init_logging(false, &cli.state_dir);
            let state = load_or_create(&state_path)?;
            println!("{}", state.private_key.public());
            Ok(())
        }
        Cmd::Run(opts) => {
            init_logging(opts.service, &cli.state_dir);
            let state = load_or_create(&state_path)?;
            if opts.service {
                #[cfg(windows)]
                {
                    let socket = cli.socket.clone();
                    return ig_node::service::run(Box::new(move |stop| {
                        let rt = tokio::runtime::Runtime::new()?;
                        let result =
                            rt.block_on(run(state, state_path, socket, opts, async move {
                                let _ = stop.await;
                            }));
                        // Never wait on a straggling blocking task; the SCM is waiting on us.
                        rt.shutdown_timeout(std::time::Duration::from_secs(3));
                        result
                    }));
                }
                #[cfg(not(windows))]
                anyhow::bail!("--service is only meaningful on Windows");
            }
            let rt = tokio::runtime::Runtime::new()?;
            let result = rt.block_on(run(state, state_path, cli.socket, opts, shutdown_signal()));
            rt.shutdown_timeout(std::time::Duration::from_secs(3));
            result
        }
        Cmd::Service { cmd } => {
            init_logging(false, &cli.state_dir);
            #[cfg(windows)]
            {
                match cmd {
                    ServiceCmd::Install { opts } => {
                        let mut launch = vec![
                            "--state-dir".to_string(),
                            cli.state_dir.to_string_lossy().into_owned(),
                            "--socket".to_string(),
                            cli.socket.to_string_lossy().into_owned(),
                            "run".to_string(),
                            "--service".to_string(),
                            "--port".to_string(),
                            opts.port.to_string(),
                            "--dns".to_string(),
                            format!("{:?}", opts.dns).to_lowercase(),
                        ];
                        if opts.relay_only {
                            launch.push("--relay-only".into());
                        }
                        if opts.gateway {
                            launch.push("--gateway".into());
                        }
                        if let Some(h) = &opts.hostname {
                            launch.push("--hostname".into());
                            launch.push(h.clone());
                        }
                        ig_node::service::install_with_layout(launch)?;
                        println!("service `ig-node` installed and started");
                    }
                    ServiceCmd::Uninstall => {
                        ig_node::service::uninstall()?;
                        println!("service removed");
                    }
                    ServiceCmd::Start => ig_node::service::start()?,
                    ServiceCmd::Stop => ig_node::service::stop()?,
                }
                Ok(())
            }
            #[cfg(not(windows))]
            {
                let _ = cmd;
                anyhow::bail!(
                    "`service` is for Windows. On Linux use deploy/ig-node.service with systemd."
                )
            }
        }
    }
}

fn init_logging(to_file: bool, state_dir: &std::path::Path) {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if to_file {
        let _ = std::fs::create_dir_all(state_dir);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(state_dir.join("ig-node.log"))
            .expect("open log file");
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

fn load_or_create(state_path: &std::path::Path) -> anyhow::Result<NodeState> {
    match NodeState::load(state_path)
        .with_context(|| format!("reading {}", state_path.display()))?
    {
        Some(s) => Ok(s),
        None => {
            let s = NodeState::generate();
            s.save(state_path)
                .with_context(|| format!("writing {}", state_path.display()))?;
            tracing::info!(path = %state_path.display(), "created new node identity");
            Ok(s)
        }
    }
}

async fn run(
    state: NodeState,
    state_path: PathBuf,
    socket: PathBuf,
    opts: RunOpts,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    let hostname = opts
        .hostname
        .clone()
        .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().into_owned());
    let keypair = Keypair::from_private(state.private_key.clone());
    let (engine, mut events) = Engine::start(
        EngineConfig {
            keypair,
            hostname,
            os: paths::os_tag().to_string(),
            udp_port: opts.port,
            memberships: state.memberships.clone(),
            persistent_keepalive: Some(25),
            relay_only: opts.relay_only,
            gateway: opts.gateway,
            upstream_dns: Vec::new(),
        },
        Arc::new(NoProtector),
    )
    .await?;
    tracing::info!(node = %engine.node_id(), udp_port = engine.udp_port(), "node running");
    let dns_mode = dns_os::resolve_mode(opts.dns);
    tracing::info!(?dns_mode, "dns mode");

    // Interfaces we created, by network. Reconciled on every membership change.
    let mut tuns: HashMap<NetworkId, (Membership, String)> = HashMap::new();
    // Resolver configuration applied last; None until the first reconcile.
    let mut dns_plan: Option<DnsPlan> = None;
    reconcile(
        &engine,
        &mut tuns,
        engine.memberships(),
        dns_mode,
        &mut dns_plan,
    );
    let mut gateway_prefixes = GatewayState::default();
    reconcile_gateway(&engine, opts.gateway, &mut gateway_prefixes);
    dns_os::apply_hosts(dns_mode, &engine.status());

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
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            ev = events.recv() => {
                let Some(ev) = ev else { break };
                match ev {
                    EngineEvent::MembershipsChanged(list) => {
                        let st = NodeState { private_key: private_key.clone(), memberships: list.clone() };
                        if let Err(e) = st.save(&state_path) {
                            tracing::error!(error = %e, "failed to save state");
                        }
                        reconcile(&engine, &mut tuns, list, dns_mode, &mut dns_plan);
                        dns_os::apply_hosts(dns_mode, &engine.status());
                        reconcile_gateway(&engine, opts.gateway, &mut gateway_prefixes);
                    }
                    EngineEvent::PeersChanged => {
                        dns_os::apply_hosts(dns_mode, &engine.status());
                    }
                    EngineEvent::LighthouseStatus { lighthouse, connected } => {
                        tracing::info!(%lighthouse, connected, "lighthouse status");
                    }
                }
            }
        }
    }
    tracing::info!("shutting down");
    ipc_task.abort();
    tracing::debug!("shutdown: engine");
    engine.shutdown().await;
    tracing::debug!("shutdown: resolver cleanup");
    dns_os::cleanup(dns_mode);
    if opts.gateway {
        ig_node::gateway_os::remove();
    }
    tracing::debug!("shutdown: firewall cleanup");
    ig_node::firewall::remove_all();
    tracing::info!("shutdown complete");
    Ok(())
}

/// Enable or disable kernel forwarding for the networks in which this node is
/// the active gateway of at least one device.
fn reconcile_gateway(engine: &Engine, enabled: bool, current: &mut GatewayState) {
    if !enabled {
        return;
    }
    let me = engine.node_id();
    let memberships = engine.memberships();
    let mut wanted = GatewayState::default();
    for m in &memberships {
        let mine = m.network.my_devices(&me);
        if mine.is_empty() {
            continue;
        }
        wanted.prefixes.push(m.network.cidr);
        if mine.iter().any(|d| d.address6.is_some()) {
            if let Some(c6) = m.network.cidr6 {
                wanted.prefixes6.push(c6);
            }
        }
        for d in mine {
            wanted.devices.push((
                std::net::IpAddr::V4(d.address),
                std::net::IpAddr::V4(d.target),
            ));
            if let (Some(a6), Some(t6)) = (d.address6, d.target6) {
                wanted
                    .devices
                    .push((std::net::IpAddr::V6(a6), std::net::IpAddr::V6(t6)));
            }
        }
    }
    wanted.prefixes.sort();
    wanted.prefixes.dedup();
    wanted.prefixes6.sort();
    wanted.prefixes6.dedup();
    wanted.devices.sort();
    if wanted != *current {
        for m in &memberships {
            for d in m.network.my_devices(&me) {
                tracing::info!(network = %m.network.name, device = %d.name, target = %d.target, target6 = ?d.target6, "acting as gateway");
            }
        }
        ig_node::gateway_os::apply(&wanted.prefixes, &wanted.prefixes6, &wanted.devices);
        *current = wanted;
    }
}

#[derive(Default, PartialEq, Eq)]
struct GatewayState {
    prefixes: Vec<ipnet::Ipv4Net>,
    prefixes6: Vec<ipnet::Ipv6Net>,
    devices: Vec<(std::net::IpAddr, std::net::IpAddr)>,
}

/// Create TUNs for new memberships, drop TUNs for memberships that went away,
/// recreate TUNs whose addresses changed. Then point the resolver at them:
/// the desired DNS plan is derived from the interfaces that exist afterwards
/// and applied when it differs from `dns_plan`, the plan applied last. So a
/// removed network, a renamed network or a new DNS suffix all reach the OS.
fn reconcile(
    engine: &Engine,
    tuns: &mut HashMap<NetworkId, (Membership, String)>,
    memberships: Vec<Membership>,
    dns_mode: DnsMode,
    dns_plan: &mut Option<DnsPlan>,
) {
    let wanted: HashMap<NetworkId, Membership> =
        memberships.into_iter().map(|m| (m.network.id, m)).collect();
    let stale: Vec<NetworkId> = tuns
        .iter()
        .filter(|(id, (m, _))| {
            wanted.get(id).is_none_or(|w| {
                w.network.address != m.network.address
                    || w.network.cidr != m.network.cidr
                    || w.network.address6 != m.network.address6
                    || w.network.cidr6 != m.network.cidr6
            })
        })
        .map(|(id, _)| *id)
        .collect();
    for id in stale {
        tracing::info!(network = %id, "removing interface");
        engine.detach_tun(TunScope::Network(id));
        if let Some((_, name)) = tuns.remove(&id) {
            ig_node::firewall::remove_interface(&name);
        }
    }
    for (id, m) in wanted {
        if let Some((existing, _)) = tuns.get_mut(&id) {
            // Same addresses; refresh the stored copy (policy/DNS names may differ).
            *existing = m;
            continue;
        }
        let taken: Vec<String> = tuns.values().map(|(_, name)| name.clone()).collect();
        match OsTun::create(&m.network, &taken) {
            Ok(tun) => {
                let name = ig_core::TunDevice::name(&tun);
                if let Err(e) = engine.attach_tun(TunScope::Network(id), Arc::new(tun)) {
                    tracing::error!(error = %e, "attach failed");
                    continue;
                }
                ig_node::firewall::allow_interface(&name);
                tuns.insert(id, (m, name));
            }
            Err(e) => {
                tracing::error!(network = %m.network.name, error = %e, "cannot create tun device (need root/CAP_NET_ADMIN on Linux, wintun.dll + admin on Windows)");
            }
        }
    }
    let next = DnsPlan::new(tuns.values().map(|(m, name)| (name.as_str(), &m.network)));
    dns_os::apply_plan(dns_mode, dns_plan, next);
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
        IpcRequest::Expose {
            network,
            proto,
            public_port,
            target,
            label,
            lighthouse,
        } => {
            let id = engine
                .memberships()
                .into_iter()
                .find(|m| m.network.name == network || m.network.id.to_string() == network)
                .map(|m| m.network.id);
            match id {
                Some(id) => match engine
                    .expose(id, proto, public_port, target, label, lighthouse)
                    .await
                {
                    Ok(info) => IpcResponse::Exposed(info),
                    Err(e) => IpcResponse::Error {
                        message: e.to_string(),
                    },
                },
                None => IpcResponse::Error {
                    message: format!("not a member of `{network}`"),
                },
            }
        }
        IpcRequest::Unexpose { id } => match engine.unexpose(&id).await {
            Ok(()) => IpcResponse::Ok,
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
