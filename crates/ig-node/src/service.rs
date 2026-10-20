//! Windows service integration. `ig-node service install` registers the daemon
//! with the Service Control Manager; the SCM then launches `ig-node run
//! --service`, which hands control to [`run`].

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "ig-node";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// What the service needs to start the daemon. Set once before dispatch.
pub struct ServiceArgs {
    pub start: Box<dyn FnOnce(tokio::sync::oneshot::Receiver<()>) -> anyhow::Result<()> + Send>,
}

static ARGS: std::sync::Mutex<Option<ServiceArgs>> = std::sync::Mutex::new(None);

define_windows_service!(ffi_service_main, service_main);

/// Block the current thread running as a Windows service. `start` runs the
/// daemon and must return when the receiver fires.
pub fn run(
    start: Box<dyn FnOnce(tokio::sync::oneshot::Receiver<()>) -> anyhow::Result<()> + Send>,
) -> anyhow::Result<()> {
    *ARGS.lock().unwrap() = Some(ServiceArgs { start });
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = service_body() {
        tracing::error!(error = %e, "service failed");
    }
}

fn service_body() -> anyhow::Result<()> {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let (sync_tx, sync_rx) = mpsc::channel::<()>();
    let handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = sync_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status = service_control_handler::register(SERVICE_NAME, handler)?;
    status.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // Forward the SCM stop request into the async world.
    std::thread::spawn(move || {
        let _ = sync_rx.recv();
        let _ = stop_tx.send(());
    });

    let args = ARGS
        .lock()
        .unwrap()
        .take()
        .expect("service args set before dispatch");
    let result = (args.start)(stop_rx);

    status.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: match &result {
            Ok(()) => ServiceExitCode::Win32(0),
            Err(_) => ServiceExitCode::ServiceSpecific(1),
        },
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    result
}

/// Register the service to start at boot and start it. `launch` is the full
/// argument list the SCM passes to the executable, e.g.
/// `--state-dir C:\ProgramData\Intergalactic\node --socket ig-node run --service --port 0`.
pub fn install_with_layout(launch: Vec<String>) -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let exe: PathBuf = std::env::current_exe()?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("Intergalactic node"),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: launch.into_iter().map(OsString::from).collect(),
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service =
        manager.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    service.set_description("Intergalactic overlay network node")?;
    service.start::<OsString>(&[])?;
    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    )?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        std::thread::sleep(Duration::from_secs(2));
    }
    service.delete()?;
    Ok(())
}

pub fn start() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    manager
        .open_service(SERVICE_NAME, ServiceAccess::START)?
        .start::<OsString>(&[])?;
    Ok(())
}

pub fn stop() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP)?
        .stop()?;
    Ok(())
}
