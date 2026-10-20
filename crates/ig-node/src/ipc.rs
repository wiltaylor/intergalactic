//! Local control socket between `ig` and `ig-node`.

use ig_proto::ipc::{IpcRequest, IpcResponse};
use interprocess::local_socket::tokio::{prelude::*, Stream};
use interprocess::local_socket::{GenericFilePath, GenericNamespaced, ListenerOptions, Name};
use std::future::Future;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub fn socket_name(path: &Path) -> std::io::Result<Name<'static>> {
    if cfg!(windows) {
        let base = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("ig-node");
        base.to_string().to_ns_name::<GenericNamespaced>()
    } else {
        path.to_path_buf().to_fs_name::<GenericFilePath>()
    }
}

/// Serve requests until the future is dropped. `handle` is called per request.
pub async fn serve<F, Fut>(path: &Path, handle: F) -> std::io::Result<()>
where
    F: Fn(IpcRequest) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = IpcResponse> + Send,
{
    if !cfg!(windows) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(path);
    }
    let listener = ListenerOptions::new()
        .name(socket_name(path)?)
        .create_tokio()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660));
    }
    tracing::info!(path = %path.display(), "control socket ready");
    loop {
        let conn = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "ipc accept failed");
                continue;
            }
        };
        let handle = handle.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(&conn);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<IpcRequest>(&line) {
                Ok(req) => handle(req).await,
                Err(e) => IpcResponse::Error {
                    message: format!("bad request: {e}"),
                },
            };
            let mut out = serde_json::to_vec(&resp).unwrap_or_default();
            out.push(b'\n');
            let mut w = &conn;
            let _ = w.write_all(&out).await;
        });
    }
}

pub async fn request(path: &Path, req: &IpcRequest) -> anyhow::Result<IpcResponse> {
    let conn = Stream::connect(socket_name(path)?).await.map_err(|e| {
        anyhow::anyhow!(
            "cannot reach the node daemon at {}: {e}\nIs `ig-node run` running? On Linux you may need sudo.",
            path.display()
        )
    })?;
    let mut w = &conn;
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    let mut reader = BufReader::new(&conn);
    let mut resp = String::new();
    reader.read_line(&mut resp).await?;
    Ok(serde_json::from_str(&resp)?)
}
