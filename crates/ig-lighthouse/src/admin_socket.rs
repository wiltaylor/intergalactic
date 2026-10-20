//! Local admin endpoint: a Unix socket (or named pipe on Windows) that accepts
//! one JSON `AdminRequest` per line and answers with one JSON `AdminResponse`.

use crate::Lighthouse;
use ig_proto::admin::{AdminRequest, AdminResponse};
use interprocess::local_socket::tokio::{prelude::*, Stream};
use interprocess::local_socket::{GenericFilePath, GenericNamespaced, ListenerOptions, Name};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub fn socket_name(path: &Path) -> std::io::Result<Name<'static>> {
    if cfg!(windows) {
        let base = path.file_name().and_then(|s| s.to_str()).unwrap_or("ig-lighthouse");
        format!("ig-lighthouse-{base}").to_ns_name::<GenericNamespaced>()
    } else {
        path.to_path_buf().to_fs_name::<GenericFilePath>()
    }
}

pub async fn serve(lh: Lighthouse, path: PathBuf) -> std::io::Result<()> {
    let path = path.as_path();
    if !cfg!(windows) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(path);
    }
    let listener = ListenerOptions::new().name(socket_name(path)?).create_tokio()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    tracing::info!(path = %path.display(), "admin socket ready");
    loop {
        let conn = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "admin accept failed");
                continue;
            }
        };
        let lh = lh.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(&conn);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<AdminRequest>(&line) {
                Ok(req) => lh.admin(req),
                Err(e) => AdminResponse::Error { message: format!("bad request: {e}") },
            };
            let mut out = serde_json::to_vec(&resp).unwrap_or_default();
            out.push(b'\n');
            let mut w = &conn;
            let _ = w.write_all(&out).await;
        });
    }
}

/// Client side used by the CLI.
pub async fn request(path: &Path, req: &AdminRequest) -> anyhow::Result<AdminResponse> {
    let conn = Stream::connect(socket_name(path)?).await.map_err(|e| {
        anyhow::anyhow!("cannot reach lighthouse admin socket at {}: {e}. Is `ig-lighthouse serve` running?", path.display())
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
