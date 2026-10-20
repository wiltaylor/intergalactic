//! Length-prefixed frames on a byte stream: `u16 BE length | bytes`.
//! Each frame is exactly one Noise message (max 65535 bytes).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME: usize = 65535;

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    debug_assert!(data.len() <= MAX_FRAME);
    let len = (data.len() as u16).to_be_bytes();
    // Two writes into a buffered/TCP stream are fine; coalesce to one syscall anyway.
    let mut buf = Vec::with_capacity(2 + data.len());
    buf.extend_from_slice(&len);
    buf.extend_from_slice(data);
    w.write_all(&buf).await
}

pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    into: &mut Vec<u8>,
) -> std::io::Result<usize> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    into.clear();
    into.resize(len, 0);
    r.read_exact(into).await?;
    Ok(len)
}
