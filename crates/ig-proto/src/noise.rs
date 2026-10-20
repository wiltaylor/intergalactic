//! Noise_IK over a TCP stream.
//!
//! IK means the initiator (node) already knows the responder's (lighthouse's)
//! static key from the invite, and sends its own static key encrypted in the
//! first message. Two messages complete the handshake. After that the stream
//! carries postcard-encoded messages, each split into Noise transport messages of
//! at most 65535 bytes so large peer lists are not a problem.
//!
//! ```text
//! message layout:  u32 BE total_len | chunk* (each chunk is one framed Noise msg)
//! ```

use crate::framing::{read_frame, write_frame, MAX_FRAME};
use crate::NodeId;
use serde::{de::DeserializeOwned, Serialize};
use snow::{HandshakeState, TransportState};
use tokio::io::{AsyncRead, AsyncWrite};

pub const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const TAG_LEN: usize = 16;
const MAX_PLAINTEXT: usize = MAX_FRAME - TAG_LEN;
/// Hard cap on a single logical message to keep a misbehaving peer from
/// making us allocate without bound.
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("encode: {0}")]
    Encode(#[from] postcard::Error),
    #[error("message too large ({0} bytes)")]
    TooLarge(usize),
    #[error("peer did not send its static key")]
    NoRemoteStatic,
}

pub struct NoiseStream<S> {
    io: S,
    transport: TransportState,
    remote: NodeId,
    scratch: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> NoiseStream<S> {
    /// Node side. `hello` is sent encrypted inside the first handshake message and
    /// the responder's reply payload is returned.
    pub async fn connect<H: Serialize, R: DeserializeOwned>(
        mut io: S,
        local_private: &[u8; 32],
        remote_public: &NodeId,
        hello: &H,
    ) -> Result<(Self, R), NoiseError> {
        let mut hs: HandshakeState = snow::Builder::new(PATTERN.parse().expect("valid pattern"))
            .local_private_key(local_private)?
            .remote_public_key(&remote_public.0)?
            .build_initiator()?;
        let payload = postcard::to_allocvec(hello)?;
        let mut buf = vec![0u8; MAX_FRAME];
        let n = hs.write_message(&payload, &mut buf)?;
        write_frame(&mut io, &buf[..n]).await?;

        let mut frame = Vec::new();
        read_frame(&mut io, &mut frame).await?;
        let n = hs.read_message(&frame, &mut buf)?;
        let reply: R = postcard::from_bytes(&buf[..n])?;
        let transport = hs.into_transport_mode()?;
        Ok((
            NoiseStream {
                io,
                transport,
                remote: *remote_public,
                scratch: buf,
            },
            reply,
        ))
    }

    /// Lighthouse side. Reads the initiator's hello, lets the caller build a reply
    /// (knowing who the remote is), then finishes the handshake.
    pub async fn accept<H: DeserializeOwned, R: Serialize, F>(
        mut io: S,
        local_private: &[u8; 32],
        make_reply: F,
    ) -> Result<(Self, H), NoiseError>
    where
        F: FnOnce(&NodeId, &H) -> R,
    {
        let mut hs: HandshakeState = snow::Builder::new(PATTERN.parse().expect("valid pattern"))
            .local_private_key(local_private)?
            .build_responder()?;
        let mut frame = Vec::new();
        read_frame(&mut io, &mut frame).await?;
        let mut buf = vec![0u8; MAX_FRAME];
        let n = hs.read_message(&frame, &mut buf)?;
        let hello: H = postcard::from_bytes(&buf[..n])?;
        let remote = hs
            .get_remote_static()
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
            .map(NodeId)
            .ok_or(NoiseError::NoRemoteStatic)?;
        let reply = make_reply(&remote, &hello);
        let payload = postcard::to_allocvec(&reply)?;
        let n = hs.write_message(&payload, &mut buf)?;
        write_frame(&mut io, &buf[..n]).await?;
        let transport = hs.into_transport_mode()?;
        Ok((
            NoiseStream {
                io,
                transport,
                remote,
                scratch: buf,
            },
            hello,
        ))
    }

    pub fn remote(&self) -> NodeId {
        self.remote
    }

    pub async fn send<T: Serialize>(&mut self, msg: &T) -> Result<(), NoiseError> {
        let plain = postcard::to_allocvec(msg)?;
        self.send_bytes(&plain).await
    }

    pub async fn send_bytes(&mut self, plain: &[u8]) -> Result<(), NoiseError> {
        if plain.len() > MAX_MESSAGE {
            return Err(NoiseError::TooLarge(plain.len()));
        }
        // Build the whole wire image first so one message is one write.
        let mut wire = Vec::with_capacity(
            4 + plain.len() + 2 * (plain.len() / MAX_PLAINTEXT + 1) * (TAG_LEN + 2),
        );
        wire.extend_from_slice(&(plain.len() as u32).to_be_bytes());
        let mut chunks = plain.chunks(MAX_PLAINTEXT).peekable();
        if chunks.peek().is_none() {
            // Zero-length message still needs one (empty) chunk.
            let n = self.transport.write_message(&[], &mut self.scratch)?;
            wire.extend_from_slice(&(n as u16).to_be_bytes());
            wire.extend_from_slice(&self.scratch[..n]);
        }
        for chunk in chunks {
            let n = self.transport.write_message(chunk, &mut self.scratch)?;
            wire.extend_from_slice(&(n as u16).to_be_bytes());
            wire.extend_from_slice(&self.scratch[..n]);
        }
        use tokio::io::AsyncWriteExt;
        self.io.write_all(&wire).await?;
        Ok(())
    }

    pub async fn recv<T: DeserializeOwned>(&mut self) -> Result<T, NoiseError> {
        let plain = self.recv_bytes().await?;
        Ok(postcard::from_bytes(&plain)?)
    }

    pub async fn recv_bytes(&mut self) -> Result<Vec<u8>, NoiseError> {
        use tokio::io::AsyncReadExt;
        let mut len = [0u8; 4];
        self.io.read_exact(&mut len).await?;
        let total = u32::from_be_bytes(len) as usize;
        if total > MAX_MESSAGE {
            return Err(NoiseError::TooLarge(total));
        }
        let mut out = Vec::with_capacity(total);
        let mut frame = Vec::new();
        loop {
            read_frame(&mut self.io, &mut frame).await?;
            let n = self.transport.read_message(&frame, &mut self.scratch)?;
            out.extend_from_slice(&self.scratch[..n]);
            if out.len() >= total {
                break;
            }
        }
        out.truncate(total);
        Ok(out)
    }

    /// Split into independently usable halves. Each half owns a copy of the
    /// stream handle; Noise state is split by direction so this is sound.
    pub fn into_parts(self) -> (NoiseSender<S>, NoiseReceiver<S>)
    where
        S: SplitIo,
    {
        let (rd, wr) = self.io.split_io();
        let (send_state, recv_state) = DirectionalState::split(self.transport);
        (
            NoiseSender {
                io: wr,
                state: send_state,
                scratch: vec![0u8; MAX_FRAME],
                remote: self.remote,
            },
            NoiseReceiver {
                io: rd,
                state: recv_state,
                scratch: vec![0u8; MAX_FRAME],
                remote: self.remote,
            },
        )
    }
}

/// Splitting a `TransportState` by direction: snow does not offer this, so we keep
/// the full state behind a mutex but each half only ever touches its own
/// direction's cipher state. Contention is nil because the two halves never
/// block each other for long (encrypt/decrypt are microseconds).
pub struct DirectionalState(std::sync::Arc<std::sync::Mutex<TransportState>>);

impl DirectionalState {
    fn split(t: TransportState) -> (Self, Self) {
        let shared = std::sync::Arc::new(std::sync::Mutex::new(t));
        (DirectionalState(shared.clone()), DirectionalState(shared))
    }
}

pub trait SplitIo {
    type Read: AsyncRead + Unpin + Send;
    type Write: AsyncWrite + Unpin + Send;
    fn split_io(self) -> (Self::Read, Self::Write);
}

impl SplitIo for tokio::net::TcpStream {
    type Read = tokio::net::tcp::OwnedReadHalf;
    type Write = tokio::net::tcp::OwnedWriteHalf;
    fn split_io(self) -> (Self::Read, Self::Write) {
        self.into_split()
    }
}

pub struct NoiseSender<S: SplitIo> {
    io: S::Write,
    state: DirectionalState,
    scratch: Vec<u8>,
    remote: NodeId,
}

pub struct NoiseReceiver<S: SplitIo> {
    io: S::Read,
    state: DirectionalState,
    scratch: Vec<u8>,
    remote: NodeId,
}

impl<S: SplitIo> NoiseSender<S> {
    pub fn remote(&self) -> NodeId {
        self.remote
    }

    pub async fn send<T: Serialize>(&mut self, msg: &T) -> Result<(), NoiseError> {
        let plain = postcard::to_allocvec(msg)?;
        if plain.len() > MAX_MESSAGE {
            return Err(NoiseError::TooLarge(plain.len()));
        }
        let mut wire = Vec::with_capacity(4 + plain.len() + 64);
        wire.extend_from_slice(&(plain.len() as u32).to_be_bytes());
        {
            let mut st = self.state.0.lock().expect("noise state poisoned");
            let mut chunks = plain.chunks(MAX_PLAINTEXT).peekable();
            if chunks.peek().is_none() {
                let n = st.write_message(&[], &mut self.scratch)?;
                wire.extend_from_slice(&(n as u16).to_be_bytes());
                wire.extend_from_slice(&self.scratch[..n]);
            }
            for chunk in chunks {
                let n = st.write_message(chunk, &mut self.scratch)?;
                wire.extend_from_slice(&(n as u16).to_be_bytes());
                wire.extend_from_slice(&self.scratch[..n]);
            }
        }
        use tokio::io::AsyncWriteExt;
        self.io.write_all(&wire).await?;
        Ok(())
    }
}

impl<S: SplitIo> NoiseReceiver<S> {
    pub fn remote(&self) -> NodeId {
        self.remote
    }

    pub async fn recv<T: DeserializeOwned>(&mut self) -> Result<T, NoiseError> {
        use tokio::io::AsyncReadExt;
        let mut len = [0u8; 4];
        self.io.read_exact(&mut len).await?;
        let total = u32::from_be_bytes(len) as usize;
        if total > MAX_MESSAGE {
            return Err(NoiseError::TooLarge(total));
        }
        let mut out = Vec::with_capacity(total);
        let mut frame = Vec::new();
        loop {
            read_frame(&mut self.io, &mut frame).await?;
            let n = {
                let mut st = self.state.0.lock().expect("noise state poisoned");
                st.read_message(&frame, &mut self.scratch)?
            };
            out.extend_from_slice(&self.scratch[..n]);
            if out.len() >= total {
                break;
            }
        }
        out.truncate(total);
        Ok(postcard::from_bytes(&out)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keypair;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Hello(String);
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Reply(u32);

    #[tokio::test]
    async fn handshake_and_large_messages_over_tcp() {
        let server = Keypair::generate();
        let client = Keypair::generate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_priv = server.private.0;
        let client_pub = client.public;
        let srv = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (stream, hello): (NoiseStream<_>, Hello) =
                NoiseStream::accept(sock, &server_priv, |who, _h: &Hello| {
                    assert_eq!(*who, client_pub);
                    Reply(7)
                })
                .await
                .unwrap();
            assert_eq!(hello, Hello("hi".into()));
            let (mut tx, mut rx) = stream.into_parts();
            let big: Vec<u8> = rx.recv().await.unwrap();
            assert_eq!(big.len(), 200_000);
            assert!(big.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
            tx.send(&"done".to_string()).await.unwrap();
            let empty: Vec<u8> = rx.recv().await.unwrap();
            assert!(empty.is_empty());
        });
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (stream, reply): (NoiseStream<_>, Reply) =
            NoiseStream::connect(sock, &client.private.0, &server.public, &Hello("hi".into()))
                .await
                .unwrap();
        assert_eq!(reply, Reply(7));
        assert_eq!(stream.remote(), server.public);
        let (mut tx, mut rx) = stream.into_parts();
        let big: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
        tx.send(&big).await.unwrap();
        let s: String = rx.recv().await.unwrap();
        assert_eq!(s, "done");
        tx.send(&Vec::<u8>::new()).await.unwrap();
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_server_key_fails() {
        let server = Keypair::generate();
        let impostor = Keypair::generate();
        let client = Keypair::generate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let imp_priv = impostor.private.0;
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let r: Result<(NoiseStream<_>, Hello), _> =
                NoiseStream::accept(sock, &imp_priv, |_, _: &Hello| Reply(0)).await;
            assert!(r.is_err());
        });
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let r: Result<(NoiseStream<_>, Reply), _> =
            NoiseStream::connect(sock, &client.private.0, &server.public, &Hello("x".into())).await;
        assert!(r.is_err());
    }
}
