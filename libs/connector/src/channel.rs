//! The Secretarium Connection Protocol (SCP) as a secure channel, and nothing more.
//!
//! [`open`] connects the WebSocket, runs the handshake (authenticating the server against the known
//! trusted key, when one is given) and returns two halves that carry opaque messages: the sender encrypts
//! and frames them, the receiver strips the frame header and decrypts them. The channel knows nothing about
//! what the messages contain.
//!
//! [`open_with`] does the same with the cryptography done by a [`Terminator`]: the channel then holds neither
//! the user's key nor the session key, and only relays bytes.

use std::sync::Arc;

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::gateway_handshake;
use crate::key::Key;
use crate::scp::{CHUNK_SIZE, SCP};
use crate::terminator::{LocalTerminator, TerminationError, Terminator};
use crate::types::SCPOptions;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Length of the nng pair1 header that starts every frame.
const FRAME_HEADER: usize = 4;

#[derive(Debug, Error)]
pub enum ChannelError {
    /// The WebSocket could not be opened, or the handshake failed (including an untrusted server).
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// The WebSocket failed after the handshake.
    #[error("transport error: {0}")]
    Transport(String),
    /// A frame arrived that is not a valid SCP message; the channel itself is still usable.
    #[error("invalid frame: {0}")]
    Frame(String),
    #[error("channel closed")]
    Closed,
}

/// Connects to `url` and establishes the secure channel as `user_key`.
/// With `known_trusted_key` (64 bytes, URL-safe base64) the server must present that key.
pub async fn open(
    url: &str,
    user_key: &Key,
    known_trusted_key: Option<&str>,
    options: Option<SCPOptions>,
) -> Result<(ChannelSender, ChannelReceiver), ChannelError> {
    let terminator = LocalTerminator::new(user_key.clone(), known_trusted_key).map_err(|e| ChannelError::Handshake(e.to_string()))?;
    open_with(url, Arc::new(terminator), known_trusted_key, options).await
}

/// Connects to `url` and establishes the secure channel, with `terminator` doing the cryptography.
/// With `known_trusted_key` the server must present that key (the terminator should check it too).
pub async fn open_with(
    url: &str,
    terminator: Arc<dyn Terminator>,
    known_trusted_key: Option<&str>,
    options: Option<SCPOptions>,
) -> Result<(ChannelSender, ChannelReceiver), ChannelError> {
    let mut request = url.into_client_request().map_err(|e| ChannelError::Handshake(e.to_string()))?;
    request.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static("pair1.sp.nanomsg.org"));
    let (mut stream, _) = connect_async(request).await.map_err(|e| ChannelError::Handshake(e.to_string()))?;

    {
        let (mut writer, mut reader) = (&mut stream).split();
        if let Err(e) = gateway_handshake::try_gateway_negotiation(&mut writer, &mut reader, terminator.as_ref(), known_trusted_key, options).await {
            terminator.close().await;
            return Err(ChannelError::Handshake(e.to_string()));
        }
    }

    let (sink, stream) = stream.split();
    Ok((
        ChannelSender { sink: Arc::new(AsyncMutex::new(sink)), terminator: terminator.clone() },
        ChannelReceiver { stream, terminator },
    ))
}

fn transport(e: TerminationError) -> ChannelError {
    ChannelError::Transport(e.to_string())
}

/// Sending half: encrypts and frames messages. Cheap to clone; clones share the connection.
#[derive(Clone)]
pub struct ChannelSender {
    sink: Arc<AsyncMutex<SplitSink<WsStream, Message>>>,
    terminator: Arc<dyn Terminator>,
}

impl ChannelSender {
    pub async fn send(&self, message: &[u8]) -> Result<(), ChannelError> {
        let encrypted = self.terminator.seal(message).await.map_err(transport)?;
        let mut sink = self.sink.lock().await;
        SCP::send_chunked(&mut sink, &encrypted, CHUNK_SIZE, true)
            .await
            .map_err(|e| ChannelError::Transport(e.to_string()))
    }

    pub async fn close(&self) {
        let _ = self.sink.lock().await.send(Message::Close(None)).await;
        self.terminator.close().await;
    }
}

/// Receiving half: yields decrypted messages in arrival order.
pub struct ChannelReceiver {
    stream: SplitStream<WsStream>,
    terminator: Arc<dyn Terminator>,
}

impl ChannelReceiver {
    /// The next message; `None` once the connection is closed. A frame that cannot be decrypted is
    /// returned as [`ChannelError::Frame`] and the channel stays usable; a terminator that is gone, as
    /// [`ChannelError::Transport`].
    pub async fn recv(&mut self) -> Option<Result<Vec<u8>, ChannelError>> {
        loop {
            return match self.stream.next().await? {
                Ok(Message::Binary(data)) => Some(self.open_frame(&data).await),
                Ok(Message::Close(_)) => None,
                Ok(_) => continue,
                Err(e) => Some(Err(ChannelError::Transport(e.to_string()))),
            };
        }
    }

    async fn open_frame(&self, data: &[u8]) -> Result<Vec<u8>, ChannelError> {
        if data.len() < FRAME_HEADER {
            return Err(ChannelError::Frame("shorter than the frame header".into()));
        }
        match self.terminator.open(&data[FRAME_HEADER..]).await {
            Ok(m) => Ok(m),
            Err(TerminationError::Invalid(e)) => Err(ChannelError::Frame(e)),
            Err(e) => Err(transport(e)),
        }
    }
}
