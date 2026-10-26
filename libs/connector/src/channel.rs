//! The Secretarium Connection Protocol (SCP) as a secure channel, and nothing more.
//!
//! [`open`] connects the WebSocket, runs the handshake (authenticating the server against the known
//! trusted key, when one is given) and returns two halves that carry opaque messages: the sender encrypts
//! and frames them, the receiver strips the frame header and decrypts them. The channel knows nothing about
//! what the messages contain; see [`crate::client`] for requests, queries and transactions.

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

use crate::gateway_handshake::{self, Handshaker};
use crate::key::Key;
use crate::scp::{decrypt_data, encrypt_data, CHUNK_SIZE, SCP};
use crate::types::{SCPOptions, SCPSession};
use crate::utils::get_random_bytes;

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
    let mut request = url.into_client_request().map_err(|e| ChannelError::Handshake(e.to_string()))?;
    request.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static("pair1.sp.nanomsg.org"));
    let (mut stream, _) = connect_async(request).await.map_err(|e| ChannelError::Handshake(e.to_string()))?;

    let (session, _) = gateway_handshake::blood_beer_exchange()
        .handshake(&mut stream, user_key.clone(), known_trusted_key.map(str::to_string), options)
        .await
        .map_err(|e| ChannelError::Handshake(e.to_string()))?;

    let session = Arc::new(session);
    let (sink, stream) = stream.split();
    Ok((
        ChannelSender { sink: Arc::new(AsyncMutex::new(sink)), session: session.clone() },
        ChannelReceiver { stream, session },
    ))
}

/// Sending half: encrypts and frames messages. Cheap to clone; clones share the connection.
#[derive(Clone)]
pub struct ChannelSender {
    sink: Arc<AsyncMutex<SplitSink<WsStream, Message>>>,
    session: Arc<SCPSession>,
}

impl ChannelSender {
    pub async fn send(&self, message: &[u8]) -> Result<(), ChannelError> {
        let encrypted = encrypt_data(&self.session, message, &get_random_bytes(16))
            .map_err(|e| ChannelError::Transport(e.to_string()))?;
        let mut sink = self.sink.lock().await;
        SCP::send_chunked(&mut sink, &encrypted, CHUNK_SIZE, true)
            .await
            .map_err(|e| ChannelError::Transport(e.to_string()))
    }

    pub async fn close(&self) {
        let _ = self.sink.lock().await.send(Message::Close(None)).await;
    }
}

/// Receiving half: yields decrypted messages in arrival order.
pub struct ChannelReceiver {
    stream: SplitStream<WsStream>,
    session: Arc<SCPSession>,
}

impl ChannelReceiver {
    /// The next message; `None` once the connection is closed. A frame that cannot be decrypted is
    /// returned as [`ChannelError::Frame`] and the channel stays usable.
    pub async fn recv(&mut self) -> Option<Result<Vec<u8>, ChannelError>> {
        loop {
            return match self.stream.next().await? {
                Ok(Message::Binary(data)) => Some(self.open_frame(&data)),
                Ok(Message::Close(_)) => None,
                Ok(_) => continue,
                Err(e) => Some(Err(ChannelError::Transport(e.to_string()))),
            };
        }
    }

    fn open_frame(&self, data: &[u8]) -> Result<Vec<u8>, ChannelError> {
        if data.len() < FRAME_HEADER {
            return Err(ChannelError::Frame("shorter than the frame header".into()));
        }
        decrypt_data(&self.session, &data[FRAME_HEADER..]).map_err(|e| ChannelError::Frame(e.to_string()))
    }
}
