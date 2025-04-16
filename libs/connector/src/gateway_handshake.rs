use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};
use futures::{future::BoxFuture, stream::{SplitSink, SplitStream}, StreamExt};
use std::time::Duration;

use crate::{cluster_negotiation, key::Key, types::{SCPOptions, SCPSession}};
use crate::scp::ConnectionState;

#[derive(Debug)]
pub struct SCPProto {
    pub id: String,
    pub version: String,
    pub server_type: String,
    pub server_version: String,
    pub server_tag: String,
}


pub async fn try_gateway_handshake(
    writer: &mut SplitSink<&mut WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    reader: &mut SplitStream<&mut WebSocketStream<MaybeTlsStream<TcpStream>>>,
    user_key: &Key,
    known_trusted_key: Option<&str>,
    scp_options: Option<SCPOptions>,
) -> Result<(SCPSession, ConnectionState), Box<dyn std::error::Error + Send + Sync>> {
    // Allocate a buffer to read the initial bytes (at least 4 for skipping)
    let mut total_received = 0;
    let mut proto_info_bytes = Vec::new();
    let scp_options = scp_options.unwrap_or_else(|| SCPOptions::default());

    loop {
        let read_result = tokio::time::timeout(Duration::from_secs(scp_options.gateway_timeout), reader.next()).await;

        match read_result {
            Ok(Some(Ok(Message::Binary(data)))) => {
                // Append the received data to our buffer
                proto_info_bytes.extend_from_slice(&data);
                total_received += data.len();
            }
            Ok(Some(Ok(Message::Close(_)))) => {
                return Err("Connection closed unexpectedly during handshake".into());
            }
            Ok(Some(Ok(Message::Ping(_)))) => {
                // Handle ping if necessary
                continue;
            }
            Ok(Some(Ok(Message::Pong(_)))) => {
                // Handle pong if necessary
                continue;
            }
            Ok(Some(Ok(Message::Text(_)))) => {
                // Handle text messages if necessary
                continue;
            }
            Ok(Some(Ok(Message::Frame(_)))) => {
                // Handle frame messages if necessary
                continue;
            }
            Ok(Some(Err(e))) => {
                // Handle errors from the WebSocket stream
                return Err(format!("Error reading from WebSocket stream: {}", e).into());
            }
            Ok(None) => {
                // Handle the case where the stream ends gracefully
                return Err("Connection ended unexpectedly during handshake".into());
            }
            Err(_timeout) => {
                let (scp_session, connection_state) = cluster_negotiation::process(
                    writer, reader, user_key, known_trusted_key, Duration::from_secs(scp_options.connect_timeout)).await?;
                return Ok((scp_session, connection_state));
            }
        }

        if total_received > 256 { // Add a safety break to prevent infinite loops on malformed data
            return Err("Received too much data without valid protocol information".into());
        }
    }
}

pub trait Handshaker: Send + Sync + 'static {
    fn handshake<'a>(
        &self,
        ws_stream: &'a mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        user_key: Key,
        known_trusted_key: Option<String>,
        scp_options: Option<SCPOptions>
    ) -> BoxFuture<'a, Result<(SCPSession, ConnectionState), Box<dyn std::error::Error + Send + Sync>>>;
}

pub struct BloodBeerExchangeHandshaker;

#[async_trait]
impl Handshaker for BloodBeerExchangeHandshaker {
    fn handshake<'a>(
        &self,
        ws_stream: &'a mut WebSocketStream<MaybeTlsStream<TcpStream>>,
        user_key: Key,
        known_trusted_key: Option<String>,
        scp_options: Option<SCPOptions>,
    ) -> BoxFuture<'a, Result<(SCPSession, ConnectionState), Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            let (mut writer, mut reader) = ws_stream.split();
            let (scp_session, connection_state) = try_gateway_handshake(&mut writer, &mut reader, &user_key, known_trusted_key.as_deref(), scp_options).await?;
            Ok((scp_session, connection_state))
        })
    }
}

pub fn blood_beer_exchange() -> impl Handshaker {
    BloodBeerExchangeHandshaker
}