use aes_gcm::aead::Aead;
use aes_gcm::Nonce;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message, WebSocketStream};
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;
use futures::future::BoxFuture;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::watch;

use crate::cluster_negotiation::HandshakeError;
use crate::gateway_handshake::{self, Handshaker};
use crate::key::Key;
use crate::tx::{TransactionNotificationHandlers, Tx};
use crate::types::OptionalArgs;
use crate::types::{SCPEndpoint, SCPMessage, SCPOptions, SCPSession};
use crate::utils::{get_random_bytes, increment_by};
use crate::Args;

pub type MessageCallback = Arc<dyn Fn(&str) + Send + Sync + 'static>;
pub type HandshakeFn = Arc<dyn Fn(&mut WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>) -> BoxFuture<'static, Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send + Sync + 'static>;

pub const CHUNK_SIZE: usize = 524_288; // 512 KB

#[derive(Debug)]
pub enum ConnectionState {
    CONNECTING,
    OPEN,
    CLOSING,
    CLOSED,
}

impl Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::CONNECTING => write!(f, "CONNECTING"),
            ConnectionState::OPEN => write!(f, "OPEN"),
            ConnectionState::CLOSING => write!(f, "CLOSING"),
            ConnectionState::CLOSED => write!(f, "CLOSED"),
        }
    }
}

pub fn encrypt_data(session: &SCPSession, data: &[u8], iv_offset: &[u8]) -> Result<Vec<u8>, HandshakeError> {        
    let iv: [u8; 12] = increment_by(session.iv.as_slice(), iv_offset).unwrap()[0..12]
        .try_into()
        .map_err(|_| HandshakeError::Generic("Failed to create IV".into()))?;
    let nonce = Nonce::from_slice(&iv); // Using IV as nonce for simplicity in this example
    let encrypted = match session.crypto_key.encrypt(nonce, data) {
        Ok(encrypted) => encrypted,
        Err(e) => return Err(HandshakeError::AesGcm(e)),
    };
    Ok([iv_offset, encrypted.as_slice()].concat())
}

pub fn decrypt_data(session: &SCPSession, encrypted_data: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    let iv_offset = encrypted_data[0..16].to_vec();
    let iv: [u8; 12] = increment_by(session.iv.as_slice(), iv_offset.as_slice()).unwrap()[0..12]
        .try_into()
        .map_err(|_| HandshakeError::Generic("Failed to create IV".into()))?; 
    
    let nonce = Nonce::from_slice(&iv); // Using IV as nonce for simplicity in this example
    let decrypted = match session.crypto_key.decrypt(nonce, encrypted_data[16..].as_ref()) {
        Ok(decrypted) => decrypted,
        Err(e) => return Err(HandshakeError::AesGcm(e))
    };
    Ok(decrypted)
}

pub struct SCP {
    endpoint: SCPEndpoint,
    user_key: Key,
    options: Option<SCPOptions>,    
    session: Arc<AsyncMutex<Option<SCPSession>>>,
    sender: Option<mpsc::Sender<Vec<u8>>>,
    task_handle: Option<JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>>,
    handshaker: Option<Arc<dyn Handshaker>>,
    connection_state: ConnectionState,
    pub requests: Arc<AsyncMutex<HashMap<String, Arc<AsyncMutex<TransactionNotificationHandlers>>>>>,
    shutdown_signal: Option<watch::Sender<bool>>,
}

impl Display for SCP {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SCP {{ endpoint: {}, user_key: {}, options: {:?}, connection_state: {} }}", 
            self.endpoint.url, 
            self.user_key, 
            self.options, 
            self.connection_state)
    }
}

impl SCP {
    pub fn new(url: &str, user_key: Option<&Key>, known_trusted_key: Option<&str>) -> Self {
        let mut requests = HashMap::new();
        requests.insert(
            "default".to_string(),
            Arc::new(AsyncMutex::new(TransactionNotificationHandlers::default())),
        );        
        let (shutdown_tx, _) = watch::channel(false); 

        SCP {
            endpoint: SCPEndpoint {
                url: url.to_string(),
                known_trusted_key: match known_trusted_key {
                    Some(key) => Some(key.to_string()),
                    None => None,
                },
            },
            user_key: match user_key {
                Some(key) => key.clone(),
                None => Key::new(None)
            },
            options: None,
            session: Arc::new(AsyncMutex::new(None)),
            sender: None,
            task_handle: None,
            handshaker: None,
            connection_state: ConnectionState::CLOSED,
            requests: Arc::new(AsyncMutex::new(requests)),
            shutdown_signal: Some(shutdown_tx),
        }
    }

    pub fn set_handshake(&mut self, handshaker: impl Handshaker) {
        self.handshaker = Some(Arc::new(handshaker));
    }

    pub async fn get_default_callbacks(&self) -> Arc<AsyncMutex<TransactionNotificationHandlers>> {
        Arc::clone(&self.requests)
            .lock()
            .await
            .get("default")
            .unwrap()
            .clone()
    }

    pub async fn connect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.connection_state = ConnectionState::CONNECTING;

        // Set the default handshake using a closure that calls perform_handshake
        self.set_handshake(gateway_handshake::blood_beer_exchange());

        let mut request = self.endpoint.url.clone().into_client_request()
            .map_err(|e| format!("Failed to create request: {}", e))?;
        request.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static("pair1.sp.nanomsg.org"));        
        
        let (mut stream, _) = connect_async(request).await?;

        // Perform handshake if a function is provided
        if let Some(ref handshaker) = self.handshaker {
            match handshaker.handshake(&mut stream, self.user_key.clone(), self.endpoint.known_trusted_key.clone(), self.options.clone()).await {
                Ok((scp_session, connection_state)) => {
                    self.connection_state = connection_state;

                    // Store the session key
                    let mut session = self.session.lock().await;
                    *session = Some(scp_session);        
                }
                Err(e) => {
                    eprintln!("Handshake failed: {}", e);
                    return Err(e);
                }
            }
        }

        let (write, read) = stream.split();
        let (tx, rx) = mpsc::channel::<Vec<u8>>(32);
        self.sender = Some(tx.clone());

        let shutdown_rx = self.shutdown_signal.as_ref().unwrap().subscribe();        
        let session = Arc::clone(&self.session);
        let requests = Arc::clone(&self.requests);

        let task = tokio::spawn(async move {
            SCP::handle_connection(session, read, write, rx, requests, shutdown_rx)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        });
        self.task_handle = Some(task);

        println!("WebSocket connection established.");
        Ok(())
    }

    pub fn prepare(scp_session: &SCPSession, msg_to_send: &[u8]) -> Vec<u8> {
        // Encrypt the message using the session key
        let iv_offset = get_random_bytes(16);                            
        let encrypted = encrypt_data(&scp_session, &msg_to_send, &iv_offset).unwrap();                
        return encrypted.to_vec();                               
    }

    async fn send_chunked(
        write: &mut futures::stream::SplitSink<WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>, Message>,
        data: &[u8],
        chunk_size: usize,
        requires_hop: bool,        
    ) -> Result<(), tokio_tungstenite::tungstenite::Error> {
        let length = data.len();

        if length > chunk_size {
            let chunks_count = ((length - 1) / chunk_size) + 1;
            let offset = if requires_hop { 4 } else { 0 };
            let frame_size = chunk_size + 20 + offset;
            let mut partial_data = vec![0u8; frame_size];
    
            if requires_hop {
                partial_data[0..4].copy_from_slice(&[0, 0, 0, 1]);
            }
    
            // Magic header `chunk${chunkNumber}/${chunksCount}`
            partial_data[offset..offset + 8].copy_from_slice(&[99, 104, 117, 110, 107, 0, 47, chunks_count as u8]);
    
            // Add total length of the data frame
            let total_length = (length as u32).to_be_bytes();
            partial_data[offset + 8..offset + 12].copy_from_slice(&total_length);
    
            // Add a random ID to differentiate messages
            let random_id = get_random_bytes(8);
            partial_data[offset + 12..offset + 20].copy_from_slice(&random_id);
    
            // Sending the data in chunks
            for chunk_number in 0..chunks_count {
                // Tagging the chunk number
                partial_data[offset + 5] = chunk_number as u8;
    
                // Copy the chunk data into the frame
                let start = chunk_size * chunk_number;
                let end = std::cmp::min(chunk_size * (chunk_number + 1), length);
                partial_data[offset + 20..offset + 20 + (end - start)].copy_from_slice(&data[start..end]);
    
                // Send the chunk
                write.send(Message::Binary(partial_data.clone())).await?;
            }
        } else {
            let mut data_to_send = data.to_vec();
            if requires_hop {
                let mut with_hop = vec![0, 0, 0, 1];
                with_hop.extend_from_slice(&data_to_send);
                data_to_send = with_hop;
            }
            write.send(Message::Binary(data_to_send)).await?;
        } 
        Ok(())
    }

    async fn handle_response(
        handlers: &Vec<Arc<dyn Fn(Option<&str>, Option<&str>) + Send + Sync>>,
        default_handlers: &Vec<Arc<dyn Fn(Option<&str>, Option<&str>) + Send + Sync>>,
        request_id: &str,
        response: Option<&str>,
    ) {
        if !handlers.is_empty() {
            for callback in handlers.iter() {
                callback(Some(request_id), response);
            }
        }
        else if !default_handlers.is_empty() {
            for callback in default_handlers.iter() {
                callback(Some(request_id), response);
            }
        } else {
            println!("Received {}, but no handlers registered for {}.", response.unwrap_or("response"), request_id);
        }        
    }

    async fn handle_connection<'a>(       
        session: Arc<AsyncMutex<Option<SCPSession>>>,
        mut read: futures::stream::SplitStream<WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>>,
        mut write: futures::stream::SplitSink<WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>, Message>,
        mut receiver: mpsc::Receiver<Vec<u8>>,
        requests: Arc<AsyncMutex<HashMap<String, Arc<AsyncMutex<TransactionNotificationHandlers>>>>>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<(), tokio_tungstenite::tungstenite::Error> {
        let mut periodic_timers: HashMap<String, tokio::time::Instant> = HashMap::new();     

        loop {
            // Calculate the next timer expiration
            let next_timer = periodic_timers
                .values()
                .min()
                .cloned()
                .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(3600)); // Default to a far future time

            tokio::select! {
                result = read.next() => {
                    match result {
                        Some(Ok(msg)) => {
                            if msg.is_binary() {                                
                                let buffer = msg.into_data()[4..].to_vec();
                                let session = session.lock().await;
                                if let Some(ref scp_session) = *session {                                    
                                    let decrypted = decrypt_data(&scp_session, &buffer).unwrap();
                                    match String::from_utf8(decrypted) {
                                        Ok(text) => {
                                            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&text) {
                                                let request_id = match json_value["requestId"].as_str() {
                                                    Some(id) => id.to_string(),
                                                    None => "default".to_string(),
                                                };
                                                // Use transaction-specific callbacks if they exist; otherwise, use default callbacks
                                                let requests = requests.lock().await;           
                                                let default_handlers = requests.get("default").unwrap().lock().await;  
                                                if let Some(handlers) = requests.get(&request_id) {
                                                    let mut handlers = handlers.lock().await;
                                                    if handlers.periodic_message.is_some() {
                                                        //Update periodic_timers if request_id does not already exist
                                                        if periodic_timers.get(&request_id).is_none() {
                                                            println!("Adding periodic timer for request_id: {}", request_id);
                                                            periodic_timers.insert(request_id.clone(), tokio::time::Instant::now() + match handlers.periodic_message {
                                                                Some(ref periodic_message) => periodic_message.interval,
                                                                None => Duration::from_secs(3600),
                                                            });                                                            
                                                        }
                                                    }

                                                    if json_value.get("result").is_some() {
                                                        let result_value = match json_value["result"].as_str() {
                                                            Some(value) => value,
                                                            None => &format!("{}", serde_json::to_string(&json_value["result"]).unwrap()),
                                                        };
                                                        Self::handle_response(&handlers.on_result, &default_handlers.on_result, &request_id, Some(result_value)).await;
                                                        if let Some(callback) = handlers.promise_message.pop() {
                                                            callback(Some(&request_id), Some(result_value));
                                                        }                                            
                                                    } else if json_value.get("error").is_some() {
                                                        let error_value = match json_value["error"].as_str() {
                                                            Some(value) => value,
                                                            None => &format!("{}", serde_json::to_string(&json_value["result"]).unwrap()),
                                                        };
                                                        Self::handle_response(&handlers.on_error, &default_handlers.on_error, &request_id, Some(error_value)).await;
                                                        if let Some(callback) = handlers.promise_message.pop() {
                                                            callback(Some(&request_id), Some(error_value));
                                                        }                                            
                                                    } else if json_value.get("state").is_some() {
                                                        let state_value = json_value["state"].as_str().unwrap_or("");
                                                        match state_value {
                                                            "Acknowledged" => Self::handle_response(&handlers.on_acknowledged, &default_handlers.on_acknowledged, &request_id, Some("Acknowledged")).await,
                                                            "Committed" => Self::handle_response(&handlers.on_committed, &default_handlers.on_committed, &request_id, Some("Committed")).await,
                                                            "Executed" => {
                                                                Self::handle_response(&handlers.on_executed, &default_handlers.on_executed, &request_id, Some("Executed")).await;
                                                                if let Some(callback) = handlers.promise_message.pop() {
                                                                    callback(Some(&request_id), Some("Executed"));
                                                                }                                            
                                                                    }
                                                            "Failed" => {
                                                                Self::handle_response(&handlers.on_error, &default_handlers.on_error, &request_id, Some("Failed")).await;
                                                                if let Some(callback) = handlers.promise_message.pop() {
                                                                    callback(Some(&request_id), Some("Failed"));
                                                                }                                            
                                                            }
                                                            _ => {
                                                                println!("Received unknown state: {:?}", state_value);
                                                            }
                                                        }
                                                    } else {
                                                        println!("Received unknown message format: {}", text);
                                                    }
                                                }
                                            } else {
                                                println!("Received non-JSON message: {}", text);
                                            }
                                        },
                                        Err(_) => {
                                            println!("Binary data: {:?}", hex::encode(buffer));
                                        },
                                    }                                
                                }
                            } else if msg.is_close() {
                                println!("Server initiated close.");
                                break;
                            } else {
                                println!("Received non-binary message: {:?}", msg);
                            }
                        }
                        Some(Err(e)) => {
                            println!("Error receiving message: {}", e);
                            break;
                        }
                        None => {
                            println!("WebSocket stream closed by server.");
                            break;
                        }
                    }
                }
                Some(msg_to_send) = tokio::sync::mpsc::Receiver::recv(&mut receiver) => {
                    let session = session.lock().await;
                    if let Some(ref scp_session) = *session {
                        if let Err(e) = Self::send_chunked(&mut write, &Self::prepare(scp_session, &msg_to_send), CHUNK_SIZE, true).await {
                            eprintln!("Error sending message: {}", e);
                            break;
                        };
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        println!("Shutdown signal received. Closing handle_connection...");
                        break;
                    }
                }    
                _ = tokio::time::sleep_until(next_timer) => {
                    // Handle periodic transactions
                    let now = tokio::time::Instant::now();
                    let requests = requests.lock().await;
    
                    for (request_id, handlers) in requests.iter() {
                        let handlers = handlers.lock().await;
                        if let Some(periodic_message) = &handlers.periodic_message {
                            let next_tick = periodic_timers.entry(request_id.clone()).or_insert_with(|| now + periodic_message.interval);
                            if *next_tick <= now {
                                println!("Sending periodic message for request_id: {}", request_id);
    
                                // Prepare and send the periodic message
                                let session = session.lock().await;
                                if let Some(ref scp_session) = *session {                   
                                    let query_str = serde_json::to_string(&periodic_message.scp_message).unwrap();
                                    let query_bytes = query_str.as_bytes();                        
                                    if let Err(e) = Self::send_chunked(&mut write, &Self::prepare(scp_session, &query_bytes), CHUNK_SIZE, true).await {
                                        eprintln!("Error sending message: {}", e);
                                        break;
                                    };
                                }
    
                                // Schedule the next tick
                                *next_tick = now + periodic_message.interval;
                            }
                        }
                    }
                }                           
            }
        }

        println!("Closing WebSocket connection.");
        let _ = write.send(Message::Close(None)).await;
        Ok(())
    }

    pub async fn send(
        &mut self,
        app: &str,
        command: &str,
        request_id: &str,
        args: OptionalArgs,
    ) {
        if let Some(sender) = self.sender.clone() {
            let message = SCPMessage {
                dcapp: app.to_string(),
                function: command.to_string(),
                request_id: request_id.to_string(),
                args: match args {
                    Some(args) => {
                        match args {
                            Args::Map(map) => serde_json::to_string(&map).unwrap(),
                            Args::Str(s) => s,
                        }
                    }
                    None => "{}".to_string(),
                },
            };
            let query_str = serde_json::to_string(&message).unwrap();
            let query_bytes = query_str.as_bytes();
            sender.send(query_bytes.to_vec()).await.unwrap();
        }
    }

    pub async fn close(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.connection_state = ConnectionState::CLOSING;

        // Send the shutdown signal
        if let Some(shutdown_tx) = self.shutdown_signal.take() {
            let _ = shutdown_tx.send(true);
        }

        // Stop the background task
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await?;
        }

        // Clear the sender
        self.sender.take();

        // Clear the session
        {
            let mut session = self.session.lock().await;
            *session = None;
        }

        // Clear the requests map
        {
            let mut requests = self.requests.lock().await;
            requests.clear();
        }

        self.connection_state = ConnectionState::CLOSED;

        println!("WebSocket connection closed and resources cleaned up.");
        Ok(())
    }

    pub async fn new_tx(&mut self, app: &str, command: &str, request_id: Option<String>, args: OptionalArgs) -> Tx {        
        let rid = request_id.unwrap_or_else(|| {
            let random_bytes = get_random_bytes(8);
            format!("rid-{}-{}-{}", app, command, hex::encode(random_bytes))            
        });
        Tx::new(
            self,
            app.to_string(),
            command.to_string(),
            rid.to_string(),
            args,
            None,
        ).await
    }

    pub async fn new_periodic_tx(&mut self, app: &str, command: &str, request_id: Option<String>, args: OptionalArgs, interval_secs: u64) -> Tx {        
        let rid = request_id.unwrap_or_else(|| {
            let random_bytes = get_random_bytes(8);
            format!("rid-{}-{}-{}", app, command, hex::encode(random_bytes))            
        });
        Tx::new(
            self,
            app.to_string(),
            command.to_string(),
            rid.to_string(),
            args,
            Some(Duration::from_secs(interval_secs)),
        ).await 
    }

}
