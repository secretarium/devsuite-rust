//! An in-process mock node.
//!
//! The node plays the server side of the SCP handshake (see klave-connector's `cluster_negotiation.rs`), then
//! hands every decrypted message to a per-connection handler and sends back what the handler returns. It lets
//! klave-connector test its channel, and crates built on the channel test themselves against a real SCP session.

use aes_gcm::{Aes128Gcm, KeyInit};
use base64::Engine;
use elliptic_curve::sec1::ToEncodedPoint;
use futures::{SinkExt, StreamExt};
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use p256::{PublicKey, SecretKey};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, tungstenite::Message, WebSocketStream};

use klave_connector::scp::{decrypt_data, encrypt_data};
use klave_connector::types::SCPSession;
use klave_connector::utils::{get_random_bytes, get_sha256_bytes, pointwise_xor};

const WELCOME: &[u8] = b"Hey you! Welcome to Secretarium!";
const HEADER: [u8; 4] = [0, 0, 0, 1];

type Ws = WebSocketStream<TcpStream>;

/// What the node sends back for one received message.
pub enum Out {
    /// Encrypted and framed like any SCP message.
    Message(Vec<u8>),
    /// Sent as a binary frame exactly as given (header included or not), to test malformed input.
    RawFrame(Vec<u8>),
    /// Closes the connection.
    Close,
}

/// Handles the messages of one connection, in order.
pub type Handler = Box<dyn FnMut(Vec<u8>) -> Vec<Out> + Send>;

pub struct MockNode {
    pub url: String,
    /// The key the node proves it holds: what a client passes as its known trusted key.
    pub trusted_key: String,
}

/// A random 64-byte key in the trusted-key format, which no mock node presents.
pub fn other_key() -> String {
    base64::engine::general_purpose::URL_SAFE.encode(get_random_bytes(64))
}

/// Starts a node on a free local port; `new_handler` builds the handler of each connection.
pub async fn start(new_handler: impl Fn() -> Handler + Send + Sync + 'static) -> MockNode {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("mock node: bind");
    let url = format!("ws://{}", listener.local_addr().expect("mock node: address"));
    let signing = SigningKey::random(&mut rand::thread_rng());
    let identity = raw_point(&PublicKey::from(*signing.verifying_key()));
    let trusted_key = base64::engine::general_purpose::URL_SAFE.encode(&identity);

    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (signing, identity, handler) = (signing.clone(), identity.clone(), new_handler());
            tokio::spawn(serve(tcp, signing, identity, handler));
        }
    });
    MockNode { url, trusted_key }
}

async fn serve(tcp: TcpStream, signing: SigningKey, identity: Vec<u8>, mut handler: Handler) {
    let Ok(mut ws) = accept_async(tcp).await else { return };
    let Some(session) = handshake(&mut ws, &signing, &identity).await else { return };
    while let Some(frame) = recv(&mut ws).await {
        let Ok(message) = decrypt_data(&session, &frame) else { return };
        for out in handler(message) {
            match out {
                Out::Message(m) => match encrypt_data(&session, &m, &get_random_bytes(16)) {
                    Ok(ct) => send(&mut ws, &ct).await,
                    Err(_) => return,
                },
                Out::RawFrame(f) => {
                    let _ = ws.send(Message::Binary(f)).await;
                }
                Out::Close => {
                    let _ = ws.close(None).await;
                    return;
                }
            }
        }
    }
}

/// Server side of the handshake. Returns `None` when the client stops, for example after refusing the
/// server's identity.
async fn handshake(ws: &mut Ws, signing: &SigningKey, identity: &[u8]) -> Option<SCPSession> {
    // Client hello, server hello, proof of work.
    let client_ecdh = PublicKey::from_sec1_bytes(&[&[4u8][..], &recv(ws).await?].concat()).ok()?;
    send(ws, &get_random_bytes(36)).await;
    recv(ws).await?;
    // Server identity: pre-master secret || ECDH key || the key the server proves it holds.
    let ecdh = SecretKey::random(&mut rand::thread_rng());
    let pre_master = get_random_bytes(32);
    send(ws, &[pre_master.clone(), raw_point(&ecdh.public_key()), identity.to_vec()].concat()).await;
    let shared = elliptic_curve::ecdh::diffie_hellman(ecdh.to_nonzero_scalar(), client_ecdh.as_affine());
    let sym = pointwise_xor(&pre_master, &get_sha256_bytes(shared.raw_secret_bytes()));
    let session = SCPSession { crypto_key: Aes128Gcm::new(sym[..16].into()), iv: sym[16..32].to_vec() };
    // Client proof of identity: nonce || ECDH key || user key || signature of the nonce, checked as a node would.
    let proof = decrypt_data(&session, &recv(ws).await?).ok()?;
    if proof.len() < 224 {
        return None;
    }
    let user = VerifyingKey::from_sec1_bytes(&[&[4u8][..], &proof[96..160]].concat()).ok()?;
    user.verify(&proof[..32], &Signature::from_slice(&proof[160..224]).ok()?).ok()?;
    // Server proof of identity.
    let random = get_random_bytes(32);
    let sig: Signature = signing.sign(&[&random[..], WELCOME].concat());
    let ct = encrypt_data(&session, &[random, sig.to_bytes().to_vec()].concat(), &get_random_bytes(16)).ok()?;
    send(ws, &ct).await;
    Some(session)
}

async fn recv(ws: &mut Ws) -> Option<Vec<u8>> {
    loop {
        match ws.next().await? {
            Ok(Message::Binary(b)) if b.len() >= 4 => return Some(b[4..].to_vec()),
            Ok(Message::Close(_)) | Err(_) => return None,
            Ok(_) => continue,
        }
    }
}

async fn send(ws: &mut Ws, data: &[u8]) {
    let _ = ws.send(Message::Binary([&HEADER[..], data].concat())).await;
}

fn raw_point(p: &PublicKey) -> Vec<u8> {
    p.to_encoded_point(false).as_bytes()[1..].to_vec()
}
