//! Where the client side of an SCP session is terminated: what holds the user's key and the session key.
//!
//! The channel ([`crate::channel`]) owns the WebSocket and the framing; a [`Terminator`] does the cryptography. It
//! makes the client hello, answers the server's identity with the client's proof of identity (signed with the
//! user's key), checks the server's proof, then encrypts and decrypts every message. [`LocalTerminator`] does all of
//! this in this process. Another implementation can do it elsewhere (for example in the user's browser), so that
//! the process running the channel never holds the user's private key nor the session key: it only relays bytes.

use std::sync::Mutex;

use aes_gcm::{Aes128Gcm, KeyInit};
use async_trait::async_trait;
use base64::Engine;
use p256::SecretKey;
use rand::rngs::OsRng;
use thiserror::Error;

use crate::cluster_negotiation::{client_proof_of_identity, extract_key_and_iv, verify_server_proof};
use crate::key::Key;
use crate::scp::{decrypt_data, encrypt_data};
use crate::types::SCPSession;
use crate::utils::get_random_bytes;

#[derive(Debug, Error)]
pub enum TerminationError {
    /// This handshake step or this message is invalid; for a received message, the channel stays usable.
    #[error("{0}")]
    Invalid(String),
    /// The terminator cannot serve this session any more (for example, it is gone): the channel is unusable.
    #[error("terminator unavailable: {0}")]
    Unavailable(String),
}

/// The cryptographic side of one SCP session, in the order the channel uses it: [`hello`](Self::hello),
/// [`identify`](Self::identify), [`confirm`](Self::confirm), then any number of [`seal`](Self::seal) and
/// [`open`](Self::open). A terminator serves one session.
#[async_trait]
pub trait Terminator: Send + Sync {
    /// The client hello: the session's ephemeral ECDH public key, 64 bytes (x then y).
    async fn hello(&self) -> Result<Vec<u8>, TerminationError>;
    /// Takes the server identity (pre-master secret 32, server ECDH key 64, server key 64) and returns the
    /// encrypted client proof of identity. A terminator that knows the cluster's trusted key must refuse a server
    /// that presents another key: the channel checks it too, but only the terminator's check protects its keys.
    async fn identify(&self, server_identity: &[u8]) -> Result<Vec<u8>, TerminationError>;
    /// Checks the encrypted server proof of identity. The session is usable only after it succeeds.
    async fn confirm(&self, server_proof: &[u8]) -> Result<(), TerminationError>;
    /// Encrypts one message (IV offset then ciphertext).
    async fn seal(&self, message: &[u8]) -> Result<Vec<u8>, TerminationError>;
    /// Decrypts one received message (without its frame header).
    async fn open(&self, data: &[u8]) -> Result<Vec<u8>, TerminationError>;
    /// The session is over. The default does nothing.
    async fn close(&self) {}
}

#[derive(Default)]
struct Local {
    ecdh: Option<SecretKey>,
    server_key: Option<Vec<u8>>,
    session: Option<SCPSession>,
    confirmed: bool,
}

/// Terminates the session in this process, with the user's key: what [`crate::channel::open`] uses.
pub struct LocalTerminator {
    user_key: Key,
    trusted_key: Option<Vec<u8>>,
    state: Mutex<Local>,
}

impl LocalTerminator {
    /// `known_trusted_key`: the cluster's key (64 bytes, URL-safe base64), which the server must present.
    pub fn new(user_key: Key, known_trusted_key: Option<&str>) -> Result<Self, TerminationError> {
        let trusted_key = known_trusted_key.map(decode_trusted_key).transpose()?;
        Ok(Self { user_key, trusted_key, state: Mutex::default() })
    }

    /// The session key, once confirmed (for the legacy [`crate::SCP`] client).
    pub fn session(&self) -> Option<SCPSession> {
        let s = self.state.lock().ok()?;
        s.confirmed.then(|| s.session.clone()).flatten()
    }

    fn with<T>(&self, f: impl FnOnce(&mut Local) -> Result<T, TerminationError>) -> Result<T, TerminationError> {
        let mut s = self.state.lock().map_err(|_| TerminationError::Unavailable("state lock poisoned".into()))?;
        f(&mut s)
    }
}

/// The 64-byte key of a trusted-key string (URL-safe base64, padded or not).
pub fn decode_trusted_key(key: &str) -> Result<Vec<u8>, TerminationError> {
    let t = key.trim().trim_end_matches('=');
    let k = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(t)
        .map_err(|_| TerminationError::Invalid("trusted key: not URL-safe base64".into()))?;
    if k.len() != 64 {
        return Err(TerminationError::Invalid("Invalid trusted key length".into()));
    }
    Ok(k)
}

#[async_trait]
impl Terminator for LocalTerminator {
    async fn hello(&self) -> Result<Vec<u8>, TerminationError> {
        self.with(|s| {
            if s.ecdh.is_some() {
                return Err(TerminationError::Invalid("hello: this session has started already".into()));
            }
            let ecdh = SecretKey::random(&mut OsRng);
            let public = ecdh.public_key().to_sec1_bytes()[1..].to_vec();
            s.ecdh = Some(ecdh);
            Ok(public)
        })
    }

    async fn identify(&self, server_identity: &[u8]) -> Result<Vec<u8>, TerminationError> {
        let invalid = |e: crate::cluster_negotiation::HandshakeError| TerminationError::Invalid(e.to_string());
        self.with(|s| {
            let ecdh = s.ecdh.as_ref().ok_or_else(|| TerminationError::Invalid("identify: no hello".into()))?;
            if s.session.is_some() {
                return Err(TerminationError::Invalid("identify: done already".into()));
            }
            if server_identity.len() != 160 {
                return Err(TerminationError::Invalid("server identity: must be 160 bytes".into()));
            }
            if self.trusted_key.as_deref().is_some_and(|k| k != &server_identity[96..160]) {
                return Err(TerminationError::Invalid("Server identity does not match the known trusted key".into()));
            }
            let (key, iv) = extract_key_and_iv(server_identity, ecdh).map_err(invalid)?;
            let session = SCPSession { crypto_key: Aes128Gcm::new(key.as_slice().into()), iv };
            let ecdh_public = ecdh.public_key().to_sec1_bytes()[1..].to_vec();
            let proof = client_proof_of_identity(&self.user_key, &get_random_bytes(32), &ecdh_public).map_err(invalid)?;
            let sealed = encrypt_data(&session, &proof, &get_random_bytes(16)).map_err(invalid)?;
            s.server_key = Some(server_identity[96..160].to_vec());
            s.session = Some(session);
            Ok(sealed)
        })
    }

    async fn confirm(&self, server_proof: &[u8]) -> Result<(), TerminationError> {
        self.with(|s| {
            let (Some(session), Some(server_key)) = (&s.session, &s.server_key) else {
                return Err(TerminationError::Invalid("confirm: no identify".into()));
            };
            let proof = decrypt_data(session, server_proof).map_err(|e| TerminationError::Invalid(e.to_string()))?;
            verify_server_proof(&proof, server_key).map_err(|e| TerminationError::Invalid(e.to_string()))?;
            s.confirmed = true;
            Ok(())
        })
    }

    async fn seal(&self, message: &[u8]) -> Result<Vec<u8>, TerminationError> {
        self.with(|s| match (&s.session, s.confirmed) {
            (Some(session), true) => encrypt_data(session, message, &get_random_bytes(16)).map_err(|e| TerminationError::Invalid(e.to_string())),
            _ => Err(TerminationError::Invalid("seal: the session is not open".into())),
        })
    }

    async fn open(&self, data: &[u8]) -> Result<Vec<u8>, TerminationError> {
        self.with(|s| match (&s.session, s.confirmed) {
            (Some(session), true) => decrypt_data(session, data).map_err(|e| TerminationError::Invalid(e.to_string())),
            _ => Err(TerminationError::Invalid("open: the session is not open".into())),
        })
    }
}
