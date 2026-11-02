//! SCP as a secure channel: handshake, server authentication and the transport of opaque messages.
//! The mock node echoes whatever it receives; nothing here knows about applications or requests.

use std::time::Duration;

use klave_connector::channel::{self, ChannelError};
use klave_connector_test_utils::mock_node::{self as common, other_key, Out};
use klave_connector::{Key, SCP};

const WAIT: Duration = Duration::from_secs(5);

/// Echoes every message; `garbage` triggers malformed frames, `bye` closes the connection.
async fn echo_node() -> common::MockNode {
    common::start(|| {
        Box::new(|message: Vec<u8>| match message.as_slice() {
            b"garbage" => vec![
                Out::RawFrame(vec![0, 0]),             // shorter than the frame header
                Out::RawFrame(vec![0, 0, 0, 1, 7, 7]), // shorter than the IV offset
                Out::RawFrame([vec![0, 0, 0, 1], vec![9; 64]].concat()), // fails authentication
                Out::Message(b"after".to_vec()),
            ],
            b"bye" => vec![Out::Close],
            _ => vec![Out::Message(message)],
        })
    })
    .await
}

async fn next(rx: &mut channel::ChannelReceiver) -> Option<Result<Vec<u8>, ChannelError>> {
    tokio::time::timeout(WAIT, rx.recv()).await.expect("no message within the wait")
}

#[tokio::test]
async fn opens_when_the_server_presents_the_trusted_key() {
    let node = echo_node().await;
    let (tx, mut rx) = channel::open(&node.url, &Key::new(None), Some(&node.trusted_key), None).await.unwrap();
    tx.send(b"ping").await.unwrap();
    assert_eq!(next(&mut rx).await.unwrap().unwrap(), b"ping");
}

#[tokio::test]
async fn refuses_a_server_that_does_not_present_the_trusted_key() {
    let node = echo_node().await;
    let err = channel::open(&node.url, &Key::new(None), Some(&other_key()), None).await.err().expect("must fail");
    assert!(matches!(&err, ChannelError::Handshake(m) if m.contains("trusted key")), "{err}");
}

#[tokio::test]
async fn legacy_scp_client_refuses_it_too() {
    let node = echo_node().await;
    let mut scp = SCP::new(&node.url, Some(&Key::new(None)), Some(&other_key()));
    let err = scp.connect().await.err().expect("must fail").to_string();
    assert!(err.contains("trusted key"), "{err}");
}

#[tokio::test]
async fn without_a_trusted_key_the_server_is_not_authenticated() {
    // Unchanged behaviour: any server completes the handshake.
    let node = echo_node().await;
    channel::open(&node.url, &Key::new(None), None, None).await.unwrap();
}

#[tokio::test]
async fn carries_opaque_bytes_in_order() {
    let node = echo_node().await;
    let (tx, mut rx) = channel::open(&node.url, &Key::new(None), Some(&node.trusted_key), None).await.unwrap();
    let messages: [&[u8]; 3] = [&[0, 159, 255, 0], b"", &[42; 4096]];
    for m in messages {
        tx.send(m).await.unwrap();
    }
    for m in messages {
        assert_eq!(next(&mut rx).await.unwrap().unwrap(), m);
    }
}

#[tokio::test]
async fn reports_malformed_frames_and_stays_usable() {
    let node = echo_node().await;
    let (tx, mut rx) = channel::open(&node.url, &Key::new(None), Some(&node.trusted_key), None).await.unwrap();
    tx.send(b"garbage").await.unwrap();
    for _ in 0..3 {
        assert!(matches!(next(&mut rx).await, Some(Err(ChannelError::Frame(_)))));
    }
    assert_eq!(next(&mut rx).await.unwrap().unwrap(), b"after");
}

#[tokio::test]
async fn ends_when_the_server_closes() {
    let node = echo_node().await;
    let (tx, mut rx) = channel::open(&node.url, &Key::new(None), Some(&node.trusted_key), None).await.unwrap();
    tx.send(b"bye").await.unwrap();
    assert!(next(&mut rx).await.is_none());
}

// ---------- the cryptography done by a terminator ----------

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use klave_connector::{LocalTerminator, TerminationError, Terminator};

/// A terminator elsewhere: the channel gets only what it returns. It can be made to go away.
struct Remote {
    inner: LocalTerminator,
    gone: AtomicBool,
}

impl Remote {
    fn new(trusted_key: Option<&str>) -> Arc<Self> {
        Arc::new(Self { inner: LocalTerminator::new(Key::new(None), trusted_key).unwrap(), gone: AtomicBool::new(false) })
    }
    fn up(&self) -> Result<(), TerminationError> {
        if self.gone.load(Ordering::SeqCst) {
            return Err(TerminationError::Unavailable("gone".into()));
        }
        Ok(())
    }
}

#[async_trait]
impl Terminator for Remote {
    async fn hello(&self) -> Result<Vec<u8>, TerminationError> {
        self.up()?;
        self.inner.hello().await
    }
    async fn identify(&self, server_identity: &[u8]) -> Result<Vec<u8>, TerminationError> {
        self.up()?;
        self.inner.identify(server_identity).await
    }
    async fn confirm(&self, server_proof: &[u8]) -> Result<(), TerminationError> {
        self.up()?;
        self.inner.confirm(server_proof).await
    }
    async fn seal(&self, message: &[u8]) -> Result<Vec<u8>, TerminationError> {
        self.up()?;
        self.inner.seal(message).await
    }
    async fn open(&self, data: &[u8]) -> Result<Vec<u8>, TerminationError> {
        self.up()?;
        self.inner.open(data).await
    }
}

#[tokio::test]
async fn a_terminator_does_the_cryptography() {
    let node = echo_node().await;
    let t = Remote::new(Some(&node.trusted_key));
    let (tx, mut rx) = channel::open_with(&node.url, t.clone(), Some(&node.trusted_key), None).await.unwrap();
    tx.send(b"ping").await.unwrap();
    assert_eq!(next(&mut rx).await.unwrap().unwrap(), b"ping");
}

#[tokio::test]
async fn the_terminator_refuses_an_untrusted_server_whatever_the_channel_says() {
    // The relaying side gives no trusted key (or a wrong one): the terminator, which knows the cluster's key, refuses.
    let node = echo_node().await;
    let t = Remote::new(Some(&other_key()));
    let err = channel::open_with(&node.url, t, None, None).await.err().expect("must fail");
    assert!(matches!(&err, ChannelError::Handshake(m) if m.contains("trusted key")), "{err}");
}

#[tokio::test]
async fn without_its_terminator_the_channel_is_unusable() {
    let node = echo_node().await;
    let t = Remote::new(Some(&node.trusted_key));
    let (tx, mut rx) = channel::open_with(&node.url, t.clone(), Some(&node.trusted_key), None).await.unwrap();
    tx.send(b"ping").await.unwrap();
    t.gone.store(true, Ordering::SeqCst);
    assert!(matches!(next(&mut rx).await, Some(Err(ChannelError::Transport(_)))));
    assert!(matches!(tx.send(b"again").await, Err(ChannelError::Transport(_))));
}

#[tokio::test]
async fn a_terminator_serves_one_session() {
    let t = LocalTerminator::new(Key::new(None), None).unwrap();
    t.hello().await.unwrap();
    assert!(t.hello().await.is_err());
    assert!(t.seal(b"x").await.is_err(), "nothing is sealed before the handshake");
}
