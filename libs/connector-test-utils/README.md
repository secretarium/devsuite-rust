# klave-connector-test-utils

Test utilities for [klave-connector](../connector) and for crates built on its SCP channel. Add it as a
dev-dependency only; it is not meant for production use.

## `mock_node`

An in-process mock node on a free local port. It plays the server side of the SCP handshake, then hands every
decrypted message of a connection to a handler and sends back what the handler returns:

```rust
use klave_connector::{channel, Key};
use klave_connector_test_utils::mock_node::{self, Out};

let node = mock_node::start(|| Box::new(|message: Vec<u8>| vec![Out::Message(message)])).await; // echo
let (sender, mut receiver) = channel::open(&node.url, &Key::new(None), Some(&node.trusted_key), None).await?;
```

- `Out::Message` is encrypted and framed like any SCP message; `Out::RawFrame` is sent exactly as given, to test
  malformed input; `Out::Close` closes the connection.
- `node.trusted_key` is the key the node proves it holds; `mock_node::other_key()` is one it never presents.
- A handler is built per connection, so it can keep per-connection state (for example a mock application).
