# Rust Connector for Klave

## Overview

This crate provides the necessary tools for connecting/interacting with Klave applications. It enables seamless communication with Klave apps and supports various features for secure and efficient integration.

It covers:

- Establishing secure WebSocket connections
- Performing cryptographic handshake operations
- Sending and receiving messages with callbacks
- Managing periodic transactions
- And more...

## Getting Started

### Bootstrap

You can start from scratch with `cargo add klave-connector` or  
Fork the Rust Connector [repository](https://github.com/secretarium/devsuite-rust/tree/main/libs/connector).

### Develop

Develop your app in Rust using the Klave Connector. Ensure the Rust packages you are using are compatible with `tokio` and asynchronous programming.

### Build

Build your project with:

```bash
cargo build --release
```

### Deploy

Deploy your app on [Klave](https://klave.com) or integrate it into your existing Rust application.

## Usage

### Example: Connecting to Klave

```rust
use klave_connector::SCP;
use klave_connector::Key;

#[tokio::main]
async fn main() {    
    let mut client = SCP::new("<wss://your-endpoint>", None, None);

    match client.connect().await {
        Ok(_) => println!("Connected to Klave successfully."),
        Err(e) => {
            eprintln!("Failed to connect to Klave: {}", e);
            return;
        }
    };

    // Send a transaction
    let mut tx = client.new_tx("<your-app>", "<your-route>", None, None).await;
    tx.on_error(|request_id, error_message| {
        eprintln!("Transaction error occurred. RequestId: {:?}, Error: {:?}", request_id, error_message);
    });
    tx.on_result(|request_id, result| {
        eprintln!("Result received. RequestId: {:?}, Result: {:?}", request_id, result);
    });
    let _ = tx.send().await;

    match client.close().await {
        Ok(_) => println!("Connection closed successfully."),
        Err(e) => eprintln!("Failed to close connection: {}", e),
    };
}
```

## Features

- **Secure WebSocket Communication**: Establish encrypted WebSocket connections with Klave apps.
- **Transaction Management**: Send transactions with support for callbacks and periodic execution.
- **Cluster Negotiation**: Handle cluster negotiations and gateway handshakes seamlessly.
- **Cryptographic Operations**: Perform encryption and decryption using hardware-accelerated cryptography.
- **Customizable Callbacks**: Define custom handlers for transaction results, errors, and states.

## Contributing

Contributions to this crate are welcome! If you encounter any bugs or have suggestions for improvements, please open an issue on the GitHub [repository](https://github.com/secretarium/devsuite-rust/tree/main/libs/connector).

## License

This crate is licensed under the terms detailed in [LICENSE.md](https://github.com/secretarium/devsuite-rust/tree/main/libs/connector/LICENSE.md).