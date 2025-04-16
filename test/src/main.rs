use std::{collections::HashMap, time::Duration};
use tokio::time::sleep;
use klave_connector::{SCP, Key};

pub const KLAVE_TEST: &str = "<Use your own URL>";
// #[tokio::main]
// async fn main() {    
//     let mut client = SCP::new("wss://klave-dev.secretarium.org/", None, None);

//     match client.connect().await {
//         Ok(_) => println!("Connected to Klave successfully."),
//         Err(e) => {
//             eprintln!("Failed to connect to Klave: {}", e);
//             return;
//         }
//     };

//     // Send a transaction
//     let mut tx = client.new_tx("wasm-manager", "version", None, None).await;
//     tx.on_error(|request_id, error_message| {
//         eprintln!("Transaction error occurred. RequestId: {:?}, Error: {:?}", request_id, error_message);
//     });
//     tx.on_result(|request_id, result| {
//         eprintln!("Result received. RequestId: {:?}, Result: {:?}", request_id, result);
//     });
//     let _ = tx.send().await;

//     match client.close().await {
//         Ok(_) => println!("Connection closed successfully."),
//         Err(e) => eprintln!("Failed to close connection: {}", e),
//     };
// }

#[tokio::main]
async fn main() {   
    //Read file from connectionKeys folder
    let key = match Key::import_jwk("<Use your own Key>", "klave") {
        Ok(key) => {
            println!("Key imported successfully.");
            key
        }
        Err(e) => {
            eprintln!("Failed to import key: {}", e);
            return;
        }
    };
    
    let mut client = SCP::new(KLAVE_TEST, Some(&key), None);

    // Connect to the WebSocket (this will now perform the default handshake)
    match client.connect().await {
        Ok(_) => println!("WebSocket client connected successfully."),
        Err(e) => {
            eprintln!("Failed to connect WebSocket client: {}", e);            
        }
    };

    // Simulate sending messages after some delay
    sleep(Duration::from_secs(2)).await;

    println!("Sending a transaction with custom callbacks...");
    let mut tx = client.new_tx("wasm-manager", "version", None, None).await;
    tx.on_error(|request_id, error_message| {
        eprintln!("Transaction error occurred. RequestId: {:?}, Error: {:?}", request_id, error_message);
    });
    tx.on_executed(|request_id, message| {
        eprintln!("Transaction executed. RequestId: {:?}, Message: {:?}", request_id, message);
    });
    tx.on_result(|request_id, result| {
        eprintln!("LMB Result 1: RequestId: {:?}, Result: {:?}", request_id, result);
    });
    tx.on_result(|request_id, result| {
        eprintln!("LMB Result 2: RequestId: {:?}, Result: {:?}", request_id, result);
    });
    let _ = tx.send().await;

    sleep(Duration::from_secs(5)).await;

    println!("Sending a transaction with default callbacks...");
    let tx_default = client.new_tx("wasm-manager", "version", None, None).await;
    let _ = tx_default.send().await;

    sleep(Duration::from_secs(5)).await;

    let wasm_bytes_b64 = std::fs::read_to_string("<Use your own File>").expect("Unable to read file");
    let tx_chunk = client.new_tx("wasm-manager", "deploy_instance", None, Some(HashMap::from([
        ("wasm_bytes_b64".to_string(), wasm_bytes_b64.clone()),
        ("app_id".to_string(), "<my-app>-rust-connector".to_string()),
        ("fqdn".to_string(), "main.<my-app>.klave.network".to_string()),
    ]))).await;
    match tx_chunk.send().await {
        Ok(_) => println!("Transaction sent successfully."),
        Err(e) => eprintln!("Failed to send transaction: {}", e),
    };

    sleep(Duration::from_secs(5)).await;

    println!("Sending periodic calls...");
    let tx3_periodic = client.new_periodic_tx("wasm-manager", "version", None, None, 5).await;
    let _ = tx3_periodic.send().await;

    // Keep the main task alive until you decide to close the connection
    println!("Press Enter to close the WebSocket connection from main app.");
    let mut buffer = String::new();
    match std::io::stdin().read_line(&mut buffer).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync + 'static>) {
        Ok(_) => println!("Received input: {}", buffer),
        Err(e) => eprintln!("Failed to read input: {}", e),
    };

    // Close the connection
    match client.close().await {
        Ok(_) => println!("WebSocket client closed successfully."),
        Err(e) => eprintln!("Failed to close WebSocket client: {}", e),
    };

    println!("WebSocket client finished in main app.");        
}