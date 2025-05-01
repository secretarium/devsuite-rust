fn main() {
    println!("This is the main function. Add your application logic here.");
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};
    use tokio::time::sleep;
    use klave_connector::{SCP, Key, Args};
    
    #[test]
    fn test_key_import() {
        let key = Key::new(None);
        let exported_key = key.clone().export_jwk("password").expect("Failed to export key");
        //Write the exported key to a file
        std::fs::write("connectionKeys/key.json", &exported_key).expect("Unable to write file");
        println!("Exported key: {}", exported_key);
        let key2 = match Key::import_jwk(&exported_key, "password") {
            Ok(key) => {
                println!("Key imported successfully.");
                key
            }
            Err(e) => {
                eprintln!("Failed to import key: {}", e);
                return;
            }
        };
        assert_eq!(key, key2);
    }

    #[tokio::test]
    async fn test_connection() {    
        let mut client = SCP::new("wss://on.klave.network", None, None);
    
        match client.connect().await {
            Ok(_) => println!("Connected to Klave successfully."),
            Err(e) => {
                eprintln!("Failed to connect to Klave: {}", e);
                return;
            }
        };
    
        match client.close().await {
            Ok(_) => println!("Connection closed successfully."),
            Err(e) => eprintln!("Failed to close connection: {}", e),
        };
    }

    #[tokio::test]
    async fn test_simple_query() {
        let mut client = SCP::new("wss://on.klave.network", None, None);

        match client.connect().await {
            Ok(_) => println!("Connected to Klave successfully."),
            Err(e) => {
                eprintln!("Failed to connect to Klave: {}", e);
                return;
            }
        };

        // Send a transaction
        let mut tx = client.new_tx("<your-app>", "version", None, None).await;
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

    #[tokio::test]
    async fn test_transaction_hello_world() {
        let mut client = SCP::new("wss://on.klave.network", None, None);

        match client.connect().await {
            Ok(_) => println!("Connected to Klave successfully."),
            Err(e) => {
                eprintln!("Failed to connect to Klave: {}", e);
                return;
            }
        };

        // Send a transaction
        let args = Args::Map(HashMap::from([
            ("key".to_string(), "test-rust-key".to_string()),
            ("value".to_string(), "test-rust-value".to_string()),            
        ]));
        let mut tx = client.new_tx("785e78ea.hello-world.nico.klave.network", "storeValue", None, Some(args)).await;
        tx.on_error(|request_id,  error | {eprintln!("Error occurred. RequestId: {:?}, Error : {:?}", request_id, error);});
        tx.on_result(|request_id, result| {println!("Result received. RequestId: {:?}, Result: {:?}", request_id, result);});
        tx.on_acknowledged(|request_id, _| {println!("onAcknowledged received. RequestId: {:?}", request_id);});
        tx.on_committed(|request_id, _| {println!("onCommitted received. RequestId: {:?}", request_id);});
        tx.on_executed(|request_id, _| {println!("onExecuted received. RequestId: {:?}", request_id);});
        let _ = tx.send().await;

        match client.close().await {
            Ok(_) => println!("Connection closed successfully."),
            Err(e) => eprintln!("Failed to close connection: {}", e),
        };
    }

    #[tokio::test]
    async fn test_query_hello_world() {
        let mut client = SCP::new("wss://on.klave.network", None, None);
        match client.connect().await {
            Ok(_) => println!("Connected to Klave successfully."),
            Err(e) => {
                eprintln!("Failed to connect to Klave: {}", e);
                return;
            }
        };

        let app = "785e78ea.hello-world.nico.klave.network";
        let command = "fetchValue";        
        let args = Args::Map(HashMap::from([
            ("key".to_string(), "test-rust-key".to_string())            
        ]));
        let tx = client.new_tx(app, command, None, Some(args)).await;

        let _ = tx.send().await;
        match client.close().await {
            Ok(_) => println!("Connection closed successfully."),
            Err(e) => eprintln!("Failed to close connection: {}", e),
        };
    }

    #[tokio::test]
    async fn test_connection_advanced() {
        let mut client = SCP::new("wss://on.klave.network", None, None);

        // Connect to the WebSocket (this will now perform the default handshake)
        match client.connect().await {
            Ok(_) => println!("WebSocket client connected successfully."),
            Err(e) => {
                eprintln!("Failed to connect WebSocket client: {}", e);            
            }
        };

        // Simulate sending messages after some delay
        sleep(Duration::from_secs(1)).await;
        let app = "785e78ea.hello-world.nico.klave.network";
        let command = "fetchValue";        
        let args = Args::Map(HashMap::from([
            ("key".to_string(), "test-rust-key".to_string())            
        ]));

        println!("Sending a transaction with custom callbacks...");
        let mut tx = client.new_tx(app, command, None, Some(args.clone())).await;
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

        sleep(Duration::from_secs(1)).await;

        println!("Sending a transaction with default callbacks...");
        let tx_default = client.new_tx(app, command, None, Some(args.clone())).await;
        let _ = tx_default.send().await;

        sleep(Duration::from_secs(1)).await;

        println!("Sending periodic calls...");
        let tx3_periodic = client.new_periodic_tx(app, command, None, Some(args.clone()), 5).await;
        let _ = tx3_periodic.send().await;

        sleep(Duration::from_secs(20)).await;

        // Close the connection
        match client.close().await {
            Ok(_) => println!("WebSocket client closed successfully."),
            Err(e) => eprintln!("Failed to close WebSocket client: {}", e),
        };

        println!("WebSocket client finished in main app.");                
    }

}
