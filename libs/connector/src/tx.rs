use std::sync::Arc;
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio::time::Duration;

use crate::scp::SCP;
use crate::types::{Args, OptionalArgs, SCPMessage};

type Callback = Arc<dyn Fn(Option<&str>, Option<&str>) + Send + Sync>;

#[derive(Debug, Clone)]
pub struct PeriodicMessage {
    pub interval: Duration,    
    pub scp_message: SCPMessage,
}

pub struct TransactionNotificationHandlers {
    pub on_error: Vec<Callback>,
    pub on_result: Vec<Callback>,
    pub on_acknowledged: Vec<Callback>,
    pub on_committed: Vec<Callback>,
    pub on_executed: Vec<Callback>,
    pub promise_message: Vec<Callback>,
    pub periodic_message: Option<PeriodicMessage>,
}

impl Clone for TransactionNotificationHandlers {
    fn clone(&self) -> Self {
        Self { 
            on_error: self.on_error.clone(), 
            on_result: self.on_result.clone(), 
            on_acknowledged: self.on_acknowledged.clone(), 
            on_committed: self.on_committed.clone(), 
            on_executed: self.on_executed.clone(), 
            promise_message: self.promise_message.clone(),
            periodic_message: None,
        }
    }
}

impl std::fmt::Debug for TransactionNotificationHandlers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionNotificationHandlers")
            .field("on_error", &format_args!("<callbacks>"))
            .field("on_result", &format_args!("<callbacks>"))
            .field("on_acknowledged", &format_args!("<callbacks>"))
            .field("on_committed", &format_args!("<callbacks>"))
            .field("on_executed", &format_args!("<callbacks>"))
            .field("periodic_message", &self.periodic_message)
            .finish()
    }
}

impl TransactionNotificationHandlers {
    pub fn new() -> Self {
        Self {
            on_error: Vec::new(),
            on_result: Vec::new(),
            on_acknowledged: Vec::new(),
            on_committed: Vec::new(),
            on_executed: Vec::new(),
            promise_message: Vec::new(),
            periodic_message: None,
        }
    }
}

impl Default for TransactionNotificationHandlers {
    fn default() -> Self {
        Self {
            on_error: vec![Arc::new(|error_code, error_message| {
                println!("Default OnError. Code: {:?}, Message: {:?}", error_code, error_message);})],            
            on_result: vec![Arc::new(|code, message| {
                println!("Default OnResult. Code: {:?}, Message: {:?}", code, message);})],            
            on_acknowledged: Vec::new(),
            on_committed: Vec::new(),
            on_executed: Vec::new(),
            promise_message: Vec::new(),
            periodic_message: None,
        }
    }
}


pub struct Tx<'a> {
    ws_client: &'a mut SCP,
    app: String,
    command: String,
    request_id: String,
    args: OptionalArgs,
    cbs: TransactionNotificationHandlers,
    response_promise: Option<tokio::sync::oneshot::Receiver<String>>,
}

impl<'a> Tx<'a> {
    pub async fn new(
        ws_client: &'a mut SCP,
        app: String,
        command: String,
        request_id: String,
        args: OptionalArgs,
        periodic_interval: Option<Duration>,
    ) -> Self {
        let (tx, rx) = oneshot::channel();
        let tx = Arc::new(AsyncMutex::new(Some(tx)));
        let mut cbs = TransactionNotificationHandlers::new();

        let tx_clone = Arc::clone(&tx);
        cbs.promise_message.push(Arc::new(move |_, message| {
            if let Some(message) = message {
                let message_cloned = message.to_string(); // Clone the result to ensure it has a 'static lifetime
                let tx_clone = Arc::clone(&tx_clone);
                tokio::spawn(async move {
                    if let Some(tx) = tx_clone.lock().await.take() {
                        let _ = tx.send(message_cloned);
                    }
                });
            }
        }));
        
        if periodic_interval.is_some() {
            cbs.periodic_message = Some(PeriodicMessage {
                interval : periodic_interval.expect("Periodic interval should be set"),
                scp_message: SCPMessage {
                    dcapp: app.clone(),
                    function: command.clone(),
                    request_id: request_id.clone(),
                    args: match args.clone() {
                        Some(Args::Map(map)) => serde_json::to_string(&map).unwrap(),
                        Some(Args::Str(s)) => s,
                        None => String::from("{}"),
                    },
                }
            });
        }

        Self {
            ws_client,
            app,
            command,
            request_id,
            args,
            cbs,
            response_promise: Some(rx),
        }
    }

    fn wrapper<F>(&self, callback: F) -> Callback
    where
        F: Fn(Option<&str>, Option<&str>) + Send + Sync + 'static,
    {
        Arc::new(move |d, r| callback(d, r))
    }

    pub fn on_error<F>(&mut self, callback: F) -> &mut Self
    where
        F: Fn(Option<&str>, Option<&str>) + Send + Sync + 'static,
    {
        self.cbs.on_error.push(self.wrapper(callback));
        self
    }

    pub fn on_result<F>(&mut self, callback: F) -> &mut Self
    where
        F: Fn(Option<&str>, Option<&str>) + Send + Sync + 'static,
    {
        self.cbs.on_result.push(self.wrapper(callback));
        self
    }

    pub fn on_acknowledged<F>(&mut self, callback: F) -> &mut Self
    where
        F: Fn(Option<&str>, Option<&str>) + Send + Sync + 'static,
    {
        self.cbs.on_acknowledged.push(self.wrapper(callback));
        self
    }

    pub fn on_committed<F>(&mut self, callback: F) -> &mut Self
    where
        F: Fn(Option<&str>, Option<&str>) + Send + Sync + 'static,
    {
        self.cbs.on_committed.push(self.wrapper(callback));
        self
    }

    pub fn on_executed<F>(&mut self, callback: F) -> &mut Self
    where
        F: Fn(Option<&str>, Option<&str>) + Send + Sync + 'static,
    {
        self.cbs.on_executed.push(self.wrapper(callback));
        self
    }
    
    pub async fn send(mut self) -> Result<String, String> {
        self.ws_client.requests.lock().await.insert(self.request_id.clone(), Arc::new(AsyncMutex::new(self.cbs)));
        self.ws_client.send(&self.app, &self.command, &self.request_id, self.args).await;

        // Wait for the response
        if let Some(rx) = self.response_promise.take() {
            match rx.await {
                Ok(response) => Ok(response),
                Err(_) => Err("Failed to receive response".into()),
            }
        } else {
            Err("Response promise not initialized".into())
        }  
    }
}
