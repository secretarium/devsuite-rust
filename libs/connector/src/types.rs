use aes_gcm::Aes128Gcm;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct SCPEndpoint {
    pub url: String,
    pub known_trusted_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SCPOptions {
    pub gateway_timeout: u64, // Assuming seconds
    pub connect_timeout: u64, // Assuming seconds
}

impl Default for SCPOptions {
    fn default() -> Self {
        Self {
            gateway_timeout: 0,
            connect_timeout: 5,
        }
    }
}

#[derive(Clone)]
pub struct SCPSession {
    pub crypto_key: Aes128Gcm, 
    pub iv: Vec<u8>,
}

pub struct SCPProto {
    pub proto_id: String,
    pub proto_version: String,
    pub server_type: String,
    pub server_version: String,
    pub server_tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Args {
    Map(HashMap<String, String>),
    Str(String),
}

pub type OptionalArgs = Option<Args>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SCPMessage {
    pub dcapp: String,
    pub function: String,    
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub args: String,
}
