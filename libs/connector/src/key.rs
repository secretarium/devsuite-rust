use std::fmt::Display;
use aes_gcm::{aead::Aead, Aes256Gcm, Key as AesGcmKey, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine};
use elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use serde_json::Value;
use crate::utils::{get_sha256_bytes, get_random_bytes};


#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct AesKeyGenParams {
    name: String,
    length: u32,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
pub struct CryptoKey {
    crv: String,
    ext: bool,
    key_ops: Vec<String>,
    kty: String,
    x: String,
    y: String,
    d: Option<String>
}

impl Display for CryptoKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CryptoKey {{ crv: {}, ext: {}, key_ops: {:?}, kty: {}, x: {}, y: {}, d: {:?} }}", 
            self.crv, self.ext, self.key_ops, self.kty, self.x, self.y, self.d)
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
pub struct CryptoKeyPair {
    public_key: CryptoKey,
    private_key: CryptoKey,
}

impl Display for CryptoKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CryptoKeyPair {{ public_key: {}, private_key: {} }}", 
            self.public_key, self.private_key)  
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct EncryptedKeyPairV0 {
    version: String,
    name: String,
    iv: String,
    salt: String,
    encrypted_keys: String,
    encrypted_key_pair: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct EncryptedKeyPairV2 {
    version: u64,
    name: String,
    iv: String,
    salt: String,
    data: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub enum EncryptedKeyPair {
    V0(EncryptedKeyPairV0),
    V2(EncryptedKeyPairV2),
}

pub enum CryptoKeyType {
    Public,
    Private,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
pub struct Key {
    crypto_key_pair: CryptoKeyPair,
}

impl Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key {{ crypto_key_pair: {} }}", self.crypto_key_pair)
    }
}

impl Key {
    pub fn new(secret_key_input: Option<SecretKey>) -> Key {        
        let secret_key = match secret_key_input {
            Some(secret_key) => secret_key,
            None => {
                // Generate a new secret key if none is provided
                SecretKey::random(&mut rand::thread_rng())
            }
        };
        Key {
            crypto_key_pair: CryptoKeyPair {
                public_key: Key::key_pair_to_crypto_key(&secret_key, CryptoKeyType::Public).unwrap(),
                private_key: Key::key_pair_to_crypto_key(&secret_key, CryptoKeyType::Private).unwrap(),
            }
        }
    }

    pub fn get_raw_public_key(&self) -> Vec<u8> {
        let public_key = &self.crypto_key_pair.public_key;
        let x = general_purpose::URL_SAFE_NO_PAD.decode(public_key.x.clone()).expect("Failed to decode x");
        let y = general_purpose::URL_SAFE_NO_PAD.decode(public_key.y.clone()).expect("Failed to decode y");
        let mut raw_public_key = vec![0; 64];
        raw_public_key[0..32].copy_from_slice(&x);
        raw_public_key[32..64].copy_from_slice(&y);
        raw_public_key
    }

    pub fn get_raw_private_key(&self) -> Vec<u8> {
        let private_key = &self.crypto_key_pair.private_key;
        match &private_key.d {
            Some(d) => {
                let d = general_purpose::URL_SAFE_NO_PAD.decode(d).expect("Failed to decode d");
                let mut raw_private_key = vec![0; 32];
                raw_private_key[0..32].copy_from_slice(&d);
                return raw_private_key;
            }
            None => {
                return vec![];
            }
        }
    }

    pub fn key_pair_to_crypto_key(secret_key: &SecretKey, crypto_key_type: CryptoKeyType) -> Result<CryptoKey, Box<dyn std::error::Error>> {
        // Derive the public key from the secret key
        let public_key = secret_key.public_key();
    
        // Get the encoded point (x, y coordinates)
        let encoded_point = public_key.to_encoded_point(false); // Uncompressed point
    
        // Extract x and y as byte slices
        let x = match encoded_point.x() {
            Some(x) => x,
            None => return Err("Failed to extract x coordinate".into()),
        };
        let y = match encoded_point.y() {
            Some(y) => y,
            None => return Err("Failed to extract y coordinate".into()),
        };
    
        // Convert x and y to Base64 strings
        let x_b64 = general_purpose::URL_SAFE_NO_PAD.encode(x);
        let y_b64 = general_purpose::URL_SAFE_NO_PAD.encode(y);
    
        // Create the CryptoKey
        Ok(CryptoKey {
            crv: "P-256".to_string(),
            ext: true,
            key_ops: vec!["sign".to_string(), "verify".to_string()],
            kty: "EC".to_string(),
            x: x_b64,
            y: y_b64,
            d: match crypto_key_type {
                CryptoKeyType::Public => None,
                CryptoKeyType::Private => Some(general_purpose::URL_SAFE_NO_PAD.encode(secret_key.to_bytes())),
            },
        })
    }

    pub fn import_jwk_from_file(        
        file_path: &str,
        password: &str
    ) -> Result<Key, Box<dyn std::error::Error>> {
        // Read the file content
        let file_content = match std::fs::read_to_string(file_path) {
            Ok(content) => content,
            Err(_) => return Err("Failed to read file".into()),
        };
        // Parse the JSON content
        let Ok(v) = serde_json::from_str::<Value>(&file_content.clone()) else {
            return Err("Failed to parse JSON".into());
        };            

        //Check if the file did contain iv, salt and data
        let iv = v.get("iv").and_then(|v| v.as_str()).unwrap_or("");
        let salt = v.get("salt").and_then(|v| v.as_str()).unwrap_or("");
        match v.get("data") {
            Some(data) => {
                println!("File contains a v2 key pair");
                let data = data.as_str().unwrap_or("");
                let encrypted_key_pair = EncryptedKeyPair::V2(EncryptedKeyPairV2 {
                    version: 2,
                    name: v.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    iv: iv.to_string(),
                    salt: salt.to_string(),
                    data: data.to_string(),
                });
                return Ok(match Key::import_key_pair(encrypted_key_pair, password) {
                    Ok(key) => key,
                    Err(_) => {
                        return Err("Failed to import key".into());
                    }
                });
            }
            None => {
                println!("File contains a v0 key pair");
                let encrypted_key_pair = EncryptedKeyPair::V0(EncryptedKeyPairV0 {
                    version: 0.to_string(),
                    name: v.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    iv: iv.to_string(),
                    salt: salt.to_string(),
                    encrypted_keys: v.get("encrypted_keys").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    encrypted_key_pair: v.get("encrypted_key_pair").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                });
                return Ok(match Key::import_key_pair(encrypted_key_pair, password) {
                    Ok(key) => key,
                    Err(_) => {
                        return Err("Failed to import key".into());
                    }
                });                
            }
        };
    }

    pub fn import_jwk(        
        encrypted_key_pair_v2: &str,
        password: &str
    ) -> Result<Key, Box<dyn std::error::Error>> {

        // Parse the JSON content
        let Ok(encrypted_key_pair) = serde_json::from_str::<EncryptedKeyPairV2>(&encrypted_key_pair_v2) else {
            return Err("Failed to parse JSON".into());
        };            

        return Ok(match Key::import_key_pair(EncryptedKeyPair::V2(encrypted_key_pair), password) {
            Ok(key) => key,
            Err(_) => {
                return Err("Failed to import key".into());
            }
        });
    }

    pub fn export_jwk(self, password: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Convert the key to JSON
        let json = serde_json::to_string(&self.crypto_key_pair)?;
        // Encrypt the JSON data using AES-GCM
        let iv = get_random_bytes(12);
        let salt = get_random_bytes(16);
        let weak_pwd = password.to_string().into_bytes();
        let mut combined = salt.clone();
        combined.extend_from_slice(&weak_pwd);
        let strong_pwd = get_sha256_bytes(&combined);
        // Create an AES key using the strong password imported as raw
        let aes_key = AesGcmKey::<Aes256Gcm>::from_slice(&strong_pwd);
        // Encrypt the data using the AES key
        let cipher = Aes256Gcm::new(aes_key);            
        let nonce = Nonce::from_slice(&iv);
        let encrypted_data = match cipher.encrypt(nonce, json.as_bytes()) {
            Ok(encrypted_data) => encrypted_data,
            Err(_) => return Err("Failed to encrypt data".into())
        };
        
        // Encode the encrypted data and IV as Base64
        let encrypted_key_pair_v2 = EncryptedKeyPairV2{
            iv: general_purpose::URL_SAFE.encode(iv),
            salt: general_purpose::URL_SAFE.encode(salt),
            data: general_purpose::URL_SAFE.encode(encrypted_data),
            name: self.crypto_key_pair.public_key.kty,
            version: 2,
        };

        // Create a JSON object with the encrypted data and IV
        let json_output = serde_json::to_string::<EncryptedKeyPairV2>(&encrypted_key_pair_v2)?;        
        Ok(json_output)
    }

    pub fn import_key_pair(
        input_encrypted_key_pair: EncryptedKeyPair,
        password: &str
    ) -> Result<Key, Box<dyn std::error::Error>> {

        let decrypt_v2 = |iv: &str, salt: &str, data: &str| {
            let iv = match general_purpose::URL_SAFE.decode(iv) {
                Ok(iv) => iv,
                Err(_) => return Err(Box::<dyn std::error::Error>::from("Failed to decode IV"))
            };                
            let salt = match general_purpose::URL_SAFE.decode(salt) {
                Ok(salt) => salt,
                Err(_) => return Err("Failed to decode salt".into())
            };
            let encrypted_data = match general_purpose::URL_SAFE.decode(data) {
                Ok(encrypted_data) => encrypted_data,
                Err(_) => return Err("Failed to decode encrypted data".into())
            };
            let weak_pwd = password.to_string().into_bytes();
            let mut combined = salt.clone();
            combined.extend_from_slice(&weak_pwd);
            let strong_pwd = get_sha256_bytes(&combined);
            // Create an AES key using the strong password imported as raw
            let aes_key = AesGcmKey::<Aes256Gcm>::from_slice(&strong_pwd);
            // Decrypt the data using the AES key
            let cipher = Aes256Gcm::new(aes_key);            
            let nonce = Nonce::from_slice(&iv);
            let decrypted = match cipher.decrypt(nonce, encrypted_data.as_slice()) {
                Ok(decrypted) => decrypted,
                Err(_) => return Err("Failed to decrypt data".into())
            };
            //Convert this decrypted data to a UTF8 string
            let decrypted_str = match String::from_utf8(decrypted){
                Ok(decrypted_str) => decrypted_str,
                Err(_) => return Err("Failed to convert decrypted data to UTF-8".into())
            };
            // Parse the decrypted string as JSON
            let decrypted_json: Value = match serde_json::from_str(&decrypted_str) {
                Ok(decrypted_json) => decrypted_json,
                Err(_) => return Err("Failed to parse decrypted data as JSON".into())
            };
            // Extract the public and private keys from the decrypted JSON
            let public_key = match serde_json::from_value::<CryptoKey>(match decrypted_json.get("public_key") {
                Some(public_key) => public_key.clone(),
                None => return Err("Failed to get public key".into())
            }) {
                Ok(crypto_key) => crypto_key,
                Err(_) => return Err("Failed to parse crypto key".into())
            };
            let private_key = match serde_json::from_value::<CryptoKey>(match decrypted_json.get("private_key") {
                Some(private_key) => private_key.clone(),
                None => return Err("Failed to get private key".into())
            }) {
                Ok(crypto_key) => crypto_key,
                Err(_) => return Err("Failed to parse crypto key".into())
            };
            Ok((public_key, private_key))
        };

        match input_encrypted_key_pair {
            EncryptedKeyPair::V0(v0) => {                
                // Handle V0 key pair       
                let data: String;
                if v0.encrypted_keys.is_empty() {
                    data = v0.encrypted_key_pair;
                } else {
                    data = v0.encrypted_keys;
                }    
                let (public_key, private_key) = match decrypt_v2(
                    &v0.iv, 
                    &v0.salt, 
                    &data
                ) {
                    Ok((public_key, private_key)) => (public_key, private_key),
                    Err(_) => return Err("Failed to decrypt V0 key pair".into())
                };
                // Convert the public and private keys to JWK format
                Ok(Key {
                    crypto_key_pair: CryptoKeyPair {
                        public_key: public_key,
                        private_key: private_key,
                    }
                })
            }
            EncryptedKeyPair::V2(v2) => {
                // Handle V2 key pair
                let (public_key, private_key) = match decrypt_v2(&v2.iv, &v2.salt, &v2.data) {
                    Ok((public_key, private_key)) => (public_key, private_key),
                    Err(_) => return Err("Failed to decrypt V2 key pair".into())
                };
                // Convert the public and private keys to JWK format          
                Ok(Key {
                    crypto_key_pair: CryptoKeyPair {
                        public_key: public_key,
                        private_key: private_key,
                    }
                })
            }
        }
    }
}
