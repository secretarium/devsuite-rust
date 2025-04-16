use aes_gcm::{aead::Aead, Aes256Gcm, Key as AesGcmKey, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine};
use elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use serde_json::Value;

use crate::utils::get_sha256_bytes;


#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct AesKeyGenParams {
    name: String,
    length: u32,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct CryptoKey {
    crv: String,
    ext: bool,
    key_ops: Vec<String>,
    kty: String,
    x: String,
    y: String,
    d: Option<String>
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct CryptoKeyPair {
    public_key: CryptoKey,
    private_key: CryptoKey,
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

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct Key {
    crypto_key_pair: CryptoKeyPair,
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
                public_key: Key::key_pair_to_crypto_key(&secret_key, CryptoKeyType::Public),
                private_key: Key::key_pair_to_crypto_key(&secret_key, CryptoKeyType::Private),
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
                println!("Private key is not available");
                return vec![];
            }
        }
    }

    pub fn key_pair_to_crypto_key(secret_key: &SecretKey, crypto_key_type: CryptoKeyType) -> CryptoKey {
        // Derive the public key from the secret key
        let public_key = secret_key.public_key();
    
        // Get the encoded point (x, y coordinates)
        let encoded_point = public_key.to_encoded_point(false); // Uncompressed point
    
        // Extract x and y as byte slices
        let x = encoded_point.x().expect("Failed to extract x coordinate");
        let y = encoded_point.y().expect("Failed to extract y coordinate");
    
        // Convert x and y to Base64 strings
        let x_b64 = general_purpose::URL_SAFE_NO_PAD.encode(x);
        let y_b64 = general_purpose::URL_SAFE_NO_PAD.encode(y);
    
        // Create the CryptoKey
        CryptoKey {
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
        }
    }

    pub fn import_jwk(        
        file_path: &str,
        password: &str
    ) -> Result<Key, Box<dyn std::error::Error>> {
        // Read the file content
        let file_content = std::fs::read_to_string(file_path).expect("Unable to read file");
        // Parse the JSON content
        let Ok(v) = serde_json::from_str::<Value>(&file_content.clone()) else {
            println!("ERROR: failed to parse '{}' as json", file_content);
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
                return Ok(Key::import_key_pair(encrypted_key_pair, password));
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
                return Ok(Key::import_key_pair(encrypted_key_pair, password));                
            }
        };
    }

    pub fn import_key_pair(
        input_encrypted_key_pair: EncryptedKeyPair,
        password: &str
    ) -> Key {

        let decrypt_v2 = |iv: &str, salt: &str, data: &str| {
            let iv = general_purpose::URL_SAFE.decode(iv).expect("Failed to decode salt");                
            let salt = general_purpose::URL_SAFE.decode(salt).expect("Failed to decode salt");                
            let encrypted_data = general_purpose::URL_SAFE.decode(data).expect("Failed to decode data");
            let weak_pwd = password.to_string().into_bytes();
            let mut combined = salt.clone();
            combined.extend_from_slice(&weak_pwd);
            let strong_pwd = get_sha256_bytes(&combined);
            // Create an AES key using the strong password imported as raw
            let aes_key = AesGcmKey::<Aes256Gcm>::from_slice(&strong_pwd);
            // Decrypt the data using the AES key
            let cipher = Aes256Gcm::new(aes_key);            
            let nonce = Nonce::from_slice(&iv);
            let decrypted = cipher.decrypt(nonce, encrypted_data.as_slice()).expect("decryption failure!");
            //Convert this decrypted data to a UTF8 string
            let decrypted_str = String::from_utf8(decrypted).expect("Failed to convert decrypted data to UTF-8");
            // Parse the decrypted string as JSON
            let decrypted_json: Value = serde_json::from_str(&decrypted_str).expect("Failed to parse decrypted JSON");
            // Extract the public and private keys from the decrypted JSON
            let public_key = serde_json::from_value::<CryptoKey>(decrypted_json.get("publicKey").expect("Failed to get public key").clone()).unwrap();
            let private_key = serde_json::from_value::<CryptoKey>(decrypted_json.get("privateKey").expect("Failed to get private key").clone()).unwrap();
            (public_key, private_key)
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
                let (public_key, private_key) = decrypt_v2(
                    &v0.iv, 
                    &v0.salt, 
                    &data
                );
                // Convert the public and private keys to JWK format
                Key {
                    crypto_key_pair: CryptoKeyPair {
                        public_key: public_key,
                        private_key: private_key,
                    }
                }
            }
            EncryptedKeyPair::V2(v2) => {
                // Handle V2 key pair
                let (public_key, private_key) = decrypt_v2(&v2.iv, &v2.salt, &v2.data);
                // Convert the public and private keys to JWK format          
                Key {
                    crypto_key_pair: CryptoKeyPair {
                        public_key: public_key,
                        private_key: private_key,
                    }
                }
            }
        }
    }
}
