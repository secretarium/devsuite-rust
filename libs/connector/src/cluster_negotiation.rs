use std::time::Duration;
use base64::{self, Engine};
use futures::SinkExt;
use rand::rngs::OsRng;
use num_bigint::BigUint;
use thiserror::Error;
use tokio::{net::TcpStream, time::timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::MaybeTlsStream;
use futures_util::stream::{SplitSink, SplitStream, StreamExt};
use tokio_tungstenite::WebSocketStream;
use p256::ecdsa::{signature, Signature, VerifyingKey};
use signature::Verifier;
use aes_gcm::{Aes128Gcm, KeyInit, aead::Error as AesGcmError};
use p256::{EncodedPoint, PublicKey as EcdhPublicKey, SecretKey};
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use crate::key::Key;
use crate::types::SCPSession;
use crate::utils::{get_random_bytes, get_sha256_bytes, pointwise_xor};
use crate::scp::{ConnectionState, encrypt_data, decrypt_data};

#[derive(Debug, Clone)]
pub struct UserKey {
    private_key: p256::SecretKey,
    public_key: p256::PublicKey,
}

impl UserKey {
    pub fn new(private_key_bytes: &[u8]) -> Result<Self, p256::ecdsa::Error> {
        let private_key = match p256::SecretKey::from_bytes(private_key_bytes.into()) {
            Ok(key) => key,
            Err(_) => return Err(p256::ecdsa::Error::default()),
        };
        let public_key = private_key.public_key();
        Ok(Self { private_key, public_key })
    }

    pub async fn get_raw_public_key(&self) -> Vec<u8> {
        self.public_key.to_encoded_point(false).as_bytes()[1..].to_vec()
    }

    pub fn get_signing_key(&self) -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from(self.private_key.clone())
    }

    pub fn get_verifying_key(&self) -> p256::ecdsa::VerifyingKey {
        self.public_key.into()
    }
}

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("Socket not set")]
    SocketNotSet,
    #[error("Endpoint not set")]
    EndpointNotSet,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Timeout")]
    Timeout,
    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("ECDH error")]
    EcdhError,
    #[error("ECDSA error: {0}")]
    Ecdsa(#[from] p256::ecdsa::Error),
    #[error("AES-GCM error: {0}")]
    AesGcm(AesGcmError),
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("ASN.1 decode error: {0}")]
    Asn1Decode(String),
    #[error("Handshake failed: {0}")]
    Generic(String),
}

async fn read_n_bytes<'a>(    
    reader: &mut SplitStream<&mut WebSocketStream<MaybeTlsStream<TcpStream>>>,
    n: usize,
    timeout_duration: Duration,
) -> Result<Vec<u8>, HandshakeError> {    

    let n_with_prefix = n+4; // Add 4 bytes for the prefix
    let mut buffer = vec![0u8; n_with_prefix];
    let mut total_read = 0;

    while total_read < n_with_prefix {
        let read_result = timeout(timeout_duration, reader.next()).await;
        match read_result {
            Ok(Some(Ok(Message::Binary(data)))) => {
                let bytes_to_copy = std::cmp::min(data.len(), n_with_prefix - total_read);
                buffer[total_read..total_read + bytes_to_copy].copy_from_slice(&data[..bytes_to_copy]);
                total_read += bytes_to_copy;
            }
            Ok(Some(Ok(Message::Close(_)))) => {
                return Err(HandshakeError::Generic("Connection closed unexpectedly".into()));
            }
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => {
                return Err(HandshakeError::Generic(format!("WebSocket error: {}", e)));
            }
            Ok(None) => break,
            Err(_) => return Err(HandshakeError::Timeout),
        }
    }

    if total_read < n_with_prefix {
        return Err(HandshakeError::Timeout);
    }

    //Remove the first 4 bytes
    buffer = buffer[4..].to_vec();

    Ok(buffer)
}

async fn send_bytes<'a>(
    writer: &mut SplitSink<&mut WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    data: &[u8],
) -> Result<(), HandshakeError> {

    let mut clear_data = data.to_vec();
    // //Add [0,0,0,1] prefix to the ECDH public key
    clear_data.insert(0, 1);
    clear_data.insert(0, 0);
    clear_data.insert(0, 0);
    clear_data.insert(0, 0);
    
    let message = Message::Binary(clear_data);
    writer.send(message).await.map_err(|e| HandshakeError::Generic(format!("Failed to send message: {}", e)))?;
    Ok(())
}

fn compute_proof_of_work(server_random: &[u8]) -> Vec<u8> {
    // let challenge = server_random; // Assuming `server_random` is the intended challenge
    // let pow = get_sha256_bytes(challenge);
    // pow.into()
    server_random.to_vec() // Placeholder for the actual proof of work logic
}

fn pad_to_size(bytes: &[u8], size: usize) -> Vec<u8> {
    if bytes.len() >= size {
        bytes[bytes.len() - size..].to_vec()
    } else {
        let mut padded = vec![0u8; size - bytes.len()];
        padded.extend_from_slice(bytes);
        padded
    }
}

fn extract_key_and_iv(server_identity_bytes: &[u8], ecdh_secret: &SecretKey) -> Result<(Vec<u8>, Vec<u8>), HandshakeError> {
    if server_identity_bytes.len() < 32 + 64 + 64 {
        return Err(HandshakeError::Generic("Invalid server identity bytes length".into()));
    }
    let pre_master_secret = &server_identity_bytes[0..32];
    let server_ecdh_pub_key_bytes = &server_identity_bytes[32..96];
    
    let server_ecdh_public_key = EcdhPublicKey::from_encoded_point(
        &EncodedPoint::from_bytes(
            [&[0x04], server_ecdh_pub_key_bytes].concat()
        ).unwrap()
    ).unwrap();

    // Compute the shared secret using the SecretKey
    let shared_secret = elliptic_curve::ecdh::diffie_hellman(
        ecdh_secret.to_nonzero_scalar(),
        server_ecdh_public_key.as_affine()
    ).raw_secret_bytes().to_vec();                     
    let sha256_common = get_sha256_bytes(shared_secret.as_slice());
    let symmetric_key: Vec<u8> = pointwise_xor(pre_master_secret, sha256_common.as_slice());
    let iv = &symmetric_key[16..32];
    let key = &symmetric_key[0..16];

    Ok((key.to_vec(), iv.to_vec()))
}

fn der_signature_to_raw(
    user_key: &Key,
    signature: &Signature,
) -> Result<Vec<u8>, HandshakeError> {
    let r_bigint = BigUint::from_bytes_be(&signature.r().to_bytes());
    let s_bigint = BigUint::from_bytes_be(&signature.s().to_bytes());
    let r_bytes = r_bigint.to_bytes_be();
    let s_bytes = s_bigint.to_bytes_be();
    let curve_size = user_key.get_raw_private_key().len();
    if r_bytes.len() > curve_size || s_bytes.len() > curve_size {
        return Err(HandshakeError::Generic("Signature components are too large".into()));
    }
    let r_padded = pad_to_size(&r_bytes, curve_size);
    let s_padded = pad_to_size(&s_bytes, curve_size);
    let signed_nonce = [r_padded, s_padded].concat();
    Ok(signed_nonce)
}

pub async fn process<'a>(
    mut writer: &mut SplitSink<&mut WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    mut reader: &mut SplitStream<&mut WebSocketStream<MaybeTlsStream<TcpStream>>>,
    user_key: &Key,
    known_trusted_key: Option<&str>,
    connect_timeout: Duration,
) -> Result<(SCPSession, ConnectionState), Box<dyn std::error::Error + Send + Sync>> {

    // --- Client Hello ---
    let ecdh_private_key = SecretKey::random(&mut OsRng);    
    let ecdh_pub_key_raw = ecdh_private_key.public_key().to_sec1_bytes()[1..].to_vec();
    if ecdh_pub_key_raw.len() != 64 {
        return Err(HandshakeError::Generic("Invalid ECDH public key length".into()).into());
    }    
    send_bytes(&mut writer, &ecdh_pub_key_raw).await?;

    // --- Server Hello ---
    let server_hello_bytes = read_n_bytes(&mut reader, 32 + 4, connect_timeout).await?;
    let server_random = &server_hello_bytes[0..32];

    // --- Client Proof of Work ---
    let pow = compute_proof_of_work(server_random);
    let trusted_key =  match known_trusted_key {
        Some(key) => {
            let temp = base64::engine::general_purpose::URL_SAFE.decode(key)?;
            if temp.len() != 64 {
                return Err(HandshakeError::Generic("Invalid trusted key length".into()).into());
            }
            temp
        }
        None => {
            //Random key with 64 bytes
            let temp = get_random_bytes(64);
            temp
        }
    };
    let client_proof_of_work = [pow, trusted_key].concat();

    send_bytes(&mut writer, &client_proof_of_work).await?;

    // --- Server Identity ---
    let server_identity_bytes = read_n_bytes(& mut reader, 32 + 64 + 64, connect_timeout).await?;

    let (key, iv) = extract_key_and_iv(&server_identity_bytes, &ecdh_private_key)?;
    let crypto_key = Aes128Gcm::new(key.as_slice().into());
    let session = SCPSession { crypto_key, iv: iv.try_into().map_err(|_| HandshakeError::Generic("Failed to create IV".into()))? };

    // --- Client Proof of Identity ---
    let public_key_raw = user_key.get_raw_public_key();
    let nonce = get_random_bytes(32);    

    let signing_key = UserKey::new(user_key.get_raw_private_key().to_vec().as_slice())
    .map_err(|_| HandshakeError::Generic("Failed to create signing key".into()))?
    .get_signing_key();
    let (signature, _recovery_id) = signing_key.sign_recoverable(&nonce).map_err(HandshakeError::Ecdsa)?;
    let signed_nonce = der_signature_to_raw(user_key, &signature)?;

    let client_proof_of_identity = [nonce, ecdh_pub_key_raw, public_key_raw, signed_nonce].concat();

    let iv_offset = get_random_bytes(16);    
    let encrypted_client_proof_of_identity = {
        encrypt_data(&session, &client_proof_of_identity, &iv_offset)?
    };

    send_bytes(&mut writer, &encrypted_client_proof_of_identity).await?;

    // --- Server Proof of Identity ---
    let server_proof_of_identity_encrypted = read_n_bytes(& mut reader, 64 + 64, connect_timeout).await?;
    let server_proof_of_identity = {
        decrypt_data(&session, &server_proof_of_identity_encrypted)?
    };

    let welcome = b"Hey you! Welcome to Secretarium!";
    let to_verify = [&server_proof_of_identity[0..32], welcome].concat();
    
    let server_signature = Signature::from_slice(&server_proof_of_identity[32..96]).unwrap();
    let server_ecdsa_pub_key_bytes = &server_identity_bytes[96..160];

    let server_ecdsa_verifying_key = VerifyingKey::from_encoded_point(
        &EncodedPoint::from_bytes(
            [&[0x04], server_ecdsa_pub_key_bytes].concat()
        ).unwrap()
    ).unwrap();
    if server_ecdsa_verifying_key.verify(&to_verify, &server_signature).is_err() {
        return Err(HandshakeError::Generic("ECDSA verification failed".into()).into());
    }        

    Ok((session, ConnectionState::OPEN))
}

#[cfg(test)]
mod tests {    
    use hex;
    use super::*;

    #[test]
    fn test_server_identity() {
        let server_identity_hex = "e479053863dd7bd4c440ea62e6d1db0e59eb02c08f81144be704afb87e96561e13448169d219dfe19bdbe1734bd87f7822504de07e9e5930c4b1ccd5d1933f5941d1ad46e485f4d1225ba43adbaab6b8a1cf53862236714fab24a7171bca26eaae5883fc2212a8f11e60a6d661dc1af8bfbca32b403ef74699b2c2d0a76fb07f8e54cada6ab9b57a8faae1fb5ed1c589efe926b2af307a414824ad1af37ff20a";
        let server_identity_bytes = hex::decode(server_identity_hex).unwrap();

        let user_key_hex = "bb6594d95a216082d54777d8e6b5d99985beff9b5e6ba99519c53bbfdb8ac2a1";
        let user_key_bytes = hex::decode(user_key_hex).unwrap();
        let user_key_bytes: [u8; 32] = user_key_bytes
        .try_into()
        .expect("Private key must be 32 bytes");
    
        let user_key = match SecretKey::from_bytes(&user_key_bytes.into()) {
            Ok(secret_key) => Key::new(Some(secret_key)),
            Err(_) => panic!("Failed to create SecretKey from bytes"),
        };

        // Example byte array (must be 32 bytes)
        let ecdh_key_hex = "fa2c3c7a9a52f4104ba8834c8d57afcbeb123aa72833c150bec3af5eb41f22e7";
        let ecdh_key_bytes = hex::decode(ecdh_key_hex).unwrap();
        let ecdh_key_bytes: [u8; 32] = ecdh_key_bytes
        .try_into()
        .expect("Private key must be 32 bytes");

        // Create a SecretKey from the byte array
        let ecdh_key = SecretKey::from_bytes(&ecdh_key_bytes.into())
        .expect("Failed to create SecretKey from bytes");

        let (key, iv) = extract_key_and_iv(&server_identity_bytes, &ecdh_key.clone()).unwrap();
        let key_hex = hex::encode(key.clone());
        let iv_hex = hex::encode(iv.clone());

        println!("Key: {:?}", key_hex);
        println!("IV: {:?}", iv_hex);

        let expected_key = "1c510cda986452d4ebb32f702b08589b";
        let expected_iv = "c71953dea4339dd0e796188127f0baeb";

        assert_eq!(key_hex, expected_key);
        assert_eq!(iv_hex, expected_iv);

        let crypto_key = Aes128Gcm::new(key.as_slice().into());
        let session = SCPSession { crypto_key, iv: match iv.try_into() {
            Ok(iv) => iv,
            Err(_) => panic!("Failed to create IV from bytes"),
        } };
    
        // --- Client Proof of Identity ---
        let _public_key_raw = user_key.get_raw_public_key();
        let nonce_hex = "5c513f8ab90094b01cda913d858ca71e14ee81ba484e9d6130abd96c21c5e8fa";
        let nonce_bytes = hex::decode(nonce_hex).unwrap();

        let signing_key = match UserKey::new(user_key.get_raw_private_key().to_vec().as_slice()) {
            Ok(user_key) => user_key.get_signing_key(),
            Err(_) => panic!("Failed to create UserKey from bytes"),
        };        
        let (_signature, _recovery_id) = match signing_key.sign_recoverable(&nonce_bytes) {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to sign nonce"),
        };

        let signature_hex = "3046022100eee8e43c035ef81badc6c02107cc13a29eac119b05fb645de8636e4fea7b240b022100ab83b4a4a35f293c6898da1f9c8d2c79eedd1b395d20eec4779949d5cdf22f7e";
        let signature_bytes = hex::decode(signature_hex).unwrap();
        let signature = match Signature::from_der(signature_bytes.as_slice()) {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to create Signature from bytes"),
        };

        let signed_nonce = match der_signature_to_raw(&user_key, &signature) {
            Ok(signed_nonce) => signed_nonce,
            Err(e) => panic!("Failed to sign nonce: {:?}", e),
        };
        
        let signed_nonce_hex = hex::encode(&signed_nonce);

        println!("Nonce: {:?}", nonce_bytes);
        println!("Signed Nonce: {:?}", signed_nonce);
        
        assert_eq!(signed_nonce_hex, "eee8e43c035ef81badc6c02107cc13a29eac119b05fb645de8636e4fea7b240bab83b4a4a35f293c6898da1f9c8d2c79eedd1b395d20eec4779949d5cdf22f7e");

        let client_proof_of_identity = [nonce_bytes, ecdh_key.public_key().to_sec1_bytes()[1..].to_vec(), user_key.get_raw_public_key(), signed_nonce].concat();

        println!("Client Proof of Identity: {:?}", hex::encode(&client_proof_of_identity));

        let expected_client_proof_of_identity = "5c513f8ab90094b01cda913d858ca71e14ee81ba484e9d6130abd96c21c5e8faa4c5eef4e22806412594d08a08c66201f3bb39161db47166b44f111c9eb6a40983ba3a408c2c44afded0d4b65359eb25397e4a39e2d5667f1329b413ff0efc8f04cc2484e17744aad0554e16d8b42c04688dd838a84b7dfacf53d629217ea404535c81b1fadb66e4dea5039001104d83935fb64bcd9d514dc364a893b445fad5eee8e43c035ef81badc6c02107cc13a29eac119b05fb645de8636e4fea7b240bab83b4a4a35f293c6898da1f9c8d2c79eedd1b395d20eec4779949d5cdf22f7e";
        assert_eq!(hex::encode(&client_proof_of_identity), expected_client_proof_of_identity);

        let iv_offset_hex = "ca682c217eaae46717e57df1b6f72693";
        let iv_offset_bytes = hex::decode(iv_offset_hex).unwrap();
        let encrypted_client_proof_of_identity = match encrypt_data(&session, &client_proof_of_identity, iv_offset_bytes.as_slice()) {
            Ok(encrypted_client_proof_of_identity) => encrypted_client_proof_of_identity,
            Err(e) => panic!("Failed to encrypt client proof of identity: {:?}", e),
        };

        println!("Encrypted Client Proof of Identity: {:?}", hex::encode(&encrypted_client_proof_of_identity));

        let expected_encrypted_client_proof_of_identity = "ca682c217eaae46717e57df1b6f72693d5a3126577a30fc4207887e98e5aa3ce802f4a8b3ed193ebe39882247d39ea0ce79d78d1aa04c3db94e40a4b020eb91e6f53e87ac466c6c72b90773d66202dd9d266daa54c6bfc3e2b2b0e11004e686c959fa89e98a1ff58c2f49a1b2ce07d8c2fdd48b97aaef4876763850bb3b0d566f168445dae4ec9018f277e650d794d8653a4336156f5fa5a3f99ee51c687e7f1b84d70cb8b8ebc8c2fa97d210e208850ba05b06cfb95ad99ccbda6687fc082643a437669f220b9c15782d92e6a498bc4d1ede69cfcc0d7c7badafa473cd5a6aab3413659b365f1365c960cf2553bf33db7a1e16a866583387bed40e9587b805d";
        assert_eq!(hex::encode(&encrypted_client_proof_of_identity), expected_encrypted_client_proof_of_identity);
    }
}