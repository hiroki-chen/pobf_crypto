use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Result};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct KeyPair {
    /// Only used once.
    /// Computation on the private key will CONSUME it, leaving `None` at the place.
    pub prv_k: Option<EphemeralSecret>,
    pub pub_k: PublicKey,
    pub signature: Vec<u8>,
    pub session_key: Vec<u8>,
    pub timestamp: u64,
}

impl KeyPair {
    pub fn new(keypair: (EphemeralSecret, PublicKey), signature: Vec<u8>) -> Self {
        Self {
            prv_k: Some(keypair.0),
            pub_k: keypair.1,
            signature,
            session_key: Vec::new(),
            timestamp: 0u64,
        }
    }

    pub fn compute_shared_key(&mut self, peer_pub_key: &[u8; 32], _: &[u8]) -> Result<()> {
        let peer_pub_key = PublicKey::from(peer_pub_key.clone());

        // Compute the shared DH key and take the ownership of the private key.
        self.session_key = self
            .prv_k
            .take()
            .ok_or(anyhow!("Private key is not initialized!"))?
            .diffie_hellman(&peer_pub_key)
            .to_bytes()
            .to_vec();

        Ok(())
    }

    pub fn encrypt_with_smk(&self, input: &[u8]) -> Result<Vec<u8>> {
        let aesctx = Aes128Gcm::new_from_slice(&self.session_key)
            .map_err(|e| anyhow!("[-] Failed to create AES context: {e}"))?;
        let nonce = Nonce::from_slice(&[0u8; 12]);

        match aesctx.encrypt(&nonce, input) {
            Ok(ciphertext) => Ok(ciphertext),
            Err(e) => Err(anyhow!("[-] Failed to encrypt the data: {e}")),
        }
    }

    pub fn decrypt_with_smk(&self, input: &[u8]) -> Result<Vec<u8>> {
        let aesctx = Aes128Gcm::new_from_slice(&self.session_key)
            .map_err(|e| anyhow!("[-] Failed to create AES context: {e}"))?;
        let nonce = Nonce::from_slice(&[0u8; 12]);

        match aesctx.decrypt(&nonce, input) {
            Ok(plaintext) => Ok(plaintext),
            Err(e) => Err(anyhow!("[-] Failed to decrypt the data: {e}")),
        }
    }
}
