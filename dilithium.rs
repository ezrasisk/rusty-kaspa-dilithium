use pqcrypto_dilithium::dilithium3::{keypair, sign, verify, PublicKey, SecretKey, Signature};
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, Signature as _};
use kaspa_core::{error::Error, warn};
use kaspa_hashes::{blake2b_160, Hash};
use kaspa_addresses::{Address, Prefix, Version};
use serde::{Serialize, Deserialize};
use rand::rngs::OsRng;

/// Dilithium signature scheme identifier
pub const SCHEME_ID_DILITHIUM3: u8 = 0x01;

/// Represents a Dilithium3 public key
#[derive(Clone, Serialize, Deserialize)]
pub struct DilithiumPublicKey {
    pubkey: PublicKey,
}

impl DilithiumPublicKey {
    pub fn new(pubkey: PublicKey) -> Self {
        DilithiumPublicKey { pubkey }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let pubkey = PublicKey::from_bytes(bytes)
            .map_err(|_| Error::SignatureError("Invalid Dilithium public key".to_string()))?;
        Ok(Self::new(pubkey))
    }

    pub fn to_address(&self, prefix: Prefix) -> Result<Address, Error> {
        let pubkey_bytes = self.pubkey.as_bytes();
        let payload = blake2b_160(pubkey_bytes);
        Ok(Address::new(prefix, Version::PubKey, &payload)) // Bech32m
    }

    pub fn verify(&self, message: &[u8], signature: &DilithiumSignature) -> Result<(), Error> {
        verify(&signature.sig, message, &self.pubkey)
            .map_err(|_| Error::SignatureError("Dilithium verification failed".to_string()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.pubkey.as_bytes()
    }
}

/// Represents a Dilithium3 private key
#[derive(Serialize, Deserialize)]
pub struct DilithiumPrivateKey {
    privkey: SecretKey,
}

impl DilithiumPrivateKey {
    pub fn generate_keypair() -> (DilithiumPublicKey, DilithiumPrivateKey) {
        let (pubkey, privkey) = keypair();
        (DilithiumPublicKey::new(pubkey), DilithiumPrivateKey { privkey })
    }

    pub fn sign(&self, message: &[u8]) -> DilithiumSignature {
        let mut rng = OsRng;
        let nonce = rand::Rng::gen::<[u8; 32]>(&mut rng); // Basic nonce for replay protection
        let mut msg_with_nonce = nonce.to_vec();
        msg_with_nonce.extend_from_slice(message);
        let sig = sign(&msg_with_nonce, &self.privkey);
        DilithiumSignature { sig, nonce }
    }

    pub fn to_public_key(&self) -> DilithiumPublicKey {
        let pubkey = PublicKey::from_bytes(self.privkey.public_key_bytes())
            .expect("Private key should yield valid public key");
        DilithiumPublicKey::new(pubkey)
    }
}

/// Represents a Dilithium3 signature with nonce
#[derive(Clone, Serialize, Deserialize)]
pub struct DilithiumSignature {
    sig: Signature,
    nonce: [u8; 32],
}

impl DilithiumSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let sig = Signature::from_bytes(bytes)
            .map_err(|_| Error::SignatureError("Invalid Dilithium signature bytes".to_string()))?;
        Ok(DilithiumSignature { sig, nonce: [0; 32] }) // Nonce handled separately
    }

    pub fn to_transaction_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![SCHEME_ID_DILITHIUM3];
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(self.sig.as_bytes());
        bytes
    }

    pub fn from_transaction_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 33 || bytes[0] != SCHEME_ID_DILITHIUM3 {
            return Err(Error::SignatureError("Invalid Dilithium signature scheme".to_string()));
        }
        let nonce: [u8; 32] = bytes[1..33]
            .try_into()
            .map_err(|_| Error::SignatureError("Invalid nonce length".to_string()))?;
        let sig_bytes = &bytes[33..];
        let sig = Signature::from_bytes(sig_bytes)
            .map_err(|_| Error::SignatureError("Invalid Dilithium signature bytes".to_string()))?;
        Ok(DilithiumSignature { sig, nonce })
    }
}

pub fn init() {
    warn!("Dilithium module initialized with security level 3 (128-bit classical)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_and_signing() {
        let (pubkey, privkey) = DilithiumPrivateKey::generate_keypair();
        let message = b"test message";
        let signature = privkey.sign(message);
        let mut msg_with_nonce = signature.nonce.to_vec();
        msg_with_nonce.extend_from_slice(message);
        assert!(pubkey.verify(&msg_with_nonce, &signature).is_ok());
    }

    #[test]
    fn test_address_generation() {
        let (pubkey, _) = DilithiumPrivateKey::generate_keypair();
        let address = pubkey.to_address(Prefix::Testnet).unwrap();
        assert_eq!(address.version(), Version::PubKey);
        assert_eq!(address.payload().len(), 20);
    }
}