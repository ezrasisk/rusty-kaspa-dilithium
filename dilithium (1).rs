use pqcrypto_dilithium::dilithium3::{keypair, keypair_from_seed, sign, verify, PublicKey, SecretKey, Signature};
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, Signature as _};
use kaspa_core::{error::Error, warn};
use kaspa_hashes::{blake2b_160, Hash};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_wallet_keys::bip32::ExtendedPrivateKey;
use serde::{Serialize, Deserialize};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

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
        if bytes.len() != 2448 {
            return Err(Error::SignatureError("Invalid Dilithium3 public key length".to_string()));
        }
        let pubkey = PublicKey::from_bytes(bytes)
            .map_err(|_| Error::SignatureError("Invalid Dilithium3 public key".to_string()))?;
        Ok(Self::new(pubkey))
    }

    pub fn from_pubkey_hash(hash: &[u8]) -> Result<Self, Error> {
        let pubkey = PublicKey::from_bytes(hash)
            .map_err(|_| Error::SignatureError("Invalid pubkey hash for Dilithium3".to_string()))?;
        Ok(Self::new(pubkey))
    }

    pub fn from_address(address: &Address) -> Result<Self, Error> {
        if address.version() != Version::PubKey {
            return Err(Error::SignatureError("Address must be PubKey type".to_string()));
        }
        Self::from_pubkey_hash(address.payload())
    }

    pub fn to_address(&self, prefix: Prefix) -> Result<Address, Error> {
        let pubkey_bytes = self.pubkey.as_bytes();
        if pubkey_bytes.len() != 2448 {
            return Err(Error::SignatureError("Invalid Dilithium3 public key length".to_string()));
        }
        let payload = blake2b_160(pubkey_bytes);
        Ok(Address::new(prefix, Version::PubKey, &payload)) // Bech32m
    }

    pub fn verify(&self, message: &[u8], signature: &DilithiumSignature) -> Result<(), Error> {
        verify(&signature.sig, message, &self.pubkey)
            .map_err(|_| Error::SignatureError("Dilithium3 verification failed".to_string()))
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
    /// Generate a random keypair (non-deterministic)
    pub fn generate_keypair() -> (DilithiumPublicKey, DilithiumPrivateKey) {
        let (pubkey, privkey) = keypair();
        (DilithiumPublicKey::new(pubkey), DilithiumPrivateKey { privkey })
    }

    /// Generate a keypair from a seed for deterministic wallet derivation
    pub fn from_seed(seed: &[u8]) -> Result<(DilithiumPublicKey, DilithiumPrivateKey), Error> {
        if seed.len() < 32 {
            return Err(Error::SignatureError("Seed must be at least 32 bytes".to_string()));
        }
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(b"Dilithium3");
        let derived_seed = hasher.finalize();
        let (pubkey, privkey) = keypair_from_seed(&derived_seed)
            .map_err(|_| Error::SignatureError("Failed to generate Dilithium3 keypair from seed".to_string()))?;
        Ok((DilithiumPublicKey::new(pubkey), DilithiumPrivateKey { privkey }))
    }

    /// Generate multiple keypairs from a seed for batch derivation
    pub fn generate_keypairs_from_seed(seed: &[u8], count: usize) -> Result<Vec<(DilithiumPublicKey, DilithiumPrivateKey)>, Error> {
        if seed.len() < 32 {
            return Err(Error::SignatureError("Seed must be at least 32 bytes".to_string()));
        }
        let mut keys = Vec::with_capacity(count);
        let mut hasher = Sha256::new();
        for i in 0..count {
            hasher.update(seed);
            hasher.update(&i.to_le_bytes());
            hasher.update(b"Dilithium3");
            let derived_seed = hasher.finalize_reset();
            let (pubkey, privkey) = keypair_from_seed(&derived_seed)
                .map_err(|_| Error::SignatureError("Batch key generation failed".to_string()))?;
            keys.push((DilithiumPublicKey::new(pubkey), DilithiumPrivateKey { privkey }));
        }
        Ok(keys)
    }

    /// Generate from BIP-32 extended private key with Dilithium-specific derivation path
    pub fn from_extended_key(ext_key: &ExtendedPrivateKey) -> Result<(DilithiumPublicKey, DilithiumPrivateKey), Error> {
        const DILITHIUM_COIN_TYPE: u32 = 111112; // m/44'/111112'
        let dilithium_key = ext_key.derive_path(&format!("m/44'/{}'/0'/0/0", DILITHIUM_COIN_TYPE))
            .map_err(|_| Error::SignatureError("Failed to derive Dilithium3 key from BIP-32 path".to_string()))?;
        let seed = dilithium_key.private_key().as_bytes();
        Self::from_seed(seed)
    }

    pub fn sign(&self, message: &[u8]) -> DilithiumSignature {
        let mut rng = OsRng;
        let nonce = rand::Rng::gen::<[u8; 32]>(&mut rng); // Replay protection
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
        if bytes.len() != 4591 {
            return Err(Error::SignatureError("Invalid Dilithium3 signature length".to_string()));
        }
        let sig = Signature::from_bytes(bytes)
            .map_err(|_| Error::SignatureError("Invalid Dilithium3 signature bytes".to_string()))?;
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
            return Err(Error::SignatureError("Invalid Dilithium3 signature scheme".to_string()));
        }
        let nonce: [u8; 32] = bytes[1..33]
            .try_into()
            .map_err(|_| Error::SignatureError("Invalid nonce length".to_string()))?;
        let sig_bytes = &bytes[33..];
        if sig_bytes.len() != 4591 {
            return Err(Error::SignatureError("Invalid Dilithium3 signature length".to_string()));
        }
        let sig = Signature::from_bytes(sig_bytes)
            .map_err(|_| Error::SignatureError("Invalid Dilithium3 signature bytes".to_string()))?;
        Ok(DilithiumSignature { sig, nonce })
    }
}

pub fn init() {
    warn!("Dilithium3 module initialized with security level 3 (128-bit classical). Pending side-channel audit for pqcrypto-dilithium.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_addresses::Prefix;

    #[test]
    fn test_random_keypair_and_signing() {
        let (pubkey, privkey) = DilithiumPrivateKey::generate_keypair();
        let message = b"test message";
        let signature = privkey.sign(message);
        let mut msg_with_nonce = signature.nonce.to_vec();
        msg_with_nonce.extend_from_slice(message);
        assert!(pubkey.verify(&msg_with_nonce, &signature).is_ok());
    }

    #[test]
    fn test_deterministic_keypair() {
        let seed = [0u8; 32];
        let (pubkey1, privkey1) = DilithiumPrivateKey::from_seed(&seed).unwrap();
        let (pubkey2, privkey2) = DilithiumPrivateKey::from_seed(&seed).unwrap();
        assert_eq!(pubkey1.as_bytes(), pubkey2.as_bytes());
        let message = b"test message";
        let signature = privkey1.sign(message);
        let mut msg_with_nonce = signature.nonce.to_vec();
        msg_with_nonce.extend_from_slice(message);
        assert!(pubkey2.verify(&msg_with_nonce, &signature).is_ok());
    }

    #[test]
    fn test_batch_keypair() {
        let seed = [0u8; 32];
        let keypairs = DilithiumPrivateKey::generate_keypairs_from_seed(&seed, 3).unwrap();
        assert_eq!(keypairs.len(), 3);
        for (pubkey, _) in &keypairs {
            let address = pubkey.to_address(Prefix::Testnet).unwrap();
            assert_eq!(address.version(), Version::PubKey);
        }
    }

    #[test]
    fn test_invalid_seed() {
        let seed = [0u8; 16]; // Too short
        assert!(DilithiumPrivateKey::from_seed(&seed).is_err());
    }
}