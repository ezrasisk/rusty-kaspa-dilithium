use kaspa_core::{error::Error, warn};
use kaspa_consensus::model::{BlockHeader, Transaction};
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub dilithium_activation_height: u64,
    pub enable_ecdsa: bool,
}

impl ConsensusConfig {
    pub fn new(dilithium_activation_height: u64) -> Self {
        ConsensusConfig {
            dilithium_activation_height,
            enable_ecdsa: true,
        }
    }

    pub fn is_dilithium_active(&self, block_height: u64) -> bool {
        block_height >= self.dilithium_activation_height
    }

    pub fn validate_block_signatures(&self, header: &BlockHeader, txs: &[Transaction]) -> Result<(), Error> {
        let block_height = header.height;
        for tx in txs {
            for (i, input) in tx.inputs.iter().enumerate() {
                let signature = input.signature.as_ref().ok_or_else(|| {
                    Error::SignatureError("Missing signature".to_string())
                })?;
                let scheme_id = signature[0];
                if scheme_id == SCHEME_ID_DILITHIUM3 && !self.is_dilithium_active(block_height) {
                    return Err(Error::SignatureError("Dilithium signatures not active".to_string()));
                }
                if scheme_id == SCHEME_ID_ECDSA && !self.enable_ecdsa {
                    return Err(Error::SignatureError("ECDSA signatures disabled".to_string()));
                }
            }
        }
        Ok(())
    }
}

pub fn init() -> ConsensusConfig {
    let activation_height = 15_768_000; // ~6 months at 10 BPS
    warn!("Consensus config initialized with Dilithium activation at height {}", activation_height);
    ConsensusConfig::new(activation_height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::dilithium::DilithiumPrivateKey;

    #[test]
    fn test_dilithium_activation() {
        let config = ConsensusConfig::new(1000);
        assert!(!config.is_dilithium_active(999));
        assert!(config.is_dilithium_active(1000));
    }
}