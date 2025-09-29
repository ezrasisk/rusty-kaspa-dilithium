use kaspa_core::{error::Error, warn};
use kaspa_hashes::blake2b_256;
use kaspa_addresses::{Address, Version};
use kaspa_consensus::model::Transaction;
use crate::crypto::dilithium::{DilithiumPublicKey, DilithiumSignature, SCHEME_ID_DILITHIUM3};
use crate::crypto::ecdsa::{EcdsaPublicKey, EcdsaSignature, SCHEME_ID_ECDSA};

pub const SCHEME_ID_ECDSA: u8 = 0x00;

pub fn verify_transaction(tx: &Transaction) -> Result<(), Error> {
    for (index, input) in tx.inputs.iter().enumerate() {
        let signature_bytes = input.signature.as_ref().ok_or_else(|| {
            Error::SignatureError("Missing signature".to_string())
        })?;
        if signature_bytes.is_empty() {
            return Err(Error::SignatureError("Empty signature".to_string()));
        }
        let scheme_id = signature_bytes[0];
        let sighash = serialize_sighash(tx, index)?;

        match scheme_id {
            SCHEME_ID_ECDSA => {
                let ecdsa_sig = EcdsaSignature::from_bytes(&signature_bytes[1..])?;
                let pubkey = EcdsaPublicKey::from_address(&input.previous_outpoint_address)?;
                pubkey.verify(&sighash, &ecdsa_sig)?;
            }
            SCHEME_ID_DILITHIUM3 => {
                let dilithium_sig = DilithiumSignature::from_transaction_bytes(signature_bytes)?;
                let pubkey = DilithiumPublicKey::from_address(&input.previous_outpoint_address)?;
                let mut msg_with_nonce = dilithium_sig.nonce.to_vec();
                msg_with_nonce.extend_from_slice(&sighash);
                pubkey.verify(&msg_with_nonce, &dilithium_sig)?;
            }
            _ => {
                return Err(Error::SignatureError(format!("Unknown scheme: {}", scheme_id)));
            }
        }
    }
    Ok(())
}

fn serialize_sighash(tx: &Transaction, input_index: usize) -> Result<Vec<u8>, Error> {
    if input_index >= tx.inputs.len() {
        return Err(Error::InvalidInput(format!("Invalid input index: {}", input_index)));
    }
    let mut serialized = Vec::new();
    serialized.extend_from_slice(&tx.version.to_le_bytes());
    serialized.extend(tx.serialize_without_signatures()?);
    serialized.extend_from_slice(&tx.mass.to_le_bytes());
    serialized.extend(&[0x01]); // SIGHASH_ALL
    let hash = blake2b_256(&serialized);
    Ok(hash.to_vec())
}

pub fn parse_input_signature(
    signature_bytes: &[u8],
    address: &Address,
) -> Result<(u8, Vec<u8>), Error> {
    if signature_bytes.is_empty() {
        return Err(Error::SignatureError("Empty signature".to_string()));
    }
    let scheme_id = signature_bytes[0];
    match scheme_id {
        SCHEME_ID_ECDSA | SCHEME_ID_DILITHIUM3 => {
            if address.version() != Version::PubKey {
                return Err(Error::SignatureError("Requires PubKey address".to_string()));
            }
            Ok((scheme_id, signature_bytes[1..].to_vec()))
        }
        _ => Err(Error::SignatureError(format!("Unsupported scheme: {}", scheme_id))),
    }
}

pub fn update_transaction_input(
    tx: &mut Transaction,
    input_index: usize,
    signature_bytes: Vec<u8>,
) -> Result<(), Error> {
    if input_index >= tx.inputs.len() {
        return Err(Error::InvalidInput(format!("Invalid input index: {}", input_index)));
    }
    tx.inputs[input_index].signature = Some(signature_bytes);
    Ok(())
}

pub fn init() {
    warn!("Transaction verifier initialized with ECDSA and Dilithium3 support");
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_addresses::Prefix;
    use crate::crypto::dilithium::DilithiumPrivateKey;

    #[test]
    fn test_dilithium_verification() {
        let mut tx = Transaction::new_dummy();
        let (pubkey, privkey) = DilithiumPrivateKey::generate_keypair();
        let address = pubkey.to_address(Prefix::Testnet).unwrap();
        tx.inputs[0].previous_outpoint_address = address;
        let sighash = serialize_sighash(&tx, 0).unwrap();
        let signature = privkey.sign(&sighash);
        update_transaction_input(&mut tx, 0, signature.to_transaction_bytes()).unwrap();
        assert!(verify_transaction(&tx).is_ok());
    }
}