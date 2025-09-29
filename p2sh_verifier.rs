use kaspa_core::{error::Error, warn};
use kaspa_hashes::{blake2b_160, blake2b_256};
use kaspa_addresses::{Address, Version};
use kaspa_consensus::model::Transaction;
use crate::crypto::dilithium::{DilithiumPublicKey, DilithiumSignature, SCHEME_ID_DILITHIUM3};
use crate::crypto::ecdsa::{EcdsaPublicKey, EcdsaSignature, SCHEME_ID_ECDSA};
use crate::consensus::multisig_verifier::{verify_multisig_input, generate_multisig_redeem_script, generate_multisig_p2sh_address};

pub fn verify_p2sh_input(
    tx: &Transaction,
    input_index: usize,
    redeem_script: &[u8],
) -> Result<(), Error> {
    if input_index >= tx.inputs.len() {
        return Err(Error::InvalidInput(format!("Invalid input index: {}", input_index)));
    }
    let input = &tx.inputs[input_index];
    let signature_bytes = input.signature.as_ref().ok_or_else(|| {
        Error::SignatureError("Missing signature".to_string())
    })?;
    let script_hash = blake2b_160(redeem_script);
    if input.previous_outpoint_address.payload() != script_hash {
        return Err(Error::SignatureError("Redeem script hash mismatch".to_string()));
    }
    if input.script != redeem_script {
        return Err(Error::SignatureError("Input script does not match redeem script".to_string()));
    }

    if redeem_script.len() >= 4 && redeem_script[redeem_script.len() - 1] == 0xAE {
        return verify_multisig_input(tx, input_index, redeem_script);
    }

    if redeem_script.len() < 24 || redeem_script[0] != 0xA9 || redeem_script[1] != 0x14 {
        return Err(Error::SignatureError("Invalid redeem script format".to_string()));
    }
    let pubkey_hash = &redeem_script[2..22];
    let sig_type = redeem_script[redeem_script.len() - 2];
    let sighash = serialize_sighash(tx, input_index)?;

    match signature_bytes[0] {
        SCHEME_ID_ECDSA if sig_type == 0xAC => {
            let ecdsa_sig = EcdsaSignature::from_bytes(&signature_bytes[1..])?;
            let pubkey = EcdsaPublicKey::from_pubkey_hash(pubkey_hash)?;
            pubkey.verify(&sighash, &ecdsa_sig)?;
        }
        SCHEME_ID_DILITHIUM3 if sig_type == 0xAD => {
            let dilithium_sig = DilithiumSignature::from_transaction_bytes(signature_bytes)?;
            let pubkey = DilithiumPublicKey::from_pubkey_hash(pubkey_hash)?;
            let mut msg_with_nonce = dilithium_sig.nonce.to_vec();
            msg_with_nonce.extend_from_slice(&sighash);
            pubkey.verify(&msg_with_nonce, &dilithium_sig)?;
        }
        _ => {
            return Err(Error::SignatureError("Invalid signature or script type".to_string()));
        }
    }
    Ok(())
}

pub fn generate_p2sh_redeem_script(pubkey: &[u8], scheme: u8) -> Vec<u8> {
    let pubkey_hash = blake2b_160(pubkey);
    let mut script = vec![0xA9, 0x14];
    script.extend_from_slice(&pubkey_hash);
    script.extend(&[0x87, if scheme == SCHEME_ID_DILITHIUM3 { 0xAD } else { 0xAC }, 0xAE]);
    script
}

pub fn generate_p2sh_address(redeem_script: &[u8], prefix: Prefix) -> Address {
    let script_hash = blake2b_160(redeem_script);
    Address::new(prefix, Version::ScriptHash, &script_hash)
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

pub fn init() {
    warn!("P2SH verifier initialized with ECDSA, Dilithium3, and multisig support");
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_addresses::Prefix;
    use crate::crypto::dilithium::DilithiumPrivateKey;

    #[test]
    fn test_p2sh_dilithium() {
        let (pubkey, privkey) = DilithiumPrivateKey::generate_keypair();
        let redeem_script = generate_p2sh_redeem_script(pubkey.as_bytes(), SCHEME_ID_DILITHIUM3);
        let address = generate_p2sh_address(&redeem_script, Prefix::Testnet);
        let mut tx = Transaction::new_dummy();
        tx.inputs[0].previous_outpoint_address = address;
        tx.inputs[0].script = redeem_script.clone();
        let sighash = serialize_sighash(&tx, 0).unwrap();
        let signature = privkey.sign(&sighash);
        tx.inputs[0].signature = Some(signature.to_transaction_bytes());
        assert!(verify_p2sh_input(&tx, 0, &redeem_script).is_ok());
    }
}