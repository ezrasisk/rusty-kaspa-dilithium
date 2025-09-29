use kaspa_core::{error::Error, warn};
use kaspa_hashes::{blake2b_160, blake2b_256};
use kaspa_addresses::{Address, Version};
use kaspa_consensus::model::Transaction;
use crate::crypto::dilithium::{DilithiumPublicKey, DilithiumSignature, SCHEME_ID_DILITHIUM3};
use crate::crypto::ecdsa::{EcdsaPublicKey, EcdsaSignature, SCHEME_ID_ECDSA};

const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_3: u8 = 0x53;
const OP_CHECKMULTISIG: u8 = 0xAE;

pub fn verify_multisig_input(
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
    if input.script != redeem_script {
        return Err(Error::SignatureError("Input script does not match redeem script".to_string()));
    }

    if redeem_script.len() < 4 || redeem_script[redeem_script.len() - 1] != OP_CHECKMULTISIG {
        return Err(Error::SignatureError("Invalid multisig script".to_string()));
    }

    let m = match redeem_script[0] {
        OP_1 => 1,
        OP_2 => 2,
        OP_3 => 3,
        _ => return Err(Error::SignatureError("Invalid m value".to_string())),
    };
    let n = match redeem_script[redeem_script.len() - 2] {
        OP_1 => 1,
        OP_2 => 2,
        OP_3 => 3,
        _ => return Err(Error::SignatureError("Invalid n value".to_string())),
    };
    if m > n || n > 3 {
        return Err(Error::SignatureError("Invalid m-of-n configuration".to_string()));
    }

    let scheme_id = signature_bytes[0];
    let pubkey_len = if scheme_id == SCHEME_ID_DILITHIUM3 { 2448 } else { 33 };
    let pubkeys_start = 1;
    let pubkeys_end = pubkeys_start + n as usize * pubkey_len;
    if redeem_script.len() < pubkeys_end + 2 {
        return Err(Error::SignatureError("Script too short for keys".to_string()));
    }
    let pubkeys: Vec<&[u8]> = (pubkeys_start..pubkeys_end)
        .step_by(pubkey_len)
        .map(|i| &redeem_script[i..i + pubkey_len])
        .collect();

    let mut sig_offset = 1;
    let mut valid_signatures = 0;
    let sighash = serialize_sighash(tx, input_index)?;
    for _ in 0..m {
        if sig_offset >= signature_bytes.len() {
            return Err(Error::SignatureError("Insufficient signatures".to_string()));
        }
        let sig_len = if scheme_id == SCHEME_ID_DILITHIUM3 { 32 + 4591 } else { 70 };
        if sig_offset + sig_len > signature_bytes.len() {
            return Err(Error::SignatureError("Invalid signature length".to_string()));
        }
        let sig_bytes = &signature_bytes[sig_offset..sig_offset + sig_len];
        sig_offset += sig_len;

        let mut matched = false;
        for pubkey_bytes in &pubkeys {
            let result = match scheme_id {
                SCHEME_ID_DILITHIUM3 => {
                    let pubkey = DilithiumPublicKey::from_bytes(pubkey_bytes)?;
                    let sig = DilithiumSignature::from_transaction_bytes(&[SCHEME_ID_DILITHIUM3].into_iter().chain(sig_bytes.iter()).copied().collect::<Vec<u8>>())?;
                    let mut msg_with_nonce = sig.nonce.to_vec();
                    msg_with_nonce.extend_from_slice(&sighash);
                    pubkey.verify(&msg_with_nonce, &sig)
                }
                SCHEME_ID_ECDSA => {
                    let pubkey = EcdsaPublicKey::from_bytes(pubkey_bytes)?;
                    let sig = EcdsaSignature::from_bytes(sig_bytes)?;
                    pubkey.verify(&sighash, &sig)
                }
                _ => Err(Error::SignatureError(format!("Unsupported scheme: {}", scheme_id))),
            };
            if result.is_ok() {
                valid_signatures += 1;
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(Error::SignatureError("No matching public key".to_string()));
        }
    }

    if valid_signatures < m {
        return Err(Error::SignatureError(format!("Insufficient valid signatures: {} of {}", valid_signatures, m)));
    }
    Ok(())
}

pub fn generate_multisig_redeem_script(pubkeys: &[&[u8]], m: u8, scheme: u8) -> Result<Vec<u8>, Error> {
    if m < 1 || m > 3 || m as usize > pubkeys.len() || pubkeys.len() > 3 {
        return Err(Error::InvalidInput(format!("Invalid m-of-n: m={}, n={}", m, pubkeys.len())));
    }
    let pubkey_len = if scheme == SCHEME_ID_DILITHIUM3 { 2448 } else { 33 };
    for pubkey in pubkeys {
        if pubkey.len() != pubkey_len {
            return Err(Error::InvalidInput("Invalid public key length".to_string()));
        }
    }
    let mut script = vec![match m { 1 => OP_1, 2 => OP_2, 3 => OP_3, _ => unreachable!() }];
    for pubkey in pubkeys {
        script.extend_from_slice(pubkey);
    }
    script.push(match pubkeys.len() as u8 { 1 => OP_1, 2 => OP_2, 3 => OP_3, _ => unreachable!() });
    script.push(OP_CHECKMULTISIG);
    Ok(script)
}

pub fn generate_multisig_p2sh_address(redeem_script: &[u8], prefix: Prefix) -> Address {
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
    warn!("Multisig verifier initialized with ECDSA and Dilithium3 support");
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_addresses::Prefix;
    use crate::crypto::dilithium::DilithiumPrivateKey;

    #[test]
    fn test_multisig_dilithium_2of3() {
        let (pubkey1, privkey1) = DilithiumPrivateKey::generate_keypair();
        let (pubkey2, privkey2) = DilithiumPrivateKey::generate_keypair();
        let (pubkey3, _) = DilithiumPrivateKey::generate_keypair();
        let pubkeys = [pubkey1.as_bytes(), pubkey2.as_bytes(), pubkey3.as_bytes()];
        let redeem_script = generate_multisig_redeem_script(&pubkeys, 2, SCHEME_ID_DILITHIUM3).unwrap();
        let address = generate_multisig_p2sh_address(&redeem_script, Prefix::Testnet);
        let mut tx = Transaction::new_dummy();
        tx.inputs[0].previous_outpoint_address = address;
        tx.inputs[0].script = redeem_script.clone();
        let sighash = serialize_sighash(&tx, 0).unwrap();
        let sig1 = privkey1.sign(&sighash);
        let sig2 = privkey2.sign(&sighash);
        let mut signature_bytes = vec![SCHEME_ID_DILITHIUM3];
        signature_bytes.extend_from_slice(sig1.to_transaction_bytes().as_slice().get(1..).unwrap());
        signature_bytes.extend_from_slice(sig2.to_transaction_bytes().as_slice().get(1..).unwrap());
        tx.inputs[0].signature = Some(signature_bytes);
        assert!(verify_multisig_input(&tx, 0, &redeem_script).is_ok());
    }
}