use kaspa_core::{error::Error, warn};
use kaspa_hashes::blake2b_256;
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus::model::{Transaction, TransactionInput, TransactionOutput};
use kaspa_wallet_core::tx::psbt::PartiallySignedTransaction;
use crate::crypto::dilithium::{DilithiumPrivateKey, DilithiumPublicKey, DilithiumSignature, SCHEME_ID_DILITHIUM3};
use crate::crypto::ecdsa::{EcdsaPrivateKey, EcdsaPublicKey, EcdsaSignature, SCHEME_ID_ECDSA};
use crate::consensus::multisig_verifier::{generate_multisig_redeem_script, generate_multisig_p2sh_address};

pub enum PrivateKey {
    Ecdsa(EcdsaPrivateKey),
    Dilithium(DilithiumPrivateKey),
}

pub struct TransactionBuilder {
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    private_keys: Vec<PrivateKey>,
    is_multisig: bool,
    multisig_m: u8,
}

impl TransactionBuilder {
    pub fn new(private_key: PrivateKey) -> Self {
        TransactionBuilder {
            inputs: Vec::new(),
            outputs: Vec::new(),
            private_keys: vec![private_key],
            is_multisig: false,
            multisig_m: 1,
        }
    }

    pub fn new_multisig(private_keys: Vec<PrivateKey>, m: u8) -> Result<Self, Error> {
        if m < 1 || m as usize > private_keys.len() {
            return Err(Error::InvalidInput(format!("Invalid multisig m: {}", m)));
        }
        let first_scheme = match &private_keys[0] {
            PrivateKey::Ecdsa(_) => SCHEME_ID_ECDSA,
            PrivateKey::Dilithium(_) => SCHEME_ID_DILITHIUM3,
        };
        for key in &private_keys {
            let scheme = match key {
                PrivateKey::Ecdsa(_) => SCHEME_ID_ECDSA,
                PrivateKey::Dilithium(_) => SCHEME_ID_DILITHIUM3,
            };
            if scheme != first_scheme {
                return Err(Error::InvalidInput("Mixed schemes not supported".to_string()));
            }
        }
        Ok(TransactionBuilder {
            inputs: Vec::new(),
            outputs: Vec::new(),
            private_keys,
            is_multisig: true,
            multisig_m: m,
        })
    }

    pub fn add_input(&mut self, input: TransactionInput) -> &mut Self {
        self.inputs.push(input);
        self
    }

    pub fn add_output(&mut self, output: TransactionOutput) -> &mut Self {
        self.outputs.push(output);
        self
    }

    pub fn build(&self) -> Result<Transaction, Error> {
        let mut tx = Transaction::new(self.inputs.clone(), self.outputs.clone());
        let scheme_id = match self.private_keys.first().unwrap() {
            PrivateKey::Ecdsa(_) => SCHEME_ID_ECDSA,
            PrivateKey::Dilithium(_) => SCHEME_ID_DILITHIUM3,
        };

        for i in 0..self.inputs.len() {
            let sighash = serialize_sighash(&tx, i)?;
            let mut signature_bytes = vec![scheme_id];
            let mut signatures_added = 0;

            for key in &self.private_keys {
                if signatures_added >= self.multisig_m {
                    break;
                }
                let signature = match key {
                    PrivateKey::Ecdsa(privkey) => {
                        let sig = privkey.sign(&sighash);
                        sig.to_transaction_bytes()[1..].to_vec()
                    }
                    PrivateKey::Dilithium(privkey) => {
                        let sig = privkey.sign(&sighash);
                        sig.to_transaction_bytes()[1..].to_vec()
                    }
                };
                signature_bytes.extend_from_slice(&signature);
                signatures_added += 1;
            }

            if signatures_added < self.multisig_m {
                return Err(Error::SignatureError(format!("Insufficient signatures: {} of {}", signatures_added, self.multisig_m)));
            }
            tx.inputs[i].signature = Some(signature_bytes);
            if self.is_multisig {
                let redeem_script = self.generate_redeem_script(scheme_id)?;
                tx.inputs[i].script = redeem_script;
            }
        }
        Ok(tx)
    }

    pub fn build_psbt(&self) -> Result<PartiallySignedTransaction, Error> {
        let tx = Transaction::new(self.inputs.clone(), self.outputs.clone());
        let mut psbt = PartiallySignedTransaction::new(tx)?;
        let scheme_id = match self.private_keys.first().unwrap() {
            PrivateKey::Ecdsa(_) => SCHEME_ID_ECDSA,
            PrivateKey::Dilithium(_) => SCHEME_ID_DILITHIUM3,
        };

        for i in 0..self.inputs.len() {
            let sighash = serialize_sighash(&psbt.tx, i)?;
            for key in &self.private_keys {
                let signature = match key {
                    PrivateKey::Ecdsa(privkey) => {
                        let sig = privkey.sign(&sighash);
                        sig.to_transaction_bytes()
                    }
                    PrivateKey::Dilithium(privkey) => {
                        let sig = privkey.sign(&sighash);
                        sig.to_transaction_bytes()
                    }
                };
                psbt.add_signature(i, signature)?;
            }
            if self.is_multisig {
                let redeem_script = self.generate_redeem_script(scheme_id)?;
                psbt.add_redeem_script(i, redeem_script)?;
            }
        }
        Ok(psbt)
    }

    fn generate_redeem_script(&self, scheme_id: u8) -> Result<Vec<u8>, Error> {
        let pubkeys: Vec<Vec<u8>> = self.private_keys.iter().map(|key| match key {
            PrivateKey::Ecdsa(pk) => pk.to_public_key().as_bytes().to_vec(),
            PrivateKey::Dilithium(pk) => pk.to_public_key().as_bytes().to_vec(),
        }).collect();
        let pubkey_refs: Vec<&[u8]> = pubkeys.iter().map(|pk| pk.as_slice()).collect();
        generate_multisig_redeem_script(&pubkey_refs, self.multisig_m, scheme_id)
    }

    pub fn generate_multisig_address(&self, prefix: Prefix) -> Result<Address, Error> {
        if !self.is_multisig {
            return Err(Error::InvalidInput("Not a multisig builder".to_string()));
        }
        let scheme_id = match self.private_keys.first().unwrap() {
            PrivateKey::Ecdsa(_) => SCHEME_ID_ECDSA,
            PrivateKey::Dilithium(_) => SCHEME_ID_DILITHIUM3,
        };
        let redeem_script = self.generate_redeem_script(scheme_id)?;
        Ok(generate_multisig_p2sh_address(&redeem_script, prefix))
    }
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

pub fn generate_keypair_and_address(scheme: &str, prefix: Prefix) -> Result<(PrivateKey, Address), Error> {
    match scheme {
        "ecdsa" => {
            let (pubkey, privkey) = EcdsaPrivateKey::generate_keypair();
            let address = pubkey.to_address(prefix)?;
            Ok((PrivateKey::Ecdsa(privkey), address))
        }
        "dilithium3" => {
            let (pubkey, privkey) = DilithiumPrivateKey::generate_keypair();
            let address = pubkey.to_address(prefix)?;
            Ok((PrivateKey::Dilithium(privkey), address))
        }
        _ => Err(Error::InvalidInput(format!("Unsupported scheme: {}", scheme))),
    }
}

pub fn init() {
    warn!("Wallet transaction module initialized with ECDSA, Dilithium3, and multisig");
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_addresses::Prefix;

    #[test]
    fn test_build_psbt_dilithium() {
        let (privkey1, _) = generate_keypair_and_address("dilithium3", Prefix::Testnet).unwrap();
        let (privkey2, _) = generate_keypair_and_address("dilithium3", Prefix::Testnet).unwrap();
        let mut builder = TransactionBuilder::new_multisig(vec![privkey1, privkey2], 2).unwrap();
        let address = builder.generate_multisig_address(Prefix::Testnet).unwrap();
        builder.add_input(TransactionInput {
            previous_outpoint_address: address.clone(),
            signature: None,
            script: vec![],
            ..TransactionInput::default()
        });
        builder.add_output(TransactionOutput::new(1000, address));
        let psbt = builder.build_psbt().unwrap();
        assert_eq!(psbt.signatures(0).unwrap().len(), 2);
    }
}