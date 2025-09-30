#[cfg(test)]
mod tests {
    use kaspa_core::error::Error;
    use kaspa_consensus::model::{Transaction, TransactionInput, TransactionOutput};
    use kaspa_addresses::Prefix;
    use kaspa_wallet_keys::bip32::ExtendedPrivateKey;
    use crate::crypto::dilithium::{DilithiumPrivateKey, SCHEME_ID_DILITHIUM3};
    use crate::consensus::transaction_verifier::{verify_transaction, serialize_sighash};
    use crate::wallet::core::transaction::{TransactionBuilder, PrivateKey, generate_keypair_and_address};
    use crate::wallet::core::key_taint::KeyTaintTracker;

    #[test]
    fn test_high_load_dilithium() -> Result<(), Error> {
        let seed = [0u8; 32];
        let ext_key = ExtendedPrivateKey::new(&seed)?;
        let mut txs = vec![];
        let keypairs = DilithiumPrivateKey::generate_keypairs_from_seed(&seed, 100)?;
        for (pubkey, privkey) in keypairs {
            let address = pubkey.to_address(Prefix::Testnet)?;
            let mut builder = TransactionBuilder::new(PrivateKey::Dilithium(privkey), KeyTaintTracker::new());
            builder.add_input(TransactionInput {
                previous_outpoint_address: address.clone(),
                signature: None,
                script: vec![],
                ..TransactionInput::default()
            });
            builder.add_output(TransactionOutput::new(1000, address));
            txs.push(builder.build()?);
        }
        for tx in &txs {
            assert!(verify_transaction(tx).is_ok());
        }
        Ok(())
    }
}