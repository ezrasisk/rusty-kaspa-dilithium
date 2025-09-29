#[cfg(test)]
mod tests {
    use kaspa_core::error::Error;
    use kaspa_consensus::model::{Transaction, TransactionInput, TransactionOutput};
    use kaspa_addresses::Prefix;
    use crate::crypto::dilithium::{DilithiumPrivateKey, SCHEME_ID_DILITHIUM3};
    use crate::crypto::ecdsa::{EcdsaPrivateKey, SCHEME_ID_ECDSA};
    use crate::consensus::transaction_verifier::{verify_transaction, serialize_sighash};
    use crate::wallet::core::transaction::{TransactionBuilder, generate_keypair_and_address};

    #[test]
    fn test_mixed_transactions() -> Result<(), Error> {
        let mut txs = vec![];

        // ECDSA transaction
        let (ecdsa_privkey, ecdsa_address) = generate_keypair_and_address("ecdsa", Prefix::Testnet)?;
        let mut ecdsa_builder = TransactionBuilder::new(ecdsa_privkey);
        ecdsa_builder.add_input(TransactionInput {
            previous_outpoint_address: ecdsa_address.clone(),
            signature: None,
            script: vec![],
            ..TransactionInput::default()
        });
        ecdsa_builder.add_output(TransactionOutput::new(1000, ecdsa_address));
        let ecdsa_tx = ecdsa_builder.build()?;
        txs.push(ecdsa_tx);

        // Dilithium transaction
        let (dilithium_privkey, dilithium_address) = generate_keypair_and_address("dilithium3", Prefix::Testnet)?;
        let mut dilithium_builder = TransactionBuilder::new(dilithium_privkey);
        dilithium_builder.add_input(TransactionInput {
            previous_outpoint_address: dilithium_address.clone(),
            signature: None,
            script: vec![],
            ..TransactionInput::default()
        });
        dilithium_builder.add_output(TransactionOutput::new(1000, dilithium_address));
        let dilithium_tx = dilithium_builder.build()?;
        txs.push(dilithium_tx);

        // Multisig Dilithium transaction
        let (privkey1, _) = generate_keypair_and_address("dilithium3", Prefix::Testnet)?;
        let (privkey2, _) = generate_keypair_and_address("dilithium3", Prefix::Testnet)?;
        let mut multisig_builder = TransactionBuilder::new_multisig(vec![privkey1, privkey2], 2)?;
        let multisig_address = multisig_builder.generate_multisig_address(Prefix::Testnet)?;
        multisig_builder.add_input(TransactionInput {
            previous_outpoint_address: multisig_address.clone(),
            signature: None,
            script: vec![],
            ..TransactionInput::default()
        });
        multisig_builder.add_output(TransactionOutput::new(1000, multisig_address));
        let multisig_tx = multisig_builder.build()?;
        txs.push(multisig_tx);

        // Verify all transactions
        for tx in &txs {
            assert!(verify_transaction(tx).is_ok(), "Transaction verification failed");
        }
        Ok(())
    }
}