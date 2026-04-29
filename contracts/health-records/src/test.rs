#[cfg(test)]
mod tests {
    use crate::{Error, HealthRecords, HealthRecordsClient};
    use shared::privacy::{EncryptedEnvelopeRef, PolicyMetadata};
    use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, String, Symbol};

    fn encrypted_ref(env: &Env, seed: u8) -> EncryptedEnvelopeRef {
        EncryptedEnvelopeRef {
            content_hash: BytesN::from_array(env, &[seed; 32]),
            envelope_uri: String::from_str(env, "enc+ipfs://bafyvalidhealthref"),
            key_version_id: String::from_str(env, "kv:v01"),
        }
    }

    fn policy(env: &Env) -> PolicyMetadata {
        PolicyMetadata {
            retention_class: Symbol::new(env, "clinical"),
            access_policy_hash: BytesN::from_array(env, &[7u8; 32]),
            purpose: Symbol::new(env, "treatment"),
        }
    }

    fn setup(env: &Env) -> (HealthRecordsClient<'static>, Address, Address) {
        let contract_id = env.register(HealthRecords, ());
        let client = HealthRecordsClient::new(env, &contract_id);
        let patient = Address::generate(env);
        let provider = Address::generate(env);
        (client, patient, provider)
    }

    #[test]
    fn test_create_record_with_consent() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, patient, provider) = setup(&env);

        client.grant_consent(&patient, &provider);

        let reference = encrypted_ref(&env, 1);
        let rtype = String::from_str(&env, "LAB_RESULT");

        let record_id =
            client.create_record(&patient, &provider, &reference, &rtype, &policy(&env));
        let record = client.get_record(&patient, &record_id);

        assert_eq!(record.integrity_hash.len(), 32);
        let hash_bytes: Bytes = record.integrity_hash.into();
        assert_ne!(hash_bytes, Bytes::new(&env));
    }

    #[test]
    fn test_create_record_without_consent_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, patient, provider) = setup(&env);

        let reference = encrypted_ref(&env, 1);
        let rtype = String::from_str(&env, "LAB_RESULT");

        let result =
            client.try_create_record(&patient, &provider, &reference, &rtype, &policy(&env));
        assert_eq!(result, Err(Ok(Error::ConsentNotGranted)));
    }

    #[test]
    fn test_get_record_by_patient() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, patient, provider) = setup(&env);

        client.grant_consent(&patient, &provider);
        let reference = encrypted_ref(&env, 1);
        let rtype = String::from_str(&env, "PRESCRIPTION");
        let record_id =
            client.create_record(&patient, &provider, &reference, &rtype, &policy(&env));

        let record = client.get_record(&patient, &record_id);
        assert_eq!(record.record_id, record_id);
    }

    #[test]
    fn test_get_record_by_consented_provider() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, patient, provider) = setup(&env);

        client.grant_consent(&patient, &provider);
        let reference = encrypted_ref(&env, 1);
        let rtype = String::from_str(&env, "DIAGNOSIS");
        let record_id =
            client.create_record(&patient, &provider, &reference, &rtype, &policy(&env));

        let record = client.get_record(&provider, &record_id);
        assert_eq!(record.record_id, record_id);
    }

    #[test]
    fn test_get_record_unauthorized_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, patient, provider) = setup(&env);
        let stranger = Address::generate(&env);

        client.grant_consent(&patient, &provider);
        let reference = encrypted_ref(&env, 1);
        let rtype = String::from_str(&env, "XRAY");
        let record_id =
            client.create_record(&patient, &provider, &reference, &rtype, &policy(&env));

        let result = client.try_get_record(&stranger, &record_id);
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
    }

    #[test]
    fn test_get_record_after_consent_revoked_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, patient, provider) = setup(&env);

        client.grant_consent(&patient, &provider);
        let reference = encrypted_ref(&env, 1);
        let rtype = String::from_str(&env, "LAB");
        let record_id =
            client.create_record(&patient, &provider, &reference, &rtype, &policy(&env));

        client.revoke_consent(&patient, &provider);

        let result = client.try_get_record(&provider, &record_id);
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
    }

    #[test]
    fn test_verify_record_integrity_valid() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, patient, provider) = setup(&env);

        client.grant_consent(&patient, &provider);
        let reference = encrypted_ref(&env, 1);
        let rtype = String::from_str(&env, "PRESCRIPTION");
        let record_id =
            client.create_record(&patient, &provider, &reference, &rtype, &policy(&env));
        let record = client.get_record(&patient, &record_id);

        let stored_hash: Bytes = record.integrity_hash.into();
        assert!(client.verify_record_integrity(&patient, &record_id, &stored_hash));
    }

    #[test]
    fn test_verify_record_integrity_tampered_returns_false() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, patient, provider) = setup(&env);

        client.grant_consent(&patient, &provider);
        let reference = encrypted_ref(&env, 1);
        let rtype = String::from_str(&env, "DIAGNOSIS");
        let record_id =
            client.create_record(&patient, &provider, &reference, &rtype, &policy(&env));

        let tampered_hash = Bytes::from_array(&env, &[0u8; 32]);
        assert!(!client.verify_record_integrity(&patient, &record_id, &tampered_hash));
    }

    #[test]
    fn test_verify_integrity_unauthorized_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, patient, provider) = setup(&env);
        let stranger = Address::generate(&env);

        client.grant_consent(&patient, &provider);
        let reference = encrypted_ref(&env, 1);
        let rtype = String::from_str(&env, "XRAY");
        let record_id =
            client.create_record(&patient, &provider, &reference, &rtype, &policy(&env));
        let record = client.get_record(&patient, &record_id);
        let hash: Bytes = record.integrity_hash.into();

        let result = client.try_verify_record_integrity(&stranger, &record_id, &hash);
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
    }

    #[test]
    fn test_verify_nonexistent_record_returns_false() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, patient, _) = setup(&env);

        let hash = Bytes::from_array(&env, &[0u8; 32]);
        assert!(!client.verify_record_integrity(&patient, &999u64, &hash));
    }

    #[test]
    fn test_verify_wrong_length_hash_returns_false() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, patient, provider) = setup(&env);

        client.grant_consent(&patient, &provider);
        let reference = encrypted_ref(&env, 1);
        let rtype = String::from_str(&env, "XRAY");
        let record_id =
            client.create_record(&patient, &provider, &reference, &rtype, &policy(&env));

        let short_hash = Bytes::from_array(&env, &[0u8; 16]);
        assert!(!client.verify_record_integrity(&patient, &record_id, &short_hash));
    }
}
