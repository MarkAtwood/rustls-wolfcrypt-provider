use super::aesgcm::define_aesgcm;

define_aesgcm! {
    struct_name: Aes128Gcm,
    enc_key_len: 16,
    key_len: 16,
    traffic_secret_tls12: Aes128Gcm,
    traffic_secret_tls13: Aes128Gcm,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wycheproof::{aead::TestFlag, TestResult};

    #[test]
    fn test_aesgcm128() {
        let key: [u8; 16] = [
            0x29, 0x8e, 0xfa, 0x1c, 0xcf, 0x29, 0xcf, 0x62, 0xae, 0x68, 0x24, 0xbf, 0xc1, 0x95,
            0x57, 0xfc,
        ];
        let iv: [u8; 12] = [
            0x6f, 0x58, 0xa9, 0x3f, 0xe1, 0xd2, 0x07, 0xfa, 0xe4, 0xed, 0x2f, 0x6d,
        ];
        let plain: [u8; 32] = [
            0xcc, 0x38, 0xbc, 0xcd, 0x6b, 0xc5, 0x36, 0xad, 0x91, 0x9b, 0x13, 0x95, 0xf5, 0xd6,
            0x38, 0x01, 0xf9, 0x9f, 0x80, 0x68, 0xd6, 0x5c, 0xa5, 0xac, 0x63, 0x87, 0x2d, 0xaf,
            0x16, 0xb9, 0x39, 0x01,
        ];
        let aad: [u8; 16] = [
            0x02, 0x1f, 0xaf, 0xd2, 0x38, 0x46, 0x39, 0x73, 0xff, 0xe8, 0x02, 0x56, 0xe5, 0xb1,
            0xc6, 0xb1,
        ];
        let cipher: [u8; 32] = [
            0xdf, 0xce, 0x4e, 0x9c, 0xd2, 0x91, 0x10, 0x3d, 0x7f, 0xe4, 0xe6, 0x33, 0x51, 0xd9,
            0xe7, 0x9d, 0x3d, 0xfd, 0x39, 0x1e, 0x32, 0x67, 0x10, 0x46, 0x58, 0x21, 0x2d, 0xa9,
            0x65, 0x21, 0xb7, 0xdb,
        ];
        let tag: [u8; 16] = [
            0x54, 0x24, 0x65, 0xef, 0x59, 0x93, 0x16, 0xf7, 0x3a, 0x7a, 0x56, 0x05, 0x09, 0xa2,
            0xd9, 0xf2,
        ];

        let mut result_encrypted = [0u8; 32];
        let mut result_decrypted = [0u8; 32];
        let mut result_tag = [0u8; 16];

        let mut gcm = GCM::new().unwrap();
        gcm.init(&key).unwrap();
        gcm.encrypt(&plain, &mut result_encrypted, &iv, &aad, &mut result_tag)
            .unwrap();

        assert_eq!(result_encrypted, cipher);
        assert_eq!(result_tag, tag);

        gcm.decrypt(&cipher, &mut result_decrypted, &iv, &aad, &result_tag)
            .unwrap();

        assert_eq!(result_decrypted, plain);
    }

    #[test]
    fn test_aesgcm128_wycheproof() {
        let test_name = wycheproof::aead::TestName::AesGcm;
        let test_set = wycheproof::aead::TestSet::load(test_name).unwrap();
        let mut counter = 0;

        for group in test_set
            .test_groups
            .into_iter()
            .filter(|group| group.key_size == 128)
            .filter(|group| group.nonce_size == 96)
        {
            for test in group.tests {
                counter += 1;

                let mut actual_ciphertext = vec![0u8; test.pt.len()];
                let mut actual_tag = [0u8; GCM_TAG_LENGTH];

                let mut gcm = GCM::new().unwrap();
                gcm.init(&test.key).unwrap();

                let encrypt_result = gcm.encrypt(
                    &test.pt,
                    &mut actual_ciphertext,
                    &test.nonce,
                    &test.aad,
                    &mut actual_tag,
                );

                match &test.result {
                    TestResult::Invalid => {
                        if test.flags.iter().any(|flag| *flag == TestFlag::ModifiedTag) {
                            assert_ne!(
                                actual_tag[..],
                                test.tag[..],
                                "Expected incorrect tag. Id {}: {}",
                                test.tc_id,
                                test.comment
                            );
                        }
                    }
                    TestResult::Valid | TestResult::Acceptable => {
                        assert!(
                            encrypt_result.is_ok(),
                            "Encryption failed for test case {}: {}",
                            test.tc_id,
                            test.comment
                        );
                        assert_eq!(
                            actual_ciphertext[..],
                            test.ct[..],
                            "Ciphertext mismatch in test case {}: {}",
                            test.tc_id,
                            test.comment
                        );
                        assert_eq!(
                            actual_tag[..],
                            test.tag[..],
                            "Tag mismatch in test case {}: {}",
                            test.tc_id,
                            test.comment
                        );
                    }
                }

                let mut decrypted_data = vec![0u8; test.ct.len()];
                let decrypt_result = gcm.decrypt(
                    &test.ct,
                    &mut decrypted_data,
                    &test.nonce,
                    &test.aad,
                    &test.tag,
                );

                match &test.result {
                    TestResult::Invalid => {
                        assert!(
                            decrypt_result.is_err(),
                            "Decryption should have failed for invalid test case {}: {}",
                            test.tc_id,
                            test.comment
                        );
                    }
                    TestResult::Valid | TestResult::Acceptable => {
                        assert!(
                            decrypt_result.is_ok(),
                            "Decryption failed for test case {}: {}",
                            test.tc_id,
                            test.comment
                        );
                        assert_eq!(
                            decrypted_data[..],
                            test.pt[..],
                            "Plaintext mismatch in test case {}: {}",
                            test.tc_id,
                            test.comment
                        );
                    }
                }
            }
        }

        assert!(
            counter > 50,
            "Insufficient number of tests run: {}",
            counter
        );
    }
}
