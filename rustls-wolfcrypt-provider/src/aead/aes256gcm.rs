use super::aesgcm::define_aesgcm;

define_aesgcm! {
    struct_name: Aes256Gcm,
    enc_key_len: 32,
    key_len: 32,
    traffic_secret_tls12: Aes256Gcm,
    traffic_secret_tls13: Aes256Gcm,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wycheproof::{aead::TestFlag, TestResult};

    #[test]
    fn test_aesgcm256() {
        let key: [u8; 32] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08,
        ];
        let iv: [u8; 12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let plain: [u8; 60] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let aad: [u8; 20] = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];
        let cipher: [u8; 60] = [
            0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84,
            0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd,
            0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0,
            0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
            0xbc, 0xc9, 0xf6, 0x62,
        ];
        let tag: [u8; 16] = [
            0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d,
            0x55, 0x1b,
        ];

        let mut result_encrypted = [0u8; 60];
        let mut result_decrypted = [0u8; 60];
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
    fn test_aesgcm256_wycheproof() {
        let test_name = wycheproof::aead::TestName::AesGcm;
        let test_set = wycheproof::aead::TestSet::load(test_name).unwrap();
        let mut counter = 0;

        for group in test_set
            .test_groups
            .into_iter()
            .filter(|group| group.key_size == 256)
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
