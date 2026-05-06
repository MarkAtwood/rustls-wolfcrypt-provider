use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use rustls::crypto::cipher::{
    make_tls12_aad, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};
use wolfssl_wolfcrypt::aes::GCM;
use zeroize::Zeroizing;

const GCM_NONCE_LENGTH: usize = 12;
const GCM_TAG_LENGTH: usize = 16;

pub struct Aes128Gcm;

impl Tls12AeadAlgorithm for Aes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        let mut iv_as_array = [0u8; GCM_NONCE_LENGTH];
        iv_as_array[..(GCM_NONCE_LENGTH - 8)].copy_from_slice(iv); // implicit
        iv_as_array[(GCM_NONCE_LENGTH - 8)..].copy_from_slice(extra); // explicit
        let key_as_slice = key.as_ref();

        Box::new(WCTls12Encrypter {
            iv: iv_as_array.into(),
            key: Zeroizing::new(key_as_slice.to_vec()),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let mut iv_implicit_as_array = [0u8; GCM_NONCE_LENGTH - 8];
        iv_implicit_as_array.copy_from_slice(iv);
        let key_as_slice = key.as_ref();

        Box::new(WCTls12Decrypter {
            implicit_iv: iv_implicit_as_array,
            key: Zeroizing::new(key_as_slice.to_vec()),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 16,
            fixed_iv_len: 4,
            explicit_nonce_len: 8,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let mut iv_arr = [0u8; GCM_NONCE_LENGTH];
        iv_arr[..4].copy_from_slice(iv);
        iv_arr[4..].copy_from_slice(explicit);
        Ok(ConnectionTrafficSecrets::Aes128Gcm {
            key,
            iv: Iv::new(iv_arr),
        })
    }
}

pub struct WCTls12Encrypter {
    iv: Iv,
    key: Zeroizing<Vec<u8>>,
}

pub struct WCTls12Decrypter {
    implicit_iv: [u8; 4],
    key: Zeroizing<Vec<u8>>,
}

impl MessageEncrypter for WCTls12Encrypter {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce = Nonce::new(&self.iv, seq).0;
        payload.extend_from_slice(&nonce[(GCM_NONCE_LENGTH - 8)..]);
        payload.extend_from_chunks(&m.payload);

        let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.len());
        let mut auth_tag = vec![0u8; GCM_TAG_LENGTH];

        let payload_start = GCM_NONCE_LENGTH - 4;
        let payload_end = m.payload.len() + (GCM_NONCE_LENGTH - 4);
        let plaintext = payload.as_ref()[payload_start..payload_end].to_vec();
        let mut ciphertext = vec![0u8; plaintext.len()];

        let mut gcm =
            GCM::new().map_err(|_| rustls::Error::General("wc_AesGcmInit failed".into()))?;
        gcm.init(&self.key)
            .map_err(|_| rustls::Error::General("wc_AesGcmSetKey failed".into()))?;
        gcm.encrypt(&plaintext, &mut ciphertext, &nonce, &aad, &mut auth_tag)
            .map_err(|_| rustls::Error::General("wc_AesGcmEncrypt failed".into()))?;

        payload.as_mut()[payload_start..payload_end].copy_from_slice(&ciphertext);
        payload.extend_from_slice(&auth_tag);

        Ok(OutboundOpaqueMessage::new(m.typ, m.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + (GCM_NONCE_LENGTH - 4) + GCM_TAG_LENGTH
    }
}

impl MessageDecrypter for WCTls12Decrypter {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;
        let payload_len = payload.len();

        // TLS 1.2 AES-GCM payload: explicit_nonce(8) || ciphertext || tag(16).
        // Minimum valid payload is explicit_nonce + tag = 24 bytes.
        let explicit_nonce_len = GCM_NONCE_LENGTH - 4; // 8
        if payload_len < explicit_nonce_len + GCM_TAG_LENGTH {
            return Err(rustls::Error::DecryptError);
        }

        let mut nonce = [0u8; GCM_NONCE_LENGTH];
        nonce[..(GCM_NONCE_LENGTH - 8)].copy_from_slice(self.implicit_iv.as_ref());
        nonce[(GCM_NONCE_LENGTH - 8)..].copy_from_slice(&payload[..(GCM_NONCE_LENGTH - 4)]);

        let mut auth_tag = [0u8; GCM_TAG_LENGTH];
        auth_tag.copy_from_slice(&payload[payload_len - GCM_TAG_LENGTH..]);
        let aad = make_tls12_aad(
            seq,
            m.typ,
            m.version,
            payload_len - GCM_TAG_LENGTH - explicit_nonce_len,
        );

        let payload_start = GCM_NONCE_LENGTH - 4;
        let payload_end = payload_len - GCM_TAG_LENGTH;
        let ciphertext = payload[payload_start..payload_end].to_vec();
        // Note: plaintext is a plain Vec; TLS record content is not zeroized on drop,
        // consistent with rustls's own behavior for record buffers.
        let mut plaintext = vec![0u8; ciphertext.len()];

        // GCM is re-initialized per-call because wolfssl_wolfcrypt::aes::GCM does not
        // implement Send/Sync and cannot be stored in the cipher struct. A future
        // optimization would add Send+Sync to GCM and store a pre-initialized context.
        let mut gcm =
            GCM::new().map_err(|_| rustls::Error::General("wc_AesGcmInit failed".into()))?;
        gcm.init(&self.key)
            .map_err(|_| rustls::Error::General("wc_AesGcmSetKey failed".into()))?;
        gcm.decrypt(&ciphertext, &mut plaintext, &nonce, &aad, &auth_tag)
            .map_err(|_| rustls::Error::General("wc_AesGcmDecrypt failed".into()))?;

        payload[..plaintext.len()].copy_from_slice(&plaintext);
        payload.truncate(plaintext.len());

        Ok(m.into_plain_message())
    }
}

impl Tls13AeadAlgorithm for Aes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(WCTls13Cipher {
            key: Zeroizing::new(key.as_ref().into()),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(WCTls13Cipher {
            key: Zeroizing::new(key.as_ref().into()),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        16_usize
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }
}

pub struct WCTls13Cipher {
    key: Zeroizing<Vec<u8>>,
    iv: Iv,
}

impl MessageEncrypter for WCTls13Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let payload_len = m.payload.len();
        let total_len = self.encrypted_payload_len(payload_len);
        let mut payload = PrefixedPayload::with_capacity(total_len);

        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);
        let mut auth_tag = [0u8; GCM_TAG_LENGTH];

        // Include the encoding type byte (+ 1) to avoid rustls EoF.
        let plaintext = payload.as_ref()[..payload_len + 1].to_vec();
        let mut ciphertext = vec![0u8; plaintext.len()];

        let mut gcm =
            GCM::new().map_err(|_| rustls::Error::General("wc_AesGcmInit failed".into()))?;
        gcm.init(&self.key)
            .map_err(|_| rustls::Error::General("wc_AesGcmSetKey failed".into()))?;
        gcm.encrypt(&plaintext, &mut ciphertext, &nonce.0, &aad, &mut auth_tag)
            .map_err(|_| rustls::Error::General("wc_AesGcmEncrypt failed".into()))?;

        payload.as_mut()[..payload_len + 1].copy_from_slice(&ciphertext);
        payload.extend_from_slice(&auth_tag);

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + GCM_TAG_LENGTH
    }
}

impl MessageDecrypter for WCTls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;
        // TLS 1.3 payload must contain at least the 16-byte auth tag.
        if payload.len() < GCM_TAG_LENGTH {
            return Err(rustls::Error::DecryptError);
        }
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload.len());
        let mut auth_tag = [0u8; GCM_TAG_LENGTH];
        let message_len = payload.len() - GCM_TAG_LENGTH;
        auth_tag.copy_from_slice(&payload[message_len..]);

        let ciphertext = payload[..message_len].to_vec();
        let mut plaintext = vec![0u8; message_len];

        let mut gcm =
            GCM::new().map_err(|_| rustls::Error::General("wc_AesGcmInit failed".into()))?;
        gcm.init(&self.key)
            .map_err(|_| rustls::Error::General("wc_AesGcmSetKey failed".into()))?;
        gcm.decrypt(&ciphertext, &mut plaintext, &nonce.0, &aad, &auth_tag)
            .map_err(|_| rustls::Error::General("wc_AesGcmDecrypt failed".into()))?;

        payload[..message_len].copy_from_slice(&plaintext);
        payload.truncate(message_len);

        m.into_tls13_unpadded_message()
    }
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
                let decrypt_result =
                    gcm.decrypt(&test.ct, &mut decrypted_data, &test.nonce, &test.aad, &test.tag);

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
