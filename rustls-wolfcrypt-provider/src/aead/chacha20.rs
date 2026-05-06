use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use chacha20poly1305::KeySizeUser;
use rustls::crypto::cipher::{
    make_tls12_aad, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    UnsupportedOperationError, NONCE_LEN,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};
use wolfssl_wolfcrypt::chacha20_poly1305::ChaCha20Poly1305;
use zeroize::Zeroizing;

const CHACHAPOLY1305_OVERHEAD: usize = 16;

pub struct Chacha20Poly1305;

impl Tls12AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        let mut key_as_vec = Zeroizing::new(vec![0u8; 32]);
        key_as_vec.copy_from_slice(key.as_ref());

        Box::new(WCTls12Cipher {
            key: key_as_vec,
            iv: Iv::copy(iv),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let mut key_as_vec = Zeroizing::new(vec![0u8; 32]);
        key_as_vec.copy_from_slice(key.as_ref());

        Box::new(WCTls12Cipher {
            key: key_as_vec,
            iv: Iv::copy(iv),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let iv_array: [u8; NONCE_LEN] = iv
            .try_into()
            .map_err(|_| UnsupportedOperationError)?;
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv_array),
        })
    }
}

pub struct WCTls12Cipher {
    key: Zeroizing<Vec<u8>>,
    iv: Iv,
}

impl MessageEncrypter for WCTls12Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&m.payload);

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.len());
        let plaintext = payload.as_ref()[..m.payload.len()].to_vec();
        let mut encrypted = vec![0u8; m.payload.len()];
        let mut auth_tag = [0u8; CHACHAPOLY1305_OVERHEAD];

        ChaCha20Poly1305::encrypt(
            &self.key,
            &nonce.0,
            &aad,
            &plaintext,
            &mut encrypted,
            &mut auth_tag,
        )
        .map_err(|_| rustls::Error::General("wc_ChaCha20Poly1305_Encrypt failed".into()))?;

        let mut output = PrefixedPayload::with_capacity(total_len);
        output.extend_from_slice(encrypted.as_slice());
        output.extend_from_slice(&auth_tag);

        Ok(OutboundOpaqueMessage::new(m.typ, m.version, output))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for WCTls12Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;
        // ChaCha20-Poly1305 payload must contain at least the 16-byte auth tag.
        if payload.len() < CHACHAPOLY1305_OVERHEAD {
            return Err(rustls::Error::DecryptError);
        }
        let message_len = payload.len() - CHACHAPOLY1305_OVERHEAD;
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, m.typ, m.version, message_len);
        let mut auth_tag = [0u8; CHACHAPOLY1305_OVERHEAD];
        auth_tag.copy_from_slice(&payload[message_len..]);

        let ciphertext = payload[..message_len].to_vec();
        let mut plaintext = vec![0u8; message_len];

        ChaCha20Poly1305::decrypt(
            &self.key,
            &nonce.0,
            &aad,
            &ciphertext,
            &auth_tag,
            &mut plaintext,
        )
        .map_err(|_| rustls::Error::General("wc_ChaCha20Poly1305_Decrypt failed".into()))?;

        payload[..message_len].copy_from_slice(&plaintext);
        payload.truncate(message_len);

        Ok(m.into_plain_message())
    }
}

impl Tls13AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        let mut key_as_array = Zeroizing::new([0u8; 32]);
        key_as_array[..32].copy_from_slice(key.as_ref());

        Box::new(WCTls13Cipher {
            key: key_as_array,
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        let mut key_as_array = Zeroizing::new([0u8; 32]);
        key_as_array[..32].copy_from_slice(key.as_ref());

        Box::new(WCTls13Cipher {
            key: key_as_array,
            iv,
        })
    }

    fn key_len(&self) -> usize {
        chacha20poly1305::ChaCha20Poly1305::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

pub struct WCTls13Cipher {
    key: Zeroizing<[u8; 32]>,
    iv: Iv,
}

impl MessageEncrypter for WCTls13Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);
        let mut auth_tag = [0u8; CHACHAPOLY1305_OVERHEAD];

        // Include the encoding type byte (+ 1) to avoid rustls EoF.
        let plaintext_len = m.payload.len() + 1;
        let plaintext = payload.as_ref()[..plaintext_len].to_vec();
        let mut encrypted = vec![0u8; plaintext_len];

        ChaCha20Poly1305::encrypt(
            &self.key[..],
            &nonce.0,
            &aad,
            &plaintext,
            &mut encrypted,
            &mut auth_tag,
        )
        .map_err(|_| rustls::Error::General("wc_ChaCha20Poly1305_Encrypt failed".into()))?;

        payload.as_mut()[..plaintext_len].copy_from_slice(&encrypted);
        payload.extend_from_slice(&auth_tag);

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for WCTls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;
        // ChaCha20-Poly1305 payload must contain at least the 16-byte auth tag.
        if payload.len() < CHACHAPOLY1305_OVERHEAD {
            return Err(rustls::Error::DecryptError);
        }
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload.len());
        let mut auth_tag = [0u8; CHACHAPOLY1305_OVERHEAD];
        let message_len = payload.len() - CHACHAPOLY1305_OVERHEAD;
        auth_tag.copy_from_slice(&payload[message_len..]);

        let ciphertext = payload[..message_len].to_vec();
        let mut plaintext = vec![0u8; message_len];

        ChaCha20Poly1305::decrypt(
            &self.key[..],
            &nonce.0,
            &aad,
            &ciphertext,
            &auth_tag,
            &mut plaintext,
        )
        .map_err(|_| rustls::Error::General("wc_ChaCha20Poly1305_Decrypt failed".into()))?;

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
    fn test_chacha() {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let plain_text: [u8; 114] = [
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e,
            0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20,
            0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
            0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
            0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72,
            0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        ];
        let iv: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let cipher: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        let auth_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        let mut generated_cipher_text = [0u8; 114];
        let mut generated_auth_tag = [0u8; CHACHAPOLY1305_OVERHEAD];

        ChaCha20Poly1305::encrypt(
            &key,
            &iv,
            &aad,
            &plain_text,
            &mut generated_cipher_text,
            &mut generated_auth_tag,
        )
        .unwrap();

        assert_eq!(generated_cipher_text, cipher);
        assert_eq!(generated_auth_tag, auth_tag);

        let mut generated_plain_text = [0u8; 114];

        ChaCha20Poly1305::decrypt(
            &key,
            &iv,
            &aad,
            &cipher,
            &auth_tag,
            &mut generated_plain_text,
        )
        .unwrap();

        assert_eq!(generated_plain_text, plain_text);
    }

    #[test]
    fn test_chacha20poly1305_wycheproof() {
        let test_name = wycheproof::aead::TestName::ChaCha20Poly1305;
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
                let mut actual_tag = [0u8; CHACHAPOLY1305_OVERHEAD];

                let encrypt_result = ChaCha20Poly1305::encrypt(
                    &test.key,
                    &test.nonce,
                    &test.aad,
                    &test.pt,
                    &mut actual_ciphertext,
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
                let decrypt_result = ChaCha20Poly1305::decrypt(
                    &test.key,
                    &test.nonce,
                    &test.aad,
                    &test.ct,
                    &test.tag,
                    &mut decrypted_data,
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
