/// Macro that generates the full AES-GCM MessageEncrypter/MessageDecrypter implementation
/// for both AES-128-GCM and AES-256-GCM. The two ciphers are identical in structure;
/// the only differences are:
///   - the outer algorithm struct name (e.g. `Aes128Gcm` vs `Aes256Gcm`)
///   - the key length reported to rustls (`key_len` / `enc_key_len`)
///   - the `ConnectionTrafficSecrets` variant used
///
/// Rather than duplicate ~300 lines of code, this macro expands both variants from a
/// single source of truth.
/// Standard AES-GCM nonce length (12 bytes = 4 implicit + 8 explicit for TLS 1.2,
/// or the full per-record nonce for TLS 1.3).
pub(crate) const GCM_NONCE_LENGTH: usize = 12;
/// AES-GCM authentication tag length (16 bytes).
pub(crate) const GCM_TAG_LENGTH: usize = 16;

macro_rules! define_aesgcm {
    (
        struct_name: $struct_name:ident,
        enc_key_len: $enc_key_len:expr,
        key_len: $key_len:expr,
        traffic_secret_tls12: $secret_tls12:ident,
        traffic_secret_tls13: $secret_tls13:ident $(,)?
    ) => {
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
        use crate::aead::aesgcm::{GCM_NONCE_LENGTH, GCM_TAG_LENGTH};

        pub struct $struct_name;

        impl Tls12AeadAlgorithm for $struct_name {
            fn encrypter(
                &self,
                key: AeadKey,
                iv: &[u8],
                extra: &[u8],
            ) -> Box<dyn MessageEncrypter> {
                let mut iv_as_array = [0u8; GCM_NONCE_LENGTH];
                iv_as_array[..(GCM_NONCE_LENGTH - 8)].copy_from_slice(iv); // implicit
                iv_as_array[(GCM_NONCE_LENGTH - 8)..].copy_from_slice(extra); // explicit
                Box::new(WCTls12Encrypter {
                    iv: iv_as_array.into(),
                    key: Zeroizing::new(key.as_ref().to_vec()),
                })
            }

            fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
                let mut iv_implicit_as_array = [0u8; GCM_NONCE_LENGTH - 8];
                iv_implicit_as_array.copy_from_slice(iv);
                Box::new(WCTls12Decrypter {
                    implicit_iv: iv_implicit_as_array,
                    key: Zeroizing::new(key.as_ref().to_vec()),
                })
            }

            fn key_block_shape(&self) -> KeyBlockShape {
                KeyBlockShape {
                    enc_key_len: $enc_key_len,
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
                Ok(ConnectionTrafficSecrets::$secret_tls12 {
                    key,
                    iv: Iv::new(iv_arr),
                })
            }
        }

        pub(super) struct WCTls12Encrypter {
            iv: Iv,
            key: Zeroizing<Vec<u8>>,
        }

        impl core::fmt::Debug for WCTls12Encrypter {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct("WCTls12Encrypter").finish_non_exhaustive()
            }
        }

        // SAFETY: WCTls12Encrypter holds only Iv ([u8; 12]) and Zeroizing<Vec<u8>>,
        // both of which are Send+Sync.  The GCM context is not stored — it is
        // created, used, and dropped within a single encrypt() call with no shared
        // state across threads.
        unsafe impl Send for WCTls12Encrypter {}
        unsafe impl Sync for WCTls12Encrypter {}

        pub(super) struct WCTls12Decrypter {
            implicit_iv: [u8; 4],
            key: Zeroizing<Vec<u8>>,
        }

        impl core::fmt::Debug for WCTls12Decrypter {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct("WCTls12Decrypter").finish_non_exhaustive()
            }
        }

        // SAFETY: Same rationale as WCTls12Encrypter — all fields are Send+Sync,
        // and the GCM context is ephemeral (created and dropped within decrypt()).
        unsafe impl Send for WCTls12Decrypter {}
        unsafe impl Sync for WCTls12Decrypter {}

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
                let mut auth_tag = [0u8; GCM_TAG_LENGTH];

                let explicit_nonce_len = GCM_NONCE_LENGTH - 4; // 8-byte explicit nonce in TLS 1.2
                let payload_start = explicit_nonce_len;
                let payload_end = m.payload.len() + explicit_nonce_len;
                // Copy only the output into a temporary buffer; pass the input
                // as a slice reference to avoid an extra heap allocation.
                let mut ciphertext = vec![0u8; payload_end - payload_start];

                let mut gcm = GCM::new()
                    .map_err(|_| rustls::Error::General("wc_AesGcmInit failed".into()))?;
                gcm.init(&self.key)
                    .map_err(|_| rustls::Error::General("wc_AesGcmSetKey failed".into()))?;
                gcm.encrypt(
                    &payload.as_ref()[payload_start..payload_end],
                    &mut ciphertext,
                    &nonce,
                    &aad,
                    &mut auth_tag,
                )
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

                // RFC 5288: nonce = fixed_iv (4 bytes) || explicit_nonce (8 bytes from wire).
                let mut nonce = [0u8; GCM_NONCE_LENGTH];
                nonce[..(GCM_NONCE_LENGTH - 8)].copy_from_slice(self.implicit_iv.as_ref()); // fixed_iv
                nonce[(GCM_NONCE_LENGTH - 8)..].copy_from_slice(&payload[..(GCM_NONCE_LENGTH - 4)]); // explicit

                let mut auth_tag = [0u8; GCM_TAG_LENGTH];
                auth_tag.copy_from_slice(&payload[payload_len - GCM_TAG_LENGTH..]);
                let aad = make_tls12_aad(
                    seq,
                    m.typ,
                    m.version,
                    payload_len - GCM_TAG_LENGTH - explicit_nonce_len,
                );

                let payload_start = explicit_nonce_len;
                let payload_end = payload_len - GCM_TAG_LENGTH;
                let plaintext_len = payload_end - payload_start;
                // Copy only the output; pass the ciphertext as a slice reference
                // to avoid an extra heap allocation on the decrypt hot path.
                // Wrap in Zeroizing so the intermediate cleartext buffer is wiped on drop.
                let mut plaintext = Zeroizing::new(vec![0u8; plaintext_len]);

                // GCM is re-initialized per-call because wolfssl_wolfcrypt::aes::GCM does not
                // implement Send/Sync and cannot be stored in the cipher struct. A future
                // optimization would add Send+Sync to GCM and store a pre-initialized context.
                let mut gcm = GCM::new()
                    .map_err(|_| rustls::Error::General("wc_AesGcmInit failed".into()))?;
                gcm.init(&self.key)
                    .map_err(|_| rustls::Error::General("wc_AesGcmSetKey failed".into()))?;
                // The immutable borrow of payload[payload_start..payload_end] is
                // released before the mutable copy_from_slice below.
                gcm.decrypt(
                    &payload[payload_start..payload_end],
                    &mut plaintext,
                    &nonce,
                    &aad,
                    &auth_tag,
                )
                .map_err(|_| rustls::Error::General("wc_AesGcmDecrypt failed".into()))?;

                payload[..plaintext_len].copy_from_slice(&plaintext);
                payload.truncate(plaintext_len);

                Ok(m.into_plain_message())
            }
        }

        impl Tls13AeadAlgorithm for $struct_name {
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
                $key_len
            }

            fn extract_keys(
                &self,
                key: AeadKey,
                iv: Iv,
            ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
                Ok(ConnectionTrafficSecrets::$secret_tls13 { key, iv })
            }
        }

        pub(super) struct WCTls13Cipher {
            key: Zeroizing<Vec<u8>>,
            iv: Iv,
        }

        impl core::fmt::Debug for WCTls13Cipher {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct("WCTls13Cipher").finish_non_exhaustive()
            }
        }

        // SAFETY: WCTls13Cipher holds only Zeroizing<Vec<u8>> and Iv ([u8; 12]),
        // both Send+Sync.  GCM is re-initialized per-call; no GCM context is stored.
        unsafe impl Send for WCTls13Cipher {}
        unsafe impl Sync for WCTls13Cipher {}

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
                // Copy only the output; pass plaintext as a slice reference to
                // avoid an extra heap allocation on the encrypt hot path.
                let inner_len = payload_len + 1;
                let mut ciphertext = vec![0u8; inner_len];

                let mut gcm = GCM::new()
                    .map_err(|_| rustls::Error::General("wc_AesGcmInit failed".into()))?;
                gcm.init(&self.key)
                    .map_err(|_| rustls::Error::General("wc_AesGcmSetKey failed".into()))?;
                gcm.encrypt(
                    &payload.as_ref()[..inner_len],
                    &mut ciphertext,
                    &nonce.0,
                    &aad,
                    &mut auth_tag,
                )
                .map_err(|_| rustls::Error::General("wc_AesGcmEncrypt failed".into()))?;

                payload.as_mut()[..inner_len].copy_from_slice(&ciphertext);
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

                // Copy only the output; pass ciphertext as a slice reference to
                // avoid an extra heap allocation on the decrypt hot path.
                // Wrap in Zeroizing so the intermediate cleartext buffer is wiped on drop.
                let mut plaintext = Zeroizing::new(vec![0u8; message_len]);

                let mut gcm = GCM::new()
                    .map_err(|_| rustls::Error::General("wc_AesGcmInit failed".into()))?;
                gcm.init(&self.key)
                    .map_err(|_| rustls::Error::General("wc_AesGcmSetKey failed".into()))?;
                // The immutable borrow of payload[..message_len] is released
                // before the mutable copy_from_slice below.
                gcm.decrypt(
                    &payload[..message_len],
                    &mut plaintext,
                    &nonce.0,
                    &aad,
                    &auth_tag,
                )
                .map_err(|_| rustls::Error::General("wc_AesGcmDecrypt failed".into()))?;

                payload[..message_len].copy_from_slice(&plaintext);
                payload.truncate(message_len);

                m.into_tls13_unpadded_message()
            }
        }
    };
}

pub(crate) use define_aesgcm;
