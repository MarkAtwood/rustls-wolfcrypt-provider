use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use rustls::crypto::tls13::{self, Hkdf as RustlsHkdf};
use wolfssl_wolfcrypt::hkdf::{hkdf_expand, hkdf_extract};

use crate::hmac::WCShaHmac;
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct WCHkdfUsingHmac(pub WCShaHmac);

impl RustlsHkdf for WCHkdfUsingHmac {
    fn extract_from_zero_ikm(
        &self,
        salt: Option<&[u8]>,
    ) -> Box<dyn rustls::crypto::tls13::HkdfExpander> {
        let hash_len = self.0.hash_len();
        let ikm = vec![0u8; hash_len];
        self.extract_from_secret(salt, &ikm)
    }

    fn extract_from_secret(
        &self,
        salt: Option<&[u8]>,
        ikm: &[u8],
    ) -> Box<dyn rustls::crypto::tls13::HkdfExpander> {
        let typ = self.0.hmac_type();
        let hash_len = self.0.hash_len();
        let mut extracted_key = vec![0u8; hash_len];
        let zero_salt = vec![0u8; hash_len];
        let salt_bytes = salt.unwrap_or(&zero_salt);

        // hkdf_extract can only fail on invalid hash type (impossible: our typ
        // comes from a statically-known WCShaHmac variant) or OOM.  The rustls
        // Hkdf trait returns a Box<dyn HkdfExpander> — there is no Result.
        hkdf_extract(typ, Some(salt_bytes), ikm, &mut extracted_key)
            .unwrap_or_else(|e| unreachable!("hkdf_extract failed: wolfSSL error {}", e));

        Box::new(WolfHkdfExpander::new(
            Zeroizing::new(extracted_key),
            typ,
            hash_len,
        ))
    }

    fn expander_for_okm(
        &self,
        okm: &rustls::crypto::tls13::OkmBlock,
    ) -> Box<dyn rustls::crypto::tls13::HkdfExpander> {
        Box::new(WolfHkdfExpander {
            extracted_key: Zeroizing::new(okm.as_ref().to_vec()),
            hash_type: self.0.hmac_type(),
            hash_len: self.0.hash_len(),
        })
    }

    fn hmac_sign(
        &self,
        key: &rustls::crypto::tls13::OkmBlock,
        message: &[u8],
    ) -> rustls::crypto::hmac::Tag {
        // HMAC(key, message) used by the TLS 1.3 finished message MAC.
        //
        // Uses hkdf_extract(salt=key, ikm=message) which is mathematically identical
        // to HMAC(key, message) per RFC 5869 §2.2, PROVIDED the key is non-empty.
        // For an empty key, HKDF-Extract uses a zero vector of hash_len bytes as
        // the implicit salt, while HMAC zero-pads the key to the block size — these
        // differ.  In TLS 1.3, hmac_sign is called with a PRK-derived OkmBlock
        // which is always hash_len bytes and non-empty.
        //
        // Switch to HMAC::new/update/finalize once the wolfssl-wolfcrypt sha.rs
        // gains the copy() method (tracked separately as a wolfssl-wolfcrypt upstream issue).
        // The HMAC-via-HKDF-Extract substitution is only equivalent when the
        // key is non-empty (RFC 5869 §2.2).  Use a hard panic so the guard
        // fires in release builds, not just debug.
        if key.as_ref().is_empty() {
            panic!("HMAC-via-HKDF-Extract requires a non-empty key");
        }
        let typ = self.0.hmac_type();
        let hash_len = self.0.hash_len();
        let mut digest = vec![0u8; hash_len];
        // hkdf_extract can only fail on invalid hash type (impossible: our typ
        // comes from a statically-known WCShaHmac variant) or OOM.  The rustls
        // Hkdf::hmac_sign method returns a Tag directly — there is no Result.
        hkdf_extract(typ, Some(key.as_ref()), message, &mut digest)
            .unwrap_or_else(|e| unreachable!("hkdf_extract (hmac_sign) failed: wolfSSL error {}", e));
        rustls::crypto::hmac::Tag::new(&digest)
    }
}

/// Expander implementation that holds the extracted key material from HKDF extract phase
struct WolfHkdfExpander {
    extracted_key: Zeroizing<Vec<u8>>, // The pseudorandom key (PRK) output from HKDF-Extract
    hash_type: i32,                    // The wolfSSL hash algorithm identifier
    hash_len: usize,                   // Length of the hash function output
}

impl WolfHkdfExpander {
    fn new(extracted_key: Zeroizing<Vec<u8>>, hash_type: i32, hash_len: usize) -> Self {
        Self {
            extracted_key,
            hash_type,
            hash_len,
        }
    }
}

impl tls13::HkdfExpander for WolfHkdfExpander {
    fn expand_slice(
        &self,
        info: &[&[u8]],
        output: &mut [u8],
    ) -> Result<(), tls13::OutputLengthError> {
        if output.len() > 255 * self.hash_len {
            return Err(tls13::OutputLengthError);
        }

        // Fast path: single non-empty info slice — pass it directly with no allocation.
        let info_opt: Option<&[u8]> = if info.len() == 1 && !info[0].is_empty() {
            Some(info[0])
        } else if info.iter().all(|s| s.is_empty()) {
            // All-empty info slices are equivalent to no info.
            None
        } else {
            // Multiple non-trivial slices: concatenate into a temporary buffer.
            // This path is uncommon in practice (TLS 1.3 key schedule typically
            // passes 2–3 small slices totalling < 100 bytes).
            let concat: Vec<u8> = info.concat();
            let result = if concat.is_empty() {
                hkdf_expand(self.hash_type, &self.extracted_key, None, output)
            } else {
                hkdf_expand(self.hash_type, &self.extracted_key, Some(&concat), output)
            };
            return result.map_err(|_| tls13::OutputLengthError);
        };

        hkdf_expand(self.hash_type, &self.extracted_key, info_opt, output)
            .map_err(|_| tls13::OutputLengthError)?;

        Ok(())
    }

    fn expand_block(&self, info: &[&[u8]]) -> tls13::OkmBlock {
        let mut output = vec![0u8; self.hash_len];
        // expand_slice returns Err only when output.len() > 255*hash_len.
        // For expand_block the output is exactly hash_len bytes, which is always
        // within the limit.  The HkdfExpander::expand_block trait method returns
        // OkmBlock directly — there is no Result to propagate.
        self.expand_slice(info, &mut output)
            .unwrap_or_else(|_| unreachable!("expand_block output length exceeds 255*hash_len"));
        tls13::OkmBlock::new(&output)
    }

    fn hash_len(&self) -> usize {
        self.hash_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    };
    use hex_literal::hex;
    use wycheproof::{hkdf::TestName, TestResult};

    #[test]
    fn test_hkdf_sha256() {
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let expected_okm = hex!(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        );

        let hkdf = WCHkdfUsingHmac(WCShaHmac::Sha256);
        let expander = hkdf.extract_from_secret(Some(&salt), &ikm);

        let mut okm = vec![0u8; 42];
        expander.expand_slice(&[&info], &mut okm).unwrap();

        assert_eq!(&okm[..], &expected_okm[..]);
    }

    #[test]
    fn test_hkdf_sha384() {
        // RFC 5869 Appendix A.1 inputs applied to SHA-384, L=48.
        // Expected OKM cross-validated with Python hmac module (same params as
        // the SHA-256 vector; SHA-384 output computed independently).
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let expected_okm = hex!(
            "9b5097a86038b805309076a44b3a9f38063e25b516dcbf36"
            "9f394cfab43685f748b6457763e4f0204fc5d95d1da3e625"
        );

        let hkdf = WCHkdfUsingHmac(WCShaHmac::Sha384);
        let expander = hkdf.extract_from_secret(Some(&salt), &ikm);

        let mut okm = vec![0u8; 48];
        expander.expand_slice(&[&info], &mut okm).unwrap();

        assert_eq!(&okm[..], &expected_okm[..], "HKDF-SHA384 OKM mismatch");
    }

    #[test]
    fn test_hkdf_output_length_limit() {
        let hkdf = WCHkdfUsingHmac(WCShaHmac::Sha256);
        let expander = hkdf.extract_from_zero_ikm(None);

        let max_len = 255 * 32;
        let mut okm = vec![0u8; max_len];
        assert!(expander.expand_slice(&[&[]], &mut okm).is_ok());

        let mut okm = vec![0u8; max_len + 1];
        assert!(expander.expand_slice(&[&[]], &mut okm).is_err());
    }

    #[test]
    fn test_hkdf_zero_ikm() {
        let hkdf = WCHkdfUsingHmac(WCShaHmac::Sha256);
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");

        let expander = hkdf.extract_from_zero_ikm(Some(&salt));

        let mut okm1 = vec![0u8; 32];
        expander.expand_slice(&[&info], &mut okm1).unwrap();

        let expander2 = hkdf.extract_from_zero_ikm(Some(&salt));
        let mut okm2 = vec![0u8; 32];
        expander2.expand_slice(&[&info], &mut okm2).unwrap();

        assert_eq!(okm1, okm2);
    }

    #[test]
    fn test_hkdf_multiple_info_components() {
        let hkdf = WCHkdfUsingHmac(WCShaHmac::Sha256);
        let salt = hex!("000102030405060708090a0b0c");
        let info1 = hex!("f0f1f2f3");
        let info2 = hex!("f4f5f6f7");
        let info3 = hex!("f8f9");

        let expander = hkdf.extract_from_zero_ikm(Some(&salt));

        let mut okm1 = vec![0u8; 32];
        expander
            .expand_slice(&[&info1, &info2, &info3], &mut okm1)
            .unwrap();

        let mut info_concat = Vec::new();
        info_concat.extend_from_slice(&info1);
        info_concat.extend_from_slice(&info2);
        info_concat.extend_from_slice(&info3);

        let mut okm2 = vec![0u8; 32];
        expander.expand_slice(&[&info_concat], &mut okm2).unwrap();

        assert_eq!(okm1, okm2);
    }

    #[test]
    fn test_hkdf_wycheproof_sha256() {
        let suites: &[rustls::SupportedCipherSuite] =
            &[TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256];

        let test_set = wycheproof::hkdf::TestSet::load(TestName::HkdfSha256).unwrap();

        for suite in suites {
            let hkdf_provider = suite.tls13().unwrap().hkdf_provider;

            for test_group in &test_set.test_groups {
                for test in &test_group.tests {
                    let expander = hkdf_provider.extract_from_secret(Some(&test.salt), &test.ikm);
                    let mut okm = vec![0; test.size];
                    let result = expander.expand_slice(&[&test.info], &mut okm);

                    match &test.result {
                        TestResult::Acceptable | TestResult::Valid => {
                            assert!(result.is_ok());
                            assert_eq!(okm[..], test.okm[..], "Failed test: {}", test.comment);
                        }
                        TestResult::Invalid => {
                            assert!(result.is_err(), "Failed test: {}", test.comment)
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_hkdf_wycheproof_sha384() {
        let suites: &[rustls::SupportedCipherSuite] = &[TLS13_AES_256_GCM_SHA384];

        let test_set = wycheproof::hkdf::TestSet::load(TestName::HkdfSha384).unwrap();

        for suite in suites {
            let hkdf_provider = suite.tls13().unwrap().hkdf_provider;

            for test_group in &test_set.test_groups {
                for test in &test_group.tests {
                    let expander = hkdf_provider.extract_from_secret(Some(&test.salt), &test.ikm);
                    let mut okm = vec![0; test.size];
                    let result = expander.expand_slice(&[&test.info], &mut okm);

                    match &test.result {
                        TestResult::Acceptable | TestResult::Valid => {
                            assert!(result.is_ok());
                            assert_eq!(okm[..], test.okm[..], "Failed test: {}", test.comment);
                        }
                        TestResult::Invalid => {
                            assert!(result.is_err(), "Failed test: {}", test.comment)
                        }
                    }
                }
            }
        }
    }
}
