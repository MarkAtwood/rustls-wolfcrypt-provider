use alloc::{boxed::Box, vec, vec::Vec};
use rustls::crypto;
use wolfssl_wolfcrypt::hkdf::hkdf_extract;
use wolfssl_wolfcrypt::hmac::HMAC;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug)]
pub enum WCShaHmac {
    Sha256,
    Sha384,
}

impl WCShaHmac {
    /// Return the wolfSSL hash-type tag (`HMAC::TYPE_SHA256` / `TYPE_SHA384`)
    /// as an `i32`, matching the type accepted by wolfssl-wolfcrypt's HMAC and
    /// HKDF APIs.  This is an ABI constant from the C layer; callers must not
    /// interpret the numeric value independently.
    pub fn hmac_type(&self) -> i32 {
        match self {
            WCShaHmac::Sha256 => HMAC::TYPE_SHA256,
            WCShaHmac::Sha384 => HMAC::TYPE_SHA384,
        }
    }

    pub fn hash_len(&self) -> usize {
        // The digest length is statically known from the variant; no C call needed.
        match self {
            WCShaHmac::Sha256 => 32,
            WCShaHmac::Sha384 => 48,
        }
    }
}

impl crypto::hmac::Hmac for WCShaHmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(WCHmacKey {
            key: Zeroizing::new(key.to_vec()),
            variant: *self,
        })
    }

    fn hash_output_len(&self) -> usize {
        self.hash_len()
    }
}

struct WCHmacKey {
    key: Zeroizing<Vec<u8>>,
    variant: WCShaHmac,
}

impl crypto::hmac::Key for WCHmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let typ = self.variant.hmac_type();
        let digest_len = self.variant.hash_len();

        // HMAC(key, first || middle... || last).
        //
        // We use hkdf_extract(salt=key, ikm=data) which is mathematically identical
        // to HMAC(key, data) per RFC 5869 §2.2, PROVIDED the key is non-empty.
        // For an empty key, HKDF-Extract uses a zero vector of hash_len bytes as
        // the implicit salt, while HMAC zero-pads the key to the block size (64
        // bytes for SHA-256) — these differ.  In all TLS 1.2/1.3 paths the HMAC
        // key is a non-empty derived PRK, so this invariant always holds.
        //
        // Switch to HMAC::new/update/finalize once the wolfssl-wolfcrypt sha.rs
        // gains the copy() method needed by hash/sha256.rs and hash/sha384.rs
        // (tracked separately as a wolfssl-wolfcrypt upstream issue).
        // The HMAC-via-HKDF-Extract substitution is only equivalent when the
        // key is non-empty (RFC 5869 §2.2).  This invariant is guaranteed by
        // the TLS 1.2/1.3 key schedule, which never produces an empty HMAC key.
        // Use a hard panic (not debug_assert) so the guard fires in release builds too.
        if self.key.is_empty() {
            panic!("HMAC-via-HKDF-Extract requires a non-empty key");
        }
        let mut data: Vec<u8> = Vec::with_capacity(
            first.len() + middle.iter().map(|s| s.len()).sum::<usize>() + last.len(),
        );
        data.extend_from_slice(first);
        for chunk in middle {
            data.extend_from_slice(chunk);
        }
        data.extend_from_slice(last);

        let mut digest = vec![0u8; digest_len];
        // hkdf_extract can only fail on invalid hash type (impossible: our typ
        // comes from a statically-known WCShaHmac variant) or OOM.  sign_concat
        // returns a Tag directly — there is no Result to propagate.
        hkdf_extract(typ, Some(&self.key), &data, &mut digest)
            .unwrap_or_else(|e| unreachable!("hkdf_extract (sign_concat) failed: wolfSSL error {}", e));
        crypto::hmac::Tag::new(&digest)
    }

    fn tag_len(&self) -> usize {
        self.variant.hash_len()
    }
}
