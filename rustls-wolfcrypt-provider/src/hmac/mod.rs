use alloc::{boxed::Box, vec, vec::Vec};
use rustls::crypto;
use wolfssl_wolfcrypt::hkdf::hkdf_extract;
use wolfssl_wolfcrypt::hmac::HMAC;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub enum WCShaHmac {
    Sha256,
    Sha384,
}

impl WCShaHmac {
    pub fn hmac_type(&self) -> i32 {
        match self {
            WCShaHmac::Sha256 => HMAC::TYPE_SHA256,
            WCShaHmac::Sha384 => HMAC::TYPE_SHA384,
        }
    }

    pub fn hash_len(&self) -> usize {
        HMAC::get_hmac_size_by_type(self.hmac_type())
            .expect("get_hmac_size_by_type failed")
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
        // Accumulate all data, then compute HMAC(key, data).
        // We use hkdf_extract(salt=key, ikm=data) which is mathematically
        // equivalent to HMAC(key, data) and avoids the HMAC struct ABI
        // mismatch between wolfssl-wolfcrypt and wolfcrypt-rs builds.
        let typ = self.variant.hmac_type();
        let digest_len = self.variant.hash_len();

        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(first);
        for m in middle {
            data.extend_from_slice(m);
        }
        data.extend_from_slice(last);

        let mut digest = vec![0u8; digest_len];
        hkdf_extract(typ, Some(&self.key), &data, &mut digest)
            .expect("hkdf_extract (HMAC) failed");
        crypto::hmac::Tag::new(&digest)
    }

    fn tag_len(&self) -> usize {
        self.variant.hash_len()
    }
}
