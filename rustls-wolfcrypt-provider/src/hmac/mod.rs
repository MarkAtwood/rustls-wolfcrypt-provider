use alloc::{boxed::Box, vec::Vec};
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
        let typ = self.variant.hmac_type();
        let digest_len = self.variant.hash_len();

        // HMAC(key, first || middle... || last).
        //
        // We use hkdf_extract(salt=key, ikm=data) which is mathematically identical
        // to HMAC(key, data) per RFC 5869 §2.2. Direct HMAC::new/update/finalize
        // is unavailable here: the Hmac C struct layout differs between the
        // wolfssl-wolfcrypt (5.9.1) and wolfcrypt-rs (5.7.6) static libraries that
        // are both linked during this transition period, causing wc_HmacFinal to
        // receive BAD_FUNC_ARG (-173) due to ABI mismatch. hkdf_extract uses
        // wolfSSL's own internal HMAC path and is not affected by this mismatch.
        // This workaround will be removed when wolfcrypt-rs is fully eliminated.
        let mut data: Vec<u8> = Vec::with_capacity(
            first.len() + middle.iter().map(|s| s.len()).sum::<usize>() + last.len()
        );
        data.extend_from_slice(first);
        for chunk in middle {
            data.extend_from_slice(chunk);
        }
        data.extend_from_slice(last);

        let mut digest = Vec::with_capacity(digest_len);
        digest.resize(digest_len, 0u8);
        hkdf_extract(typ, Some(&self.key), &data, &mut digest)
            .expect("hkdf_extract (HMAC sign_concat) failed");
        crypto::hmac::Tag::new(&digest)
    }

    fn tag_len(&self) -> usize {
        self.variant.hash_len()
    }
}
