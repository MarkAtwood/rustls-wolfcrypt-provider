use alloc::boxed::Box;
use alloc::vec::Vec;
use rustls::crypto;
use wolfssl_wolfcrypt::prf::{prf, PRF_HASH_SHA256, PRF_HASH_SHA384};

use crate::hmac::WCShaHmac;

#[derive(Debug)]
pub struct WCPrfUsingHmac(pub WCShaHmac);

impl crypto::tls12::Prf for WCPrfUsingHmac {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn crypto::ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        let secret = kx.complete(peer_pub_key)?;
        wc_prf(output, secret.secret_bytes(), label, seed, self.0)
    }

    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        // rustls::crypto::tls12::Prf::for_secret is infallible (no Result return).
        // wc_PRF only fails on allocation failure or invalid parameters; both are
        // abort-level in a TLS handshake context.
        wc_prf(output, secret, label, seed, self.0).expect("wc_PRF failed")
    }
}

fn wc_prf(
    output: &mut [u8],
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    hmac_variant: WCShaHmac,
) -> Result<(), rustls::Error> {
    let hash_type = match hmac_variant {
        WCShaHmac::Sha256 => PRF_HASH_SHA256,
        WCShaHmac::Sha384 => PRF_HASH_SHA384,
    };

    // wc_PRF takes a combined seed; TLS PRF is defined as PRF(secret, label || seed)
    let mut combined_seed: Vec<u8> = Vec::with_capacity(label.len() + seed.len());
    combined_seed.extend_from_slice(label);
    combined_seed.extend_from_slice(seed);

    prf(secret, &combined_seed, hash_type, output)
        .map_err(|_| rustls::Error::General("wc_PRF failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rustls::crypto::hmac::Hmac;

    #[test]
    fn test_hmac_variants() {
        // Key: "this is my key"
        // Message (concatenated): "fake it" + "till you" + "make" + "it" = "fake ittill youmakeit"
        // Expected values cross-validated with:
        //   printf "fake ittill youmakeit" | openssl dgst -sha256 -hmac "this is my key"
        //   printf "fake ittill youmakeit" | openssl dgst -sha384 -hmac "this is my key"
        let test_cases: &[(WCShaHmac, &[u8])] = &[
            (
                WCShaHmac::Sha256,
                &hex!("b49c38fefe72ea5d7a38e81b38f56d272642b9f63a53229f93d3a95fd3b327c9"),
            ),
            (
                WCShaHmac::Sha384,
                &hex!("aec2deee7ee331147fbb0bfdb06cae125a8979dcc2fea091117202fdcc76094c410310788a7d4f49297b40a6a5a0864b"),
            ),
        ];

        for (variant, expected) in test_cases {
            let hmac = *variant;
            let key = b"this is my key";
            let hash = hmac.with_key(key);

            let tag = hash.sign_concat(
                b"fake it",
                &[b"till you".as_ref(), b"make".as_ref()],
                b"it",
            );

            assert_eq!(
                tag.as_ref(),
                *expected,
                "HMAC-{} known-answer mismatch",
                if matches!(variant, WCShaHmac::Sha256) { "SHA256" } else { "SHA384" }
            );
        }
    }
}
