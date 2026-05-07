#![cfg(ed25519)]

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use pkcs8::PrivateKeyInfo;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use wolfssl_wolfcrypt::ed25519::Ed25519 as WcEd25519;
use zeroize::Zeroizing;

const ALL_EDDSA_SCHEMES: &[SignatureScheme] = &[SignatureScheme::ED25519];

/// Ed25519 private key size (private seed only, 32 bytes).
const PRIV_KEY_SIZE: usize = WcEd25519::KEY_SIZE;
/// Ed25519 public key size (32 bytes).
const PUB_KEY_SIZE: usize = WcEd25519::PUB_KEY_SIZE;

#[derive(Clone)]
pub struct Ed25519PrivateKey {
    priv_key: Arc<Zeroizing<Vec<u8>>>,
    /// Derived public key cached at import time to avoid per-sign scalar multiply.
    pub_key: Arc<[u8; PUB_KEY_SIZE]>,
    algo: SignatureAlgorithm,
}

impl fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519PrivateKey")
            .field("algo", &self.algo)
            .finish_non_exhaustive()
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for Ed25519PrivateKey {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let pkcs8_der = der.secret_pkcs8_der();

                // Parse the PKCS#8 structure to extract the raw private key bytes.
                // For Ed25519 (RFC 8410), PrivateKeyInfo::private_key contains a
                // DER OCTET STRING wrapping the 32-byte private key: [0x04, 0x20, <32 bytes>].
                let pki = PrivateKeyInfo::try_from(pkcs8_der)
                    .map_err(|_| rustls::Error::General("Failed to parse PKCS#8".into()))?;

                // Validate and unwrap the inner OCTET STRING (tag 0x04, length 0x20 = 32).
                if pki.private_key.len() < 2
                    || pki.private_key[0] != 0x04
                    || pki.private_key[1] != (PRIV_KEY_SIZE as u8)
                    || pki.private_key.len() != 2 + PRIV_KEY_SIZE
                {
                    return Err(rustls::Error::General(
                        "Invalid Ed25519 private key encoding".into(),
                    ));
                }
                let raw_priv = &pki.private_key[2..2 + PRIV_KEY_SIZE];

                // Derive the public key once at import time and cache it.
                // This avoids a scalar multiply on every sign() call.
                let mut ed = WcEd25519::new()
                    .map_err(|_| rustls::Error::General("Ed25519 init failed".into()))?;
                ed.import_private_only(raw_priv).map_err(|_| {
                    rustls::Error::General("Ed25519 import_private_only failed".into())
                })?;
                let mut pub_buf = [0u8; PUB_KEY_SIZE];
                ed.make_public(&mut pub_buf)
                    .map_err(|_| rustls::Error::General("Ed25519 make_public failed".into()))?;

                Ok(Self {
                    priv_key: Arc::new(Zeroizing::new(raw_priv.to_vec())),
                    pub_key: Arc::new(pub_buf),
                    algo: SignatureAlgorithm::ED25519,
                })
            }
            _ => Err(rustls::Error::General(
                "Unsupported private key format".into(),
            )),
        }
    }
}

impl SigningKey for Ed25519PrivateKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        ALL_EDDSA_SCHEMES.iter().find_map(|&scheme| {
            if offered.contains(&scheme) {
                Some(Box::new(Ed25519Signer {
                    priv_key: self.priv_key.clone(),
                    pub_key: self.pub_key.clone(),
                    scheme,
                }) as Box<dyn Signer>)
            } else {
                None
            }
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.algo
    }
}

#[derive(Clone)]
pub struct Ed25519Signer {
    priv_key: Arc<Zeroizing<Vec<u8>>>,
    /// Cached public key avoids re-deriving it via scalar multiply on each sign.
    pub_key: Arc<[u8; PUB_KEY_SIZE]>,
    scheme: SignatureScheme,
}

impl fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut ed =
            WcEd25519::new().map_err(|_| rustls::Error::General("Ed25519 init failed".into()))?;

        // Import private seed plus the cached public key in a single call.
        // This skips the make_public scalar multiply that would occur if we
        // imported the private key alone. trusted=true because we computed
        // pub_key ourselves from the private seed at import time.
        ed.import_private_key_ex(&self.priv_key, Some(self.pub_key.as_ref()), true)
            .map_err(|e| {
                rustls::Error::General(alloc::format!(
                    "Ed25519 import_private_key_ex failed: {}",
                    e
                ))
            })?;

        let mut sig = [0u8; WcEd25519::SIG_SIZE];
        let sig_len = ed
            .sign_msg(message, &mut sig)
            .map_err(|e| rustls::Error::General(alloc::format!("Ed25519 sign failed: {}", e)))?;

        Ok(sig[..sig_len].to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::sign::SigningKey;
    use wolfssl_wolfcrypt::ed25519::Ed25519 as WcEd25519;
    use wolfssl_wolfcrypt::random::RNG;

    #[test]
    fn test_eddsa_sign_verify_roundtrip() {
        // Generate a key using wolfssl-wolfcrypt
        let mut rng = RNG::new().expect("RNG::new failed");
        let mut key = WcEd25519::generate(&mut rng).expect("generate failed");

        // Export private seed
        let mut priv_raw = [0u8; WcEd25519::KEY_SIZE];
        key.export_private_only(&mut priv_raw)
            .expect("export_private_only failed");

        // Export public key
        let mut pub_raw = [0u8; WcEd25519::PUB_KEY_SIZE];
        key.make_public(&mut pub_raw).expect("make_public failed");

        // Build PKCS8 DER: 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32 bytes>
        let mut pkcs8_der = [0u8; 48];
        pkcs8_der[0..16].copy_from_slice(&[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ]);
        pkcs8_der[16..48].copy_from_slice(&priv_raw);

        // Create Ed25519PrivateKey
        let private_key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(pkcs8_der.as_slice()));
        let private_key = Ed25519PrivateKey::try_from(&private_key_der)
            .expect("Ed25519PrivateKey::try_from failed");

        // Sign
        let signer = private_key
            .choose_scheme(&[SignatureScheme::ED25519])
            .expect("choose_scheme failed");
        let message = b"test message";
        let signature = signer.sign(message).expect("sign failed");
        assert_eq!(signature.len(), 64, "signature should be 64 bytes");

        // Verify using our verify code
        use crate::verify::eddsa::Ed25519 as Ed25519Verifier;
        use rustls::pki_types::SignatureVerificationAlgorithm;
        let verifier = Ed25519Verifier;
        let result = verifier.verify_signature(&pub_raw, message, &signature);
        assert!(result.is_ok(), "verification should succeed: {:?}", result);
    }
}
