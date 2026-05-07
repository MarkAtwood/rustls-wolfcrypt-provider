use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;
use wolfssl_wolfcrypt::curve25519::Curve25519Key;
use wolfssl_wolfcrypt::random::RNG;
use zeroize::Zeroizing;

// X25519 uses little-endian byte ordering throughout.
const BIG_ENDIAN: bool = false;

pub struct KeyExchangeX25519 {
    pub_key_bytes: Box<[u8]>,
    priv_key_bytes: Zeroizing<Vec<u8>>,
}

impl KeyExchangeX25519 {
    pub fn use_curve25519() -> Result<Self, rustls::Error> {
        let mut rng = RNG::new().map_err(|_| rustls::Error::General("RNG::new failed".into()))?;

        // Generate an ephemeral Curve25519 key pair.
        let mut key = Curve25519Key::generate(&mut rng)
            .map_err(|_| rustls::Error::General("Curve25519Key::generate failed".into()))?;

        let mut priv_key_raw = Zeroizing::new([0u8; Curve25519Key::KEYSIZE]);
        let mut pub_key_raw = [0u8; Curve25519Key::KEYSIZE];

        // Export raw private and public key bytes (little-endian).
        key.export_key_raw_ex(&mut *priv_key_raw, &mut pub_key_raw, BIG_ENDIAN)
            .map_err(|_| rustls::Error::General("export_key_raw_ex failed".into()))?;

        Ok(KeyExchangeX25519 {
            pub_key_bytes: Box::new(pub_key_raw),
            priv_key_bytes: Zeroizing::new(Vec::from(*priv_key_raw)),
        })
    }

    pub fn derive_shared_secret(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, rustls::Error> {
        if peer_pub_key.len() != Curve25519Key::KEYSIZE {
            return Err(rustls::Error::General(
                "Invalid Curve25519 peer public key length".into(),
            ));
        }

        // Validate the peer public key before using it.
        Curve25519Key::check_public(peer_pub_key, BIG_ENDIAN)
            .map_err(|_| rustls::Error::General("Invalid Curve25519 public key".into()))?;

        // Import the peer's public key.
        let mut pub_key = Curve25519Key::import_public_ex(peer_pub_key, BIG_ENDIAN)
            .map_err(|_| rustls::Error::General("Failed to import Curve25519 public key".into()))?;

        // Import our private key.
        // import_private_ex imports only the private scalar.
        let mut priv_key = Curve25519Key::import_private_ex(&self.priv_key_bytes, BIG_ENDIAN)
            .map_err(|_| {
                rustls::Error::General("Failed to import Curve25519 private key".into())
            })?;

        // When wolfSSL is built with WOLFSSL_CURVE25519_BLINDING, shared-secret
        // computation requires an RNG on the private key struct for the blinding
        // scalar.  Attach a fresh RNG so the blinded scalar-multiply succeeds.
        let mut rng = RNG::new()
            .map_err(|_| rustls::Error::General("RNG::new for blinding failed".into()))?;
        priv_key
            .set_rng(&mut rng)
            .map_err(|_| rustls::Error::General("curve25519_set_rng failed".into()))?;

        // Compute the ECDH shared secret (little-endian output).
        // Zeroizing ensures the secret is wiped from memory when it is dropped.
        let mut out = Zeroizing::new([0u8; Curve25519Key::KEYSIZE]);
        Curve25519Key::shared_secret_ex(&mut priv_key, &mut pub_key, &mut *out, BIG_ENDIAN)
            .map_err(|e| {
                rustls::Error::General(format!("Failed to compute Curve25519 shared secret: wolfSSL error {}", e))
            })?;

        // Wrap the heap copy in Zeroizing so the secret is wiped when the
        // Vec is dropped, not just the stack buffer above.
        Ok(Zeroizing::new(Vec::from(*out)))
    }
}

impl rustls::crypto::ActiveKeyExchange for KeyExchangeX25519 {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<rustls::crypto::SharedSecret, rustls::Error> {
        let secret = self.derive_shared_secret(peer_pub_key)?;
        Ok(rustls::crypto::SharedSecret::from(secret.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::ActiveKeyExchange;

    #[test]
    fn test_curve25519_kx() {
        let alice = Box::new(KeyExchangeX25519::use_curve25519().unwrap());
        let bob = Box::new(KeyExchangeX25519::use_curve25519().unwrap());

        // Both sides must derive the same shared secret.
        assert_eq!(
            alice.derive_shared_secret(bob.pub_key()).unwrap(),
            bob.derive_shared_secret(alice.pub_key()).unwrap(),
        );
    }
}
