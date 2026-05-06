use alloc::boxed::Box;
use wolfssl_wolfcrypt::curve25519::Curve25519Key;
use wolfssl_wolfcrypt::random::RNG;
use zeroize::Zeroizing;

// X25519 uses little-endian byte ordering throughout.
const BIG_ENDIAN: bool = false;

pub struct KeyExchangeX25519 {
    pub_key_bytes: Box<[u8]>,
    priv_key_bytes: Zeroizing<Box<[u8]>>,
}

impl KeyExchangeX25519 {
    pub fn use_curve25519() -> Result<Self, rustls::Error> {
        let mut rng = RNG::new()
            .map_err(|_| rustls::Error::General("RNG::new failed".into()))?;

        // Generate an ephemeral Curve25519 key pair.
        let mut key = Curve25519Key::generate(&mut rng)
            .map_err(|_| rustls::Error::General("Curve25519Key::generate failed".into()))?;

        let mut priv_key_raw = [0u8; Curve25519Key::KEYSIZE];
        let mut pub_key_raw = [0u8; Curve25519Key::KEYSIZE];

        // Export raw private and public key bytes (little-endian).
        key.export_key_raw_ex(&mut priv_key_raw, &mut pub_key_raw, BIG_ENDIAN)
            .map_err(|_| rustls::Error::General("export_key_raw_ex failed".into()))?;

        Ok(KeyExchangeX25519 {
            pub_key_bytes: Box::new(pub_key_raw),
            priv_key_bytes: Zeroizing::new(Box::new(priv_key_raw)),
        })
    }

    pub fn derive_shared_secret(&self, peer_pub_key: &[u8]) -> Result<Box<[u8]>, rustls::Error> {
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
        // import_private_ex takes only the private scalar; it does not need the public key.
        let mut priv_key = Curve25519Key::import_private_ex(&self.priv_key_bytes, BIG_ENDIAN)
            .map_err(|_| rustls::Error::General("Failed to import Curve25519 private key".into()))?;

        // Compute the ECDH shared secret (little-endian output).
        let mut out = [0u8; Curve25519Key::KEYSIZE];
        Curve25519Key::shared_secret_ex(&mut priv_key, &mut pub_key, &mut out, BIG_ENDIAN)
            .map_err(|_| rustls::Error::General("Failed to compute Curve25519 shared secret".into()))?;

        Ok(Box::new(out))
    }
}

impl rustls::crypto::ActiveKeyExchange for KeyExchangeX25519 {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<rustls::crypto::SharedSecret, rustls::Error> {
        let secret = self.derive_shared_secret(peer_pub_key)?;
        Ok(rustls::crypto::SharedSecret::from(&*secret))
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
