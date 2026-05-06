use alloc::boxed::Box;
use wolfssl_wolfcrypt::ecc::ECC;
use wolfssl_wolfcrypt::random::RNG;
use zeroize::Zeroizing;

const COORD_SIZE: usize = 32;
const PUB_KEY_SIZE: usize = 1 + COORD_SIZE + COORD_SIZE; // 65

pub struct KeyExchangeSecP256r1 {
    priv_key_bytes: Zeroizing<Box<[u8]>>,
    pub_key_bytes: Box<[u8]>,
}

impl KeyExchangeSecP256r1 {
    pub fn use_secp256r1() -> Result<Self, rustls::Error> {
        let mut rng = RNG::new()
            .map_err(|_| rustls::Error::General("RNG::new failed".into()))?;

        let curve_size = ECC::get_curve_size_from_id(ECC::SECP256R1)
            .map_err(|_| rustls::Error::General("get_curve_size_from_id failed".into()))?;

        let mut key = ECC::generate_ex(curve_size, &mut rng, ECC::SECP256R1, None, None)
            .map_err(|_| rustls::Error::General("ECC::generate_ex failed".into()))?;

        let mut priv_key_raw = [0u8; COORD_SIZE];
        key.export_private(&mut priv_key_raw)
            .map_err(|_| rustls::Error::General("export_private failed".into()))?;

        let mut qx = [0u8; COORD_SIZE];
        let mut qx_len = COORD_SIZE as u32;
        let mut qy = [0u8; COORD_SIZE];
        let mut qy_len = COORD_SIZE as u32;
        key.export_public(&mut qx, &mut qx_len, &mut qy, &mut qy_len)
            .map_err(|_| rustls::Error::General("export_public failed".into()))?;

        // Build uncompressed public key: 0x04 || X || Y
        let mut pub_key_bytes = [0x04u8; PUB_KEY_SIZE];
        pub_key_bytes[1..1 + COORD_SIZE].copy_from_slice(&qx);
        pub_key_bytes[1 + COORD_SIZE..PUB_KEY_SIZE].copy_from_slice(&qy);

        Ok(KeyExchangeSecP256r1 {
            priv_key_bytes: Zeroizing::new(Box::new(priv_key_raw)),
            pub_key_bytes: Box::new(pub_key_bytes),
        })
    }

    pub fn derive_shared_secret(&self, peer_pub_key: &[u8]) -> Result<Box<[u8]>, rustls::Error> {
        if peer_pub_key.len() != PUB_KEY_SIZE {
            return Err(rustls::Error::General(
                "Invalid peer public key length".into(),
            ));
        }

        let mut rng = RNG::new()
            .map_err(|_| rustls::Error::General("RNG::new failed".into()))?;

        // Import our private key with our own X9.63 public key as the public half.
        let mut priv_key = ECC::import_private_key_ex(
            &self.priv_key_bytes,
            &self.pub_key_bytes,
            ECC::SECP256R1,
            None,
            None,
        )
        .map_err(|_| rustls::Error::General("Failed to import ECC private key".into()))?;

        // Import peer public key from raw X/Y components (skip the 0x04 prefix).
        let qx = &peer_pub_key[1..1 + COORD_SIZE];
        let qy = &peer_pub_key[1 + COORD_SIZE..PUB_KEY_SIZE];
        let mut pub_key = ECC::import_unsigned(qx, qy, &[], ECC::SECP256R1, None, None)
            .map_err(|_| rustls::Error::General("Failed to import peer ECC public key".into()))?;

        priv_key
            .set_rng(&mut rng)
            .map_err(|_| rustls::Error::General("Failed to set RNG on private key".into()))?;
        pub_key
            .set_rng(&mut rng)
            .map_err(|_| rustls::Error::General("Failed to set RNG on public key".into()))?;

        let mut out = [0u8; COORD_SIZE];
        priv_key
            .shared_secret(&mut pub_key, &mut out)
            .map_err(|_| rustls::Error::General("Failed to compute ECC shared secret".into()))?;

        Ok(Box::new(out))
    }
}

impl rustls::crypto::ActiveKeyExchange for KeyExchangeSecP256r1 {
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
        rustls::NamedGroup::secp256r1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::ActiveKeyExchange;

    #[test]
    fn test_secp256r1_kx() {
        let alice = Box::new(KeyExchangeSecP256r1::use_secp256r1().unwrap());
        let bob = Box::new(KeyExchangeSecP256r1::use_secp256r1().unwrap());

        assert_eq!(
            alice.derive_shared_secret(bob.pub_key()).unwrap(),
            bob.derive_shared_secret(alice.pub_key()).unwrap(),
        )
    }
}
