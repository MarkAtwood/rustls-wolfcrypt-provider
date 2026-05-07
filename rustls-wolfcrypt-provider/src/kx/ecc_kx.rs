/// Macro that generates the full ECC key-exchange implementation for a NIST curve.
/// The three supported curves (P-256, P-384, P-521) are structurally identical;
/// they differ only in:
///   - the struct name
///   - the coordinate size (field element size in bytes)
///   - the wolfSSL curve ID constant (passed as a const expression)
///   - the constructor function name (used by the outer `kx.rs` define_kx_group! macro)
///
/// Using a macro here eliminates ~80 lines of duplicated code per curve.
/// Callers must import `wolfssl_wolfcrypt::ecc::ECC` to reference `ECC::SECP256R1` etc.
/// as the `curve_id` argument; the macro uses fully-qualified paths internally.
macro_rules! define_ecc_kx {
    (
        struct_name:   $struct_name:ident,
        coord_size:    $coord_size:expr,
        curve_id:      $curve_id:expr,
        named_group:   $named_group:expr,
        constructor:   $constructor:ident $(,)?
    ) => {
        // NOTE: These constants are emitted at module scope by every invocation of
        // define_ecc_kx!. Each invocation MUST be in its own module (as sec256r1,
        // sec384r1, and sec521r1 are). A second invocation in the same module would
        // produce a compile error due to duplicate const definitions.
        const COORD_SIZE: usize = $coord_size;
        const PUB_KEY_SIZE: usize = 1 + COORD_SIZE + COORD_SIZE;
        const COORD_SIZE_U32: u32 = COORD_SIZE as u32; // always 32, 48, or 66

        pub struct $struct_name {
            priv_key_bytes: ::zeroize::Zeroizing<::alloc::vec::Vec<u8>>,
            pub_key_bytes: ::alloc::boxed::Box<[u8]>,
        }

        impl $struct_name {
            pub fn $constructor() -> Result<Self, ::rustls::Error> {
                let mut rng = ::wolfssl_wolfcrypt::random::RNG::new()
                    .map_err(|_| ::rustls::Error::General("RNG::new failed".into()))?;

                let curve_size = ::wolfssl_wolfcrypt::ecc::ECC::get_curve_size_from_id($curve_id)
                    .map_err(|_| {
                    ::rustls::Error::General("get_curve_size_from_id failed".into())
                })?;

                let mut key = ::wolfssl_wolfcrypt::ecc::ECC::generate_ex(
                    curve_size, &mut rng, $curve_id, None, None,
                )
                .map_err(|_| ::rustls::Error::General("ECC::generate_ex failed".into()))?;

                let mut priv_key_raw = ::zeroize::Zeroizing::new([0u8; COORD_SIZE]);
                let priv_len = key
                    .export_private(&mut *priv_key_raw)
                    .map_err(|_| ::rustls::Error::General("export_private failed".into()))?;
                if priv_len != COORD_SIZE {
                    return Err(::rustls::Error::General(
                        "export_private returned unexpected key length".into(),
                    ));
                }

                let mut qx = [0u8; COORD_SIZE];
                let mut qx_len = COORD_SIZE_U32;
                let mut qy = [0u8; COORD_SIZE];
                let mut qy_len = COORD_SIZE_U32;
                key.export_public(&mut qx, &mut qx_len, &mut qy, &mut qy_len)
                    .map_err(|_| ::rustls::Error::General("export_public failed".into()))?;
                if qx_len as usize != COORD_SIZE || qy_len as usize != COORD_SIZE {
                    return Err(::rustls::Error::General(
                        "export_public returned unexpected coordinate length".into(),
                    ));
                }

                // Build uncompressed public key: 0x04 || X || Y
                let mut pub_key_bytes = [0u8; PUB_KEY_SIZE];
                pub_key_bytes[0] = 0x04;
                pub_key_bytes[1..1 + COORD_SIZE].copy_from_slice(&qx);
                pub_key_bytes[1 + COORD_SIZE..PUB_KEY_SIZE].copy_from_slice(&qy);

                Ok($struct_name {
                    priv_key_bytes: ::zeroize::Zeroizing::new(
                        ::alloc::vec::Vec::from(*priv_key_raw),
                    ),
                    pub_key_bytes: ::alloc::boxed::Box::new(pub_key_bytes),
                })
            }

            pub fn derive_shared_secret(
                &self,
                peer_pub_key: &[u8],
            ) -> Result<::zeroize::Zeroizing<::alloc::vec::Vec<u8>>, ::rustls::Error> {
                if peer_pub_key.len() != PUB_KEY_SIZE {
                    return Err(::rustls::Error::General(
                        "Invalid peer public key length".into(),
                    ));
                }

                let mut rng = ::wolfssl_wolfcrypt::random::RNG::new()
                    .map_err(|_| ::rustls::Error::General("RNG::new failed".into()))?;

                // Import our private key with our own X9.63 public key as the public half.
                let mut priv_key = ::wolfssl_wolfcrypt::ecc::ECC::import_private_key_ex(
                    &self.priv_key_bytes,
                    &self.pub_key_bytes,
                    $curve_id,
                    None,
                    None,
                )
                .map_err(|_| ::rustls::Error::General("Failed to import ECC private key".into()))?;

                // Import peer public key from uncompressed X9.63 point (0x04 || X || Y).
                // wc_ecc_import_x963 validates that the point is on the named curve,
                // rejecting off-curve, low-order, and identity points. This is the
                // equivalent of the explicit check performed for X25519 via check_public().
                let mut pub_key =
                    ::wolfssl_wolfcrypt::ecc::ECC::import_x963(peer_pub_key, None, None).map_err(
                        |_| ::rustls::Error::General("Failed to import peer ECC public key".into()),
                    )?;

                priv_key.set_rng(&mut rng).map_err(|_| {
                    ::rustls::Error::General("Failed to set RNG on private key".into())
                })?;
                pub_key.set_rng(&mut rng).map_err(|_| {
                    ::rustls::Error::General("Failed to set RNG on public key".into())
                })?;

                // Use Zeroizing so the shared secret is wiped from memory when dropped.
                let mut out = ::zeroize::Zeroizing::new([0u8; COORD_SIZE]);
                priv_key
                    .shared_secret(&mut pub_key, &mut *out)
                    .map_err(|_| {
                        ::rustls::Error::General("Failed to compute ECC shared secret".into())
                    })?;

                // Wrap the heap copy in Zeroizing so the secret is wiped when the
                // Vec is dropped, not just the stack buffer above.
                Ok(::zeroize::Zeroizing::new(::alloc::vec::Vec::from(*out)))
            }
        }

        impl ::rustls::crypto::ActiveKeyExchange for $struct_name {
            fn complete(
                self: ::alloc::boxed::Box<Self>,
                peer_pub_key: &[u8],
            ) -> Result<::rustls::crypto::SharedSecret, ::rustls::Error> {
                let secret = self.derive_shared_secret(peer_pub_key)?;
                Ok(::rustls::crypto::SharedSecret::from(secret.as_slice()))
            }

            fn pub_key(&self) -> &[u8] {
                &self.pub_key_bytes
            }

            fn group(&self) -> ::rustls::NamedGroup {
                $named_group
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use ::rustls::crypto::ActiveKeyExchange;

            #[test]
            fn test_kx_roundtrip() {
                let alice = ::alloc::boxed::Box::new($struct_name::$constructor().unwrap());
                let bob = ::alloc::boxed::Box::new($struct_name::$constructor().unwrap());

                assert_eq!(
                    alice.derive_shared_secret(bob.pub_key()).unwrap(),
                    bob.derive_shared_secret(alice.pub_key()).unwrap(),
                );
            }
        }
    };
}

pub(crate) use define_ecc_kx;
