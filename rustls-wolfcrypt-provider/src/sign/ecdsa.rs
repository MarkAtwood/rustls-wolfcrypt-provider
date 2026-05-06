use crate::alloc::string::ToString;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use wolfssl_wolfcrypt::ecc::ECC;
use wolfssl_wolfcrypt::ecdsa::{
    P256SigningKey, P256Signature, P384SigningKey, P384Signature, P521SigningKey, P521Signature,
};
use wolfssl_wolfcrypt::random::RNG;
use signature::SignerMut;
use zeroize::Zeroizing;

/// A unified ECDSA signing key that supports P-256, P-384, P-521.
///
/// Stores the raw private scalar bytes and the x963-encoded public key bytes
/// so that a per-curve signing key can be reconstructed on each `sign()` call
/// without retaining unsafe state across threads.
#[derive(Clone)]
pub struct EcdsaSigningKey {
    /// Raw private scalar `d` (big-endian), exactly field_size bytes.
    priv_key: Arc<Zeroizing<Vec<u8>>>,
    /// Uncompressed X9.63 public key (0x04 || x || y).
    pub_x963: Arc<Vec<u8>>,
    /// The signature scheme (determines curve and hash).
    scheme: SignatureScheme,
}

impl fmt::Debug for EcdsaSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSigningKey")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

/// OID bytes for id-Ed25519 (1.3.101.112) in a 3-byte DER OID encoding: 06 03 2b 65 70
/// Ed25519 PKCS#8 DER: 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32 bytes>
/// The OID bytes (2b 65 70) start at offset 10 in a standard Ed25519 PKCS#8.
const OID_ED25519_BYTES: &[u8] = &[0x2b, 0x65, 0x70];

/// OID bytes for id-Ed448 (1.3.101.113): 2b 65 71
const OID_ED448_BYTES: &[u8] = &[0x2b, 0x65, 0x71];

/// Check whether a DER buffer contains an Ed25519 or Ed448 PKCS#8 key.
/// These keys crash wc_EccPrivateKeyDecode in wolfssl 5.9.1 when given
/// as input; reject them early to avoid the crash.
fn is_eddsa_pkcs8(der: &[u8]) -> bool {
    // Ed25519/Ed448 PKCS#8 DER: 30 ?? 02 01 00 30 05 06 03 <3 OID bytes>
    // The 3 OID bytes start at offset 10.
    der.len() > 12
        && (der.get(10..13) == Some(OID_ED25519_BYTES)
            || der.get(10..13) == Some(OID_ED448_BYTES))
}

impl TryFrom<&PrivateKeyDer<'_>> for EcdsaSigningKey {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        let der = match value {
            PrivateKeyDer::Pkcs8(der) => {
                let raw = der.secret_pkcs8_der();
                // Guard: wc_EccPrivateKeyDecode crashes on Ed25519/Ed448 PKCS#8 input
                // in wolfssl 5.9.1 due to partial key initialization followed by
                // wc_ecc_free failing. Reject these key types early.
                if is_eddsa_pkcs8(raw) {
                    return Err(rustls::Error::General(
                        "Unsupported ECDSA key format (EdDSA key)".into(),
                    ));
                }
                raw
            }
            PrivateKeyDer::Sec1(der) => der.secret_sec1_der(),
            PrivateKeyDer::Pkcs1(_) => {
                return Err(rustls::Error::General(
                    "Unsupported ECDSA key format (PKCS#1)".into(),
                ))
            }
            _ => {
                return Err(rustls::Error::General(
                    "Unsupported ECDSA key format".into(),
                ))
            }
        };

        // Import the DER-encoded private key (handles both PKCS#8 and SEC1).
        let mut ecc = ECC::import_der(der, None, None)
            .map_err(|_| rustls::Error::General("ECC::import_der failed".into()))?;

        // Export the x963 public key to determine the curve.
        // Max x963 size for any supported curve is 133 bytes (P-521).
        let mut x963_buf = [0u8; 133];
        let x963_len = ecc
            .export_x963(&mut x963_buf)
            .map_err(|_| rustls::Error::General("export_x963 failed".into()))?;
        let pub_x963 = x963_buf[..x963_len].to_vec();

        // Determine scheme from x963 length: 65 -> P-256, 97 -> P-384, 133 -> P-521.
        let scheme = x963_len_to_scheme(x963_len)
            .map_err(|e| rustls::Error::General(e.to_string()))?;

        let field_size = (x963_len - 1) / 2;
        let mut priv_buf = vec![0u8; field_size];
        let priv_len = ecc
            .export_private(&mut priv_buf)
            .map_err(|_| rustls::Error::General("export_private failed".into()))?;
        priv_buf.truncate(priv_len);

        Ok(Self {
            priv_key: Arc::new(Zeroizing::new(priv_buf)),
            pub_x963: Arc::new(pub_x963),
            scheme,
        })
    }
}

/// Map x963 public key length to rustls `SignatureScheme`.
fn x963_len_to_scheme(x963_len: usize) -> Result<SignatureScheme, &'static str> {
    match x963_len {
        65 => Ok(SignatureScheme::ECDSA_NISTP256_SHA256),
        97 => Ok(SignatureScheme::ECDSA_NISTP384_SHA384),
        133 => Ok(SignatureScheme::ECDSA_NISTP521_SHA512),
        _ => Err("Unsupported ECDSA curve (unrecognised x963 key length)"),
    }
}

impl SigningKey for EcdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for EcdsaSigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let rng = RNG::new()
            .map_err(|_| rustls::Error::General("RNG::new failed".into()))?;

        // Build a DER-encoded ECDSA signature from the r||s bytes the wrapper
        // returns, because that is what TLS expects.
        let rs_bytes = match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                let pub_arr: [u8; 65] = self
                    .pub_x963
                    .as_slice()
                    .try_into()
                    .map_err(|_| rustls::Error::General("pub_x963 length mismatch".into()))?;
                let d_arr: [u8; 32] = self
                    .priv_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| rustls::Error::General("priv_key length mismatch".into()))?;
                let mut sk = P256SigningKey::import_x963(&pub_arr, &d_arr, rng)
                    .map_err(|_| rustls::Error::General("P256SigningKey::import_x963 failed".into()))?;
                let sig: P256Signature = sk
                    .try_sign(message)
                    .map_err(|_| rustls::Error::General("P256 sign failed".into()))?;
                sig.to_bytes().to_vec()
            }
            SignatureScheme::ECDSA_NISTP384_SHA384 => {
                let pub_arr: [u8; 97] = self
                    .pub_x963
                    .as_slice()
                    .try_into()
                    .map_err(|_| rustls::Error::General("pub_x963 length mismatch".into()))?;
                let d_arr: [u8; 48] = self
                    .priv_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| rustls::Error::General("priv_key length mismatch".into()))?;
                let mut sk = P384SigningKey::import_x963(&pub_arr, &d_arr, rng)
                    .map_err(|_| rustls::Error::General("P384SigningKey::import_x963 failed".into()))?;
                let sig: P384Signature = sk
                    .try_sign(message)
                    .map_err(|_| rustls::Error::General("P384 sign failed".into()))?;
                sig.to_bytes().to_vec()
            }
            SignatureScheme::ECDSA_NISTP521_SHA512 => {
                let pub_arr: [u8; 133] = self
                    .pub_x963
                    .as_slice()
                    .try_into()
                    .map_err(|_| rustls::Error::General("pub_x963 length mismatch".into()))?;
                let d_arr: [u8; 66] = self
                    .priv_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| rustls::Error::General("priv_key length mismatch".into()))?;
                let mut sk = P521SigningKey::import_x963(&pub_arr, &d_arr, rng)
                    .map_err(|_| rustls::Error::General("P521SigningKey::import_x963 failed".into()))?;
                let sig: P521Signature = sk
                    .try_sign(message)
                    .map_err(|_| rustls::Error::General("P521 sign failed".into()))?;
                sig.to_bytes().to_vec()
            }
            _ => {
                return Err(rustls::Error::General(
                    "Unsupported ECDSA scheme".into(),
                ))
            }
        };

        // The wrapper produces fixed r||s bytes; convert to DER for TLS.
        let field_size = rs_bytes.len() / 2;
        let (r, s) = rs_bytes.split_at(field_size);
        // Max DER size for any supported curve is 141 bytes (P-521).
        let mut der_buf = vec![0u8; 141];
        let der_len = ECC::rs_bin_to_sig(r, s, &mut der_buf)
            .map_err(|_| rustls::Error::General("rs_bin_to_sig failed".into()))?;
        der_buf.truncate(der_len);
        Ok(der_buf)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}




