use crate::alloc::string::ToString;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use pkcs8::PrivateKeyInfo;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use signature::SignerMut;
use wolfssl_wolfcrypt::ecc::ECC;
use wolfssl_wolfcrypt::ecdsa::{
    P256SigningKey, P256Signature, P384SigningKey, P384Signature, P521SigningKey, P521Signature,
};
use wolfssl_wolfcrypt::random::RNG;
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
        // Extract the SEC1 ECPrivateKey bytes regardless of outer wrapper.
        // ECC::import_der calls wc_EccPrivateKeyDecode which handles SEC1 format.
        // For PKCS8 input, unwrap to SEC1 first so we pass a known format.
        let sec1_bytes: &[u8] = match value {
            PrivateKeyDer::Pkcs8(der) => {
                let raw = der.secret_pkcs8_der();
                // Guard: reject Ed25519/Ed448 PKCS8 early — they crash wc_EccPrivateKeyDecode.
                if is_eddsa_pkcs8(raw) {
                    return Err(rustls::Error::General(
                        "Unsupported ECDSA key format (EdDSA key)".into(),
                    ));
                }
                // Unwrap the PKCS8 outer layer to get the SEC1 ECPrivateKey DER.
                // pkcs8::PrivateKeyInfo::try_from parses the AlgorithmIdentifier and
                // returns private_key as the inner OCTET STRING value.
                // For id-ecPublicKey keys that inner value is the SEC1 ECPrivateKey DER.
                PrivateKeyInfo::try_from(raw)
                    .map(|pki| pki.private_key)
                    .unwrap_or(raw) // fall back to raw if PKCS8 parse fails
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

        // Import the SEC1 ECPrivateKey DER.
        let mut ecc = ECC::import_der(sec1_bytes, None, None)
            .map_err(|e| rustls::Error::General(alloc::format!("ECC::import_der failed: {}", e).into()))?;

        // wc_EccPrivateKeyDecode does not always compute the public key automatically
        // when the SEC1 structure omits the optional [1] PUBLIC KEY field.
        // Call make_pub to derive the public key from the private scalar.
        ecc.make_pub(None)
            .map_err(|e| rustls::Error::General(alloc::format!("ECC::make_pub failed: {}", e).into()))?;

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





#[cfg(test)]
mod tests {
    use super::*;
    use wolfssl_wolfcrypt::ecc::ECC;
    use wolfssl_wolfcrypt::random::RNG;

    #[test]
    fn test_ecdsa_import_and_sign() {
        // Generate a P-256 key via the wrapper, then sign with it directly.
        let mut rng = RNG::new().expect("rng");
        let curve_size = ECC::get_curve_size_from_id(ECC::SECP256R1).expect("curve_size");
        let mut key = ECC::generate_ex(curve_size, &mut rng, ECC::SECP256R1, None, None).expect("generate");

        // Export private scalar
        let mut priv_buf = [0u8; 32];
        key.export_private(&mut priv_buf).expect("export_private");

        // Export x963 public key
        let mut x963 = [0u8; 65];
        let x963_len = key.export_x963(&mut x963).expect("export_x963");
        assert_eq!(x963_len, 65);

        // Build a P256SigningKey and sign
        let rng2 = RNG::new().expect("rng2");
        let mut sk = P256SigningKey::import_x963(&x963, &priv_buf, rng2)
            .expect("P256SigningKey::import_x963");
        let sig: P256Signature = sk.try_sign(b"hello world").expect("try_sign");
        assert_eq!(sig.to_bytes().len(), 64);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use rustls::pki_types::{PrivateSec1KeyDer, PrivatePkcs8KeyDer};

    /// Build a SEC1 ECPrivateKey DER for P-256 from a raw 32-byte private scalar
    /// and a 65-byte uncompressed public key (0x04 || X || Y).
    ///
    /// Structure (RFC 5915 ECPrivateKey with namedCurve and publicKey):
    ///   SEQUENCE {
    ///     version INTEGER (1),
    ///     privateKey OCTET STRING (32 bytes),
    ///     [0] EXPLICIT OID id-prime256v1,
    ///     [1] EXPLICIT BIT STRING (uncompressed point)
    ///   }
    ///
    /// This matches what wc_EccPrivateKeyToDer produces for P-256 keys.
    fn make_sec1_p256(priv_bytes: &[u8; 32], pub_bytes: &[u8; 65]) -> alloc::vec::Vec<u8> {
        // OID for id-prime256v1 (1.2.840.10045.3.1.7): 2a 86 48 ce 3d 03 01 07
        let oid: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

        // [0] namedCurve: a0 0a 06 08 <oid>
        let named_curve: alloc::vec::Vec<u8> = {
            let mut v = alloc::vec![0xa0, 0x0a, 0x06, 0x08];
            v.extend_from_slice(oid);
            v
        };

        // [1] publicKey: a1 44 03 42 00 <65 bytes>
        let pub_key_field: alloc::vec::Vec<u8> = {
            let mut v = alloc::vec![0xa1, 0x44, 0x03, 0x42, 0x00];
            v.extend_from_slice(pub_bytes);
            v
        };

        // privateKey: 04 20 <32 bytes>
        let priv_field: alloc::vec::Vec<u8> = {
            let mut v = alloc::vec![0x04, 0x20];
            v.extend_from_slice(priv_bytes);
            v
        };

        // version: 02 01 01
        let version: &[u8] = &[0x02, 0x01, 0x01];

        let inner_len = version.len()
            + priv_field.len()
            + named_curve.len()
            + pub_key_field.len();

        let mut der = alloc::vec![0x30, inner_len as u8];
        der.extend_from_slice(version);
        der.extend_from_slice(&priv_field);
        der.extend_from_slice(&named_curve);
        der.extend_from_slice(&pub_key_field);
        der
    }

    #[test]
    fn test_ecdsa_try_from_sec1() {
        // Generate a P-256 key via the safe wrapper — no wolfcrypt_rs needed.
        let mut rng = wolfssl_wolfcrypt::random::RNG::new().expect("RNG::new");
        let curve_size = wolfssl_wolfcrypt::ecc::ECC::get_curve_size_from_id(
            wolfssl_wolfcrypt::ecc::ECC::SECP256R1,
        ).expect("curve_size");
        let mut key = wolfssl_wolfcrypt::ecc::ECC::generate_ex(
            curve_size, &mut rng, wolfssl_wolfcrypt::ecc::ECC::SECP256R1, None, None,
        ).expect("generate");

        let mut priv_bytes = [0u8; 32];
        key.export_private(&mut priv_bytes).expect("export_private");

        let mut x963 = [0u8; 65];
        key.export_x963(&mut x963).expect("export_x963");
        let pub_bytes: &[u8; 65] = &x963;

        let sec1_der = make_sec1_p256(&priv_bytes, pub_bytes);

        // Verify EcdsaSigningKey accepts SEC1 input.
        let sec1_key = PrivateKeyDer::from(PrivateSec1KeyDer::from(sec1_der.as_slice()));
        EcdsaSigningKey::try_from(&sec1_key).expect("SEC1 try_from failed");

        // Verify EcdsaSigningKey accepts SEC1 bytes mislabeled as PKCS8
        // (this is what the e2e test generates via wc_EccPrivateKeyToDer
        // wrapped in PrivatePkcs8KeyDer).
        let pkcs8_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(sec1_der.as_slice()));
        EcdsaSigningKey::try_from(&pkcs8_key).expect("PKCS8-labeled-SEC1 try_from failed");
    }
}
