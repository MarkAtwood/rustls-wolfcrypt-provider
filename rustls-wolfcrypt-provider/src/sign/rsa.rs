use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use signature::SignerMut;
use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::rsa::RSA;
use wolfssl_wolfcrypt::rsa_pkcs1v15::{self, Sha256, Sha384, Sha512};
use wolfssl_wolfcrypt::sha::{SHA256, SHA384, SHA512};
use zeroize::Zeroizing;

const ALL_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
];

const MAX_RSA_SIG_SIZE: usize = 512;

#[derive(Clone)]
pub struct RsaPrivateKey {
    der_bytes: Arc<Zeroizing<Vec<u8>>>,
    algo: SignatureAlgorithm,
}

impl fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPrivateKey")
            .finish_non_exhaustive()
    }
}

/// Parse DER bytes into an `RSA` private key.
///
/// `wc_RsaPrivateKeyDecode` accepts both raw PKCS#1 and PKCS#8 formats.
fn parse_private_key(der_bytes: &[u8]) -> Result<RSA, rustls::Error> {
    RSA::new_from_der(der_bytes)
        .map_err(|_| rustls::Error::General("RSA private key decode failed".into()))
}

impl TryFrom<&PrivateKeyDer<'_>> for RsaPrivateKey {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        let der_bytes = match value {
            PrivateKeyDer::Pkcs8(der) => der.secret_pkcs8_der().to_vec(),
            PrivateKeyDer::Pkcs1(der) => der.secret_pkcs1_der().to_vec(),
            _ => {
                return Err(rustls::Error::General(
                    "Unsupported private key format".into(),
                ))
            }
        };

        // Validate that the key parses before accepting it.
        let _rsa = parse_private_key(&der_bytes)?;

        Ok(Self {
            der_bytes: Arc::new(Zeroizing::new(der_bytes)),
            algo: SignatureAlgorithm::RSA,
        })
    }
}

impl SigningKey for RsaPrivateKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        ALL_RSA_SCHEMES.iter().find_map(|&scheme| {
            if offered.contains(&scheme) {
                Some(Box::new(RsaSigner {
                    der_bytes: Arc::clone(&self.der_bytes),
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
pub struct RsaSigner {
    der_bytes: Arc<Zeroizing<Vec<u8>>>,
    scheme: SignatureScheme,
}

impl fmt::Debug for RsaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSigner")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

fn sha256_digest(message: &[u8]) -> Result<[u8; SHA256::DIGEST_SIZE], rustls::Error> {
    let mut digest = [0u8; SHA256::DIGEST_SIZE];
    let mut sha = SHA256::new().map_err(|_| rustls::Error::General("SHA256 init failed".into()))?;
    sha.update(message)
        .map_err(|_| rustls::Error::General("SHA256 update failed".into()))?;
    sha.finalize(&mut digest)
        .map_err(|_| rustls::Error::General("SHA256 finalize failed".into()))?;
    Ok(digest)
}

fn sha384_digest(message: &[u8]) -> Result<[u8; SHA384::DIGEST_SIZE], rustls::Error> {
    let mut digest = [0u8; SHA384::DIGEST_SIZE];
    let mut sha = SHA384::new().map_err(|_| rustls::Error::General("SHA384 init failed".into()))?;
    sha.update(message)
        .map_err(|_| rustls::Error::General("SHA384 update failed".into()))?;
    sha.finalize(&mut digest)
        .map_err(|_| rustls::Error::General("SHA384 finalize failed".into()))?;
    Ok(digest)
}

fn sha512_digest(message: &[u8]) -> Result<[u8; SHA512::DIGEST_SIZE], rustls::Error> {
    let mut digest = [0u8; SHA512::DIGEST_SIZE];
    let mut sha = SHA512::new().map_err(|_| rustls::Error::General("SHA512 init failed".into()))?;
    sha.update(message)
        .map_err(|_| rustls::Error::General("SHA512 update failed".into()))?;
    sha.finalize(&mut digest)
        .map_err(|_| rustls::Error::General("SHA512 finalize failed".into()))?;
    Ok(digest)
}

/// Sign `message` with PKCS#1 v1.5 using a specific hash type and key size.
///
/// `from_rsa` returns an error if the key's actual modulus size != N, which
/// is how we dispatch to the correct size at runtime.
fn pkcs1_sign_with_size<H: rsa_pkcs1v15::Hash, const N: usize>(
    der_bytes: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, rustls::Error>
where
    rsa_pkcs1v15::SigningKey<H, N>: SignerMut<rsa_pkcs1v15::Signature<N>>,
{
    let rng = RNG::new().map_err(|_| rustls::Error::General("RNG init failed".into()))?;
    let rsa = RSA::new_from_der(der_bytes)
        .map_err(|_| rustls::Error::General("RSA key decode failed".into()))?;
    let mut sk = rsa_pkcs1v15::SigningKey::<H, N>::from_rsa(rsa, rng)
        .map_err(|_| rustls::Error::General("PKCS1 key size mismatch".into()))?;
    let sig = sk
        .try_sign(message)
        .map_err(|_| rustls::Error::General("PKCS1 sign failed".into()))?;
    Ok(sig.as_ref().to_vec())
}

impl Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let der = self.der_bytes.as_ref();

        match self.scheme {
            // RSA-PSS: hash the message externally, then pass the digest to pss_sign.
            SignatureScheme::RSA_PSS_SHA256
            | SignatureScheme::RSA_PSS_SHA384
            | SignatureScheme::RSA_PSS_SHA512 => {
                let mut rsa = parse_private_key(der)?;
                let mut rng = RNG::new()
                    .map_err(|_| rustls::Error::General("RNG init failed".into()))?;
                rsa.set_rng(&mut rng)
                    .map_err(|_| rustls::Error::General("RSA set_rng failed".into()))?;
                let mut sig_buf = [0u8; MAX_RSA_SIG_SIZE];

                match self.scheme {
                    SignatureScheme::RSA_PSS_SHA256 => {
                        let digest = sha256_digest(message)?;
                        let sig_len = rsa
                            .pss_sign(
                                &digest,
                                &mut sig_buf,
                                RSA::HASH_TYPE_SHA256,
                                RSA::MGF1SHA256,
                                &mut rng,
                            )
                            .map_err(|_| {
                                rustls::Error::General("RSA PSS SHA256 sign failed".into())
                            })?;
                        Ok(sig_buf[..sig_len].to_vec())
                    }
                    SignatureScheme::RSA_PSS_SHA384 => {
                        let digest = sha384_digest(message)?;
                        let sig_len = rsa
                            .pss_sign(
                                &digest,
                                &mut sig_buf,
                                RSA::HASH_TYPE_SHA384,
                                RSA::MGF1SHA384,
                                &mut rng,
                            )
                            .map_err(|_| {
                                rustls::Error::General("RSA PSS SHA384 sign failed".into())
                            })?;
                        Ok(sig_buf[..sig_len].to_vec())
                    }
                    SignatureScheme::RSA_PSS_SHA512 => {
                        let digest = sha512_digest(message)?;
                        let sig_len = rsa
                            .pss_sign(
                                &digest,
                                &mut sig_buf,
                                RSA::HASH_TYPE_SHA512,
                                RSA::MGF1SHA512,
                                &mut rng,
                            )
                            .map_err(|_| {
                                rustls::Error::General("RSA PSS SHA512 sign failed".into())
                            })?;
                        Ok(sig_buf[..sig_len].to_vec())
                    }
                    _ => unreachable!(),
                }
            }

            // RSA-PKCS#1 v1.5: wc_SignatureGenerate (called by pkcs1_sign_with_size via
            // rsa_pkcs1v15::SigningKey::try_sign) hashes the raw message internally.
            // This is intentionally asymmetric with RSA-PSS above, which pre-hashes
            // externally before calling pss_sign. Do NOT change PKCS#1 to pre-hash:
            // wc_SignatureGenerate performs DigestInfo encoding as part of PKCS#1 v1.5.
            SignatureScheme::RSA_PKCS1_SHA256 => {
                pkcs1_sign_with_size::<Sha256, 256>(der, message)
                    .or_else(|_| pkcs1_sign_with_size::<Sha256, 384>(der, message))
                    .or_else(|_| pkcs1_sign_with_size::<Sha256, 512>(der, message))
                    .map_err(|_| rustls::Error::General("RSA PKCS1 SHA256 sign failed".into()))
            }
            SignatureScheme::RSA_PKCS1_SHA384 => {
                pkcs1_sign_with_size::<Sha384, 256>(der, message)
                    .or_else(|_| pkcs1_sign_with_size::<Sha384, 384>(der, message))
                    .or_else(|_| pkcs1_sign_with_size::<Sha384, 512>(der, message))
                    .map_err(|_| rustls::Error::General("RSA PKCS1 SHA384 sign failed".into()))
            }
            SignatureScheme::RSA_PKCS1_SHA512 => {
                pkcs1_sign_with_size::<Sha512, 256>(der, message)
                    .or_else(|_| pkcs1_sign_with_size::<Sha512, 384>(der, message))
                    .or_else(|_| pkcs1_sign_with_size::<Sha512, 512>(der, message))
                    .map_err(|_| rustls::Error::General("RSA PKCS1 SHA512 sign failed".into()))
            }

            _ => Err(rustls::Error::General("Unsupported RSA scheme".into())),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
