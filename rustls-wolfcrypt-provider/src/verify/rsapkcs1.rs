use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls_pki_types::alg_id;
use signature::Verifier;
use wolfssl_wolfcrypt::rsa_pkcs1v15::{Sha256, Sha384, Sha512, VerifyingKey};

/// Attempt PKCS#1 v1.5 verification against each supported key size.
///
/// Tries RSA-2048 (256 B), RSA-3072 (384 B), and RSA-4096 (512 B).
/// Returns `Ok(())` on the first match, `InvalidSignature` if none succeed.
macro_rules! pkcs1_verify {
    ($hash:ty, $public_key:expr, $message:expr, $signature:expr) => {{
        macro_rules! try_size {
            ($n:literal) => {
                if let Ok(vk) = VerifyingKey::<$hash, $n>::from_public_der($public_key) {
                    if let Ok(sig) = wolfssl_wolfcrypt::rsa_pkcs1v15::Signature::<$n>::try_from(
                        $signature,
                    ) {
                        return vk
                            .verify($message, &sig)
                            .map_err(|_| InvalidSignature);
                    }
                }
            };
        }
        try_size!(256);
        try_size!(384);
        try_size!(512);
        Err(InvalidSignature)
    }};
}

#[derive(Debug)]
pub struct RsaPkcs1Sha256Verify;

impl SignatureVerificationAlgorithm for RsaPkcs1Sha256Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PKCS1_SHA256
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        pkcs1_verify!(Sha256, public_key, message, signature)
    }
}

#[derive(Debug)]
pub struct RsaPkcs1Sha384Verify;

impl SignatureVerificationAlgorithm for RsaPkcs1Sha384Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PKCS1_SHA384
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        pkcs1_verify!(Sha384, public_key, message, signature)
    }
}

#[derive(Debug)]
pub struct RsaPkcs1Sha512Verify;

impl SignatureVerificationAlgorithm for RsaPkcs1Sha512Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PKCS1_SHA512
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        pkcs1_verify!(Sha512, public_key, message, signature)
    }
}
