use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls_pki_types::alg_id;
use wolfssl_wolfcrypt::rsa::RSA;
use wolfssl_wolfcrypt::sha::{SHA256, SHA384, SHA512};

const RSA_PSS_OUT_SIZE: usize = 512;

#[derive(Debug)]
pub struct RsaPssSha256Verify;

impl SignatureVerificationAlgorithm for RsaPssSha256Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PSS_SHA256
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let mut digest = [0u8; SHA256::DIGEST_SIZE];
        let mut sha = SHA256::new().map_err(|_| InvalidSignature)?;
        sha.update(message).map_err(|_| InvalidSignature)?;
        sha.finalize(&mut digest).map_err(|_| InvalidSignature)?;

        let mut rsa = RSA::new_public_from_der(public_key).map_err(|_| InvalidSignature)?;
        let mut out = [0u8; RSA_PSS_OUT_SIZE];

        // pss_verify_check takes signature as &[u8] (immutable); no copy needed.
        rsa.pss_verify_check(signature, &mut out, &digest, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256)
            .map_err(|_| InvalidSignature)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct RsaPssSha384Verify;

impl SignatureVerificationAlgorithm for RsaPssSha384Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PSS_SHA384
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let mut digest = [0u8; SHA384::DIGEST_SIZE];
        let mut sha = SHA384::new().map_err(|_| InvalidSignature)?;
        sha.update(message).map_err(|_| InvalidSignature)?;
        sha.finalize(&mut digest).map_err(|_| InvalidSignature)?;

        let mut rsa = RSA::new_public_from_der(public_key).map_err(|_| InvalidSignature)?;
        let mut out = [0u8; RSA_PSS_OUT_SIZE];

        rsa.pss_verify_check(signature, &mut out, &digest, RSA::HASH_TYPE_SHA384, RSA::MGF1SHA384)
            .map_err(|_| InvalidSignature)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct RsaPssSha512Verify;

impl SignatureVerificationAlgorithm for RsaPssSha512Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PSS_SHA512
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let mut digest = [0u8; SHA512::DIGEST_SIZE];
        let mut sha = SHA512::new().map_err(|_| InvalidSignature)?;
        sha.update(message).map_err(|_| InvalidSignature)?;
        sha.finalize(&mut digest).map_err(|_| InvalidSignature)?;

        let mut rsa = RSA::new_public_from_der(public_key).map_err(|_| InvalidSignature)?;
        let mut out = [0u8; RSA_PSS_OUT_SIZE];

        rsa.pss_verify_check(signature, &mut out, &digest, RSA::HASH_TYPE_SHA512, RSA::MGF1SHA512)
            .map_err(|_| InvalidSignature)?;
        Ok(())
    }
}
