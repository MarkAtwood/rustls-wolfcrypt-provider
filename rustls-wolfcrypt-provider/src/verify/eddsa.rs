#![cfg(ed25519)]

use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls_pki_types::alg_id;
use wolfssl_wolfcrypt::ed25519::Ed25519 as WcEd25519;

#[derive(Debug)]
pub struct Ed25519;

impl SignatureVerificationAlgorithm for Ed25519 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let mut ed = WcEd25519::new().map_err(|_| InvalidSignature)?;
        ed.import_public(public_key).map_err(|_| InvalidSignature)?;
        match ed.verify_msg(signature, message) {
            Ok(true) => Ok(()),
            _ => Err(InvalidSignature),
        }
    }
}
