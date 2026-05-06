use alloc::vec;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;
use rustls_pki_types::alg_id;
use wolfssl_wolfcrypt::ecc::ECC;
use wolfssl_wolfcrypt::ecdsa::{
    P256Signature, P256VerifyingKey, P384Signature, P384VerifyingKey, P521Signature,
    P521VerifyingKey,
};
use signature::Verifier;

/// A unified ECDSA verifier for P-256, P-384, and P-521.
/// We store the `SignatureScheme` and switch logic accordingly.
#[derive(Debug)]
pub struct EcdsaVerifier {
    scheme: SignatureScheme,
}

impl EcdsaVerifier {
    /// Constructor for P-256 / ECDSA_NISTP256_SHA256
    pub const P256_SHA256: Self = Self {
        scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
    };

    /// Constructor for P-384 / ECDSA_NISTP384_SHA384
    pub const P384_SHA384: Self = Self {
        scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
    };

    /// Constructor for P-521 / ECDSA_NISTP521_SHA512
    pub const P521_SHA512: Self = Self {
        scheme: SignatureScheme::ECDSA_NISTP521_SHA512,
    };
}

/// Extract the r and s components from a DER-encoded ECDSA signature and
/// right-align each into a fixed-width buffer of `field_size` bytes,
/// producing a concatenated r||s byte vector.
fn der_sig_to_fixed_rs(
    der: &[u8],
    field_size: usize,
) -> Result<alloc::vec::Vec<u8>, InvalidSignature> {
    let mut r_buf = vec![0u8; field_size];
    let mut r_len = field_size as u32;
    let mut s_buf = vec![0u8; field_size];
    let mut s_len = field_size as u32;

    ECC::sig_to_rs(der, &mut r_buf, &mut r_len, &mut s_buf, &mut s_len)
        .map_err(|_| InvalidSignature)?;

    let r_len = r_len as usize;
    let s_len = s_len as usize;

    if r_len > field_size || s_len > field_size {
        return Err(InvalidSignature);
    }

    // Right-align r and s within field_size buffers (big-endian zero-padding).
    let mut out = vec![0u8; 2 * field_size];
    out[field_size - r_len..field_size].copy_from_slice(&r_buf[..r_len]);
    out[2 * field_size - s_len..].copy_from_slice(&s_buf[..s_len]);
    Ok(out)
}

impl SignatureVerificationAlgorithm for EcdsaVerifier {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => alg_id::ECDSA_P256,
            SignatureScheme::ECDSA_NISTP384_SHA384 => alg_id::ECDSA_P384,
            SignatureScheme::ECDSA_NISTP521_SHA512 => alg_id::ECDSA_P521,
            _ => unreachable!("Unsupported scheme for ECDSA public_key_alg_id"),
        }
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => alg_id::ECDSA_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384 => alg_id::ECDSA_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512 => alg_id::ECDSA_SHA512,
            _ => unreachable!("Unsupported scheme for ECDSA signature_alg_id"),
        }
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                // P-256: x963 = 0x04 || 32-byte x || 32-byte y = 65 bytes
                let pub_arr: [u8; 65] =
                    public_key.try_into().map_err(|_| InvalidSignature)?;
                let vk = P256VerifyingKey::from_bytes(pub_arr);
                let rs = der_sig_to_fixed_rs(signature, 32)?;
                let sig = P256Signature::try_from(rs.as_slice())
                    .map_err(|_| InvalidSignature)?;
                vk.verify(message, &sig).map_err(|_| InvalidSignature)
            }
            SignatureScheme::ECDSA_NISTP384_SHA384 => {
                // P-384: x963 = 0x04 || 48-byte x || 48-byte y = 97 bytes
                let pub_arr: [u8; 97] =
                    public_key.try_into().map_err(|_| InvalidSignature)?;
                let vk = P384VerifyingKey::from_bytes(pub_arr);
                let rs = der_sig_to_fixed_rs(signature, 48)?;
                let sig = P384Signature::try_from(rs.as_slice())
                    .map_err(|_| InvalidSignature)?;
                vk.verify(message, &sig).map_err(|_| InvalidSignature)
            }
            SignatureScheme::ECDSA_NISTP521_SHA512 => {
                // P-521: x963 = 0x04 || 66-byte x || 66-byte y = 133 bytes
                let pub_arr: [u8; 133] =
                    public_key.try_into().map_err(|_| InvalidSignature)?;
                let vk = P521VerifyingKey::from_bytes(pub_arr);
                let rs = der_sig_to_fixed_rs(signature, 66)?;
                let sig = P521Signature::try_from(rs.as_slice())
                    .map_err(|_| InvalidSignature)?;
                vk.verify(message, &sig).map_err(|_| InvalidSignature)
            }
            _ => Err(InvalidSignature),
        }
    }
}
