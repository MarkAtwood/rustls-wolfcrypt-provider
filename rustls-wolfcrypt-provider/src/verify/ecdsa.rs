use alloc::vec;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;
use rustls_pki_types::alg_id;
use signature::Verifier;
use wolfssl_wolfcrypt::ecc::ECC;
use wolfssl_wolfcrypt::ecdsa::{
    P256Signature, P256VerifyingKey, P384Signature, P384VerifyingKey, P521Signature,
    P521VerifyingKey,
};

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
    // field_size is always 32, 48, or 66 — safe to convert to u32.
    let field_size_u32 = u32::try_from(field_size).map_err(|_| InvalidSignature)?;
    let mut r_buf = vec![0u8; field_size];
    let mut r_len = field_size_u32;
    let mut s_buf = vec![0u8; field_size];
    let mut s_len = field_size_u32;

    // wc_ecc_sig_to_rs (called internally by ECC::sig_to_rs) writes the r and s
    // components left-aligned into the output buffers: bytes [0..r_len) and
    // [0..s_len) respectively.  The trailing bytes are left as zeroes.
    // This is confirmed by the C source in wolfcrypt/src/asn.c (GetASN_Buffer).
    ECC::sig_to_rs(der, &mut r_buf, &mut r_len, &mut s_buf, &mut s_len)
        .map_err(|_| InvalidSignature)?;

    // Bounds-check the C-written lengths before casting to usize.
    if r_len > field_size_u32 || s_len > field_size_u32 {
        return Err(InvalidSignature);
    }
    let r_len = r_len as usize;
    let s_len = s_len as usize;

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
        // RFC 5480 permits both uncompressed (0x04 || x || y) and compressed
        // (0x02/0x03 || x) SubjectPublicKeyInfo encodings.  wc_ecc_import_x963_ex
        // handles both; we import with an explicit curve ID (preventing cross-curve
        // key substitution), then re-export as the canonical uncompressed form before
        // dispatching to the typed verifying key.  The export size is checked to
        // confirm the key is on the expected curve.
        match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                let mut ecc = ECC::import_x963_ex(public_key, ECC::SECP256R1, None, None)
                    .map_err(|_| InvalidSignature)?;
                let mut pub_arr = [0u8; 65];
                let written = ecc
                    .export_x963(&mut pub_arr)
                    .map_err(|_| InvalidSignature)?;
                if written != 65 {
                    return Err(InvalidSignature);
                }
                let vk = P256VerifyingKey::from_bytes(pub_arr);
                let rs = der_sig_to_fixed_rs(signature, 32)?;
                let sig = P256Signature::try_from(rs.as_slice()).map_err(|_| InvalidSignature)?;
                vk.verify(message, &sig).map_err(|_| InvalidSignature)
            }
            SignatureScheme::ECDSA_NISTP384_SHA384 => {
                let mut ecc = ECC::import_x963_ex(public_key, ECC::SECP384R1, None, None)
                    .map_err(|_| InvalidSignature)?;
                let mut pub_arr = [0u8; 97];
                let written = ecc
                    .export_x963(&mut pub_arr)
                    .map_err(|_| InvalidSignature)?;
                if written != 97 {
                    return Err(InvalidSignature);
                }
                let vk = P384VerifyingKey::from_bytes(pub_arr);
                let rs = der_sig_to_fixed_rs(signature, 48)?;
                let sig = P384Signature::try_from(rs.as_slice()).map_err(|_| InvalidSignature)?;
                vk.verify(message, &sig).map_err(|_| InvalidSignature)
            }
            SignatureScheme::ECDSA_NISTP521_SHA512 => {
                let mut ecc = ECC::import_x963_ex(public_key, ECC::SECP521R1, None, None)
                    .map_err(|_| InvalidSignature)?;
                let mut pub_arr = [0u8; 133];
                let written = ecc
                    .export_x963(&mut pub_arr)
                    .map_err(|_| InvalidSignature)?;
                if written != 133 {
                    return Err(InvalidSignature);
                }
                let vk = P521VerifyingKey::from_bytes(pub_arr);
                let rs = der_sig_to_fixed_rs(signature, 66)?;
                let sig = P521Signature::try_from(rs.as_slice()).map_err(|_| InvalidSignature)?;
                vk.verify(message, &sig).map_err(|_| InvalidSignature)
            }
            _ => Err(InvalidSignature),
        }
    }
}
