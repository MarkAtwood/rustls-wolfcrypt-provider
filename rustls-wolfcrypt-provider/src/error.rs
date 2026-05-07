use core::fmt;

/// Custom error type for cryptographic operations.
/// Groups common wolfCrypt error types into categories.
// allow(dead_code): variants are constructed in random.rs and in test code via
// check_error; the dead_code lint does not always trace through map_err closures.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum WCError {
    /// Generic failure (-1)
    Failure,
    /// Memory-related errors (MEMORY_E, MP_MEM, etc.)
    Memory,
    /// Invalid arguments or state (BAD_FUNC_ARG, BAD_STATE_E, etc.)
    InvalidArgument,
    /// Buffer-related errors (BUFFER_E, RSA_BUFFER_E, etc.)
    Buffer,
    /// Authentication failures (MAC_CMP_FAILED_E, AES_GCM_AUTH_E, etc.)
    Authentication,
    /// Random number generation errors (RNG_FAILURE_E, MISSING_RNG_E, etc.)
    RandomError,
    /// ASN parsing errors (ASN_PARSE_E and related)
    ASNParse,
    /// Key-related errors (RSA_KEY_PAIR_E, ECC_PRIV_KEY_E, etc.)
    KeyError,
    /// Feature not available (NOT_COMPILED_IN, CRYPTOCB_UNAVAILABLE, etc.)
    NotAvailable,
}

impl fmt::Display for WCError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WCError::Failure => write!(f, "Operation failed"),
            WCError::Memory => write!(f, "Memory allocation error"),
            WCError::InvalidArgument => write!(f, "Invalid argument or state"),
            WCError::Buffer => write!(f, "Buffer error"),
            WCError::Authentication => write!(f, "Authentication failed"),
            WCError::RandomError => write!(f, "Random number generation error"),
            WCError::ASNParse => write!(f, "ASN parsing error"),
            WCError::KeyError => write!(f, "Key-related error"),
            WCError::NotAvailable => write!(f, "Feature not available"),
        }
    }
}

impl core::error::Error for WCError {}

/// A result type for cryptographic operations.
pub(crate) type WCResult = Result<(), WCError>;

/// Internal function to map wolfCrypt error codes to WCError variants
#[cfg(test)]
fn check_error(ret: i32) -> WCResult {
    match ret {
        0 => Ok(()),
        -1 => Err(WCError::Failure),
        -125 => Err(WCError::Memory),
        -173 => Err(WCError::InvalidArgument),
        -132 => Err(WCError::Buffer),
        -181..=-180 | -213 => Err(WCError::Authentication),
        -199 | -236 => Err(WCError::RandomError),
        -162..=-140 => Err(WCError::ASNParse),
        -262 | -216 => Err(WCError::KeyError),
        -174 | -271 => Err(WCError::NotAvailable),
        _ => Err(WCError::Failure),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(WCError::Failure.to_string(), "Operation failed");
        assert_eq!(WCError::Memory.to_string(), "Memory allocation error");
        assert_eq!(
            WCError::InvalidArgument.to_string(),
            "Invalid argument or state"
        );
        assert_eq!(WCError::Buffer.to_string(), "Buffer error");
        assert_eq!(WCError::Authentication.to_string(), "Authentication failed");
        assert_eq!(
            WCError::RandomError.to_string(),
            "Random number generation error"
        );
        assert_eq!(WCError::ASNParse.to_string(), "ASN parsing error");
        assert_eq!(WCError::KeyError.to_string(), "Key-related error");
        assert_eq!(WCError::NotAvailable.to_string(), "Feature not available");
    }

    #[test]
    fn test_check_error() {
        assert!(check_error(0).is_ok());
        assert!(matches!(check_error(-1), Err(WCError::Failure)));
        assert!(matches!(check_error(-125), Err(WCError::Memory)));
        assert!(matches!(check_error(-173), Err(WCError::InvalidArgument)));
        assert!(matches!(check_error(-132), Err(WCError::Buffer)));
        assert!(matches!(check_error(-180), Err(WCError::Authentication)));
        assert!(matches!(check_error(-199), Err(WCError::RandomError)));
        assert!(matches!(check_error(-140), Err(WCError::ASNParse)));
        assert!(matches!(check_error(-262), Err(WCError::KeyError)));
        assert!(matches!(check_error(-174), Err(WCError::NotAvailable)));
    }


}
