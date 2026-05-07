use super::ecc_kx::define_ecc_kx;
use wolfssl_wolfcrypt::ecc::ECC;

define_ecc_kx! {
    struct_name:  KeyExchangeSecP256r1,
    coord_size:   32,
    curve_id:     ECC::SECP256R1,
    named_group:  rustls::NamedGroup::secp256r1,
    constructor:  use_secp256r1,
}
