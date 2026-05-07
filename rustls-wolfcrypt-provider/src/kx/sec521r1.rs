use super::ecc_kx::define_ecc_kx;
use wolfssl_wolfcrypt::ecc::ECC;

define_ecc_kx! {
    struct_name:  KeyExchangeSecP521r1,
    coord_size:   66,
    curve_id:     ECC::SECP521R1,
    named_group:  rustls::NamedGroup::secp521r1,
    constructor:  use_secp521r1,
}
