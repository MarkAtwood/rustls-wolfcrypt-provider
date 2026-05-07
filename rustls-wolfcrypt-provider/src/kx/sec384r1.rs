use super::ecc_kx::define_ecc_kx;
use wolfssl_wolfcrypt::ecc::ECC;

define_ecc_kx! {
    struct_name:  KeyExchangeSecP384r1,
    coord_size:   48,
    curve_id:     ECC::SECP384R1,
    named_group:  rustls::NamedGroup::secp384r1,
    constructor:  use_secp384r1,
}
