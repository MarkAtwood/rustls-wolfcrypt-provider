use crate::error::*;
use wolfssl_wolfcrypt::random::RNG;

pub fn wolfcrypt_random_buffer_generator(buff: &mut [u8]) -> WCResult {
    let mut rng = RNG::new().map_err(|_| WCError::RandomError)?;
    rng.generate_block(buff).map_err(|_| WCError::RandomError)
}

#[cfg(test)]
mod tests {
    use super::wolfcrypt_random_buffer_generator;

    #[test]
    fn test_random() {
        let mut buff_1: [u8; 10] = [0; 10];
        let mut buff_2: [u8; 10] = [0; 10];

        wolfcrypt_random_buffer_generator(&mut buff_1).unwrap();
        wolfcrypt_random_buffer_generator(&mut buff_2).unwrap();

        assert_ne!(buff_1, buff_2);
    }
}
