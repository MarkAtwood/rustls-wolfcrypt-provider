use alloc::boxed::Box;
use alloc::vec::Vec;
use rustls::crypto::hash;
use wolfssl_wolfcrypt::sha::SHA256;

pub struct WCSha256;

impl hash::Hash for WCSha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(WCSha256Context {
            sha: SHA256::new().expect("SHA256::new failed"),
            data: Vec::new(),
        })
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        let mut hasher = self.start();
        hasher.update(data);
        hasher.finish()
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }

    fn output_len(&self) -> usize {
        SHA256::DIGEST_SIZE
    }
}

struct WCSha256Context {
    sha: SHA256,
    data: Vec<u8>,
}

impl hash::Context for WCSha256Context {
    fn fork_finish(&self) -> hash::Output {
        let forked = self.fork();
        forked.finish()
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        let mut sha = SHA256::new().expect("SHA256::new failed in fork");
        sha.update(&self.data).expect("SHA256::update failed in fork");
        Box::new(WCSha256Context {
            sha,
            data: self.data.clone(),
        })
    }

    fn finish(mut self: Box<Self>) -> hash::Output {
        let mut hash = [0u8; SHA256::DIGEST_SIZE];
        self.sha.finalize(&mut hash).expect("SHA256::finalize failed");
        hash::Output::new(&hash)
    }

    fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
        self.sha.update(data).expect("SHA256::update failed");
    }
}

unsafe impl Sync for WCSha256Context {}
unsafe impl Send for WCSha256Context {}

#[cfg(test)]
mod tests {
    use super::WCSha256;
    use rustls::crypto::hash::Hash;

    #[test]
    fn test_sha256() {
        let wcsha256_struct = WCSha256;
        let hash1 = wcsha256_struct.hash("hello".as_bytes());
        let hash2 = wcsha256_struct.hash("hello".as_bytes());

        let hash_str1 = hex::encode(hash1);
        let hash_str2 = hex::encode(hash2);

        assert_eq!(hash_str1, hash_str2);
    }
}
