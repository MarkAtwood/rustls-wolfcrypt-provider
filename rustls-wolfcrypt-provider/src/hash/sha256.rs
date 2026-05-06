use alloc::boxed::Box;
use rustls::crypto::hash;
use wolfssl_wolfcrypt::sha::SHA256;

pub struct WCSha256;

impl hash::Hash for WCSha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(WCSha256Context {
            // Treat SHA256::new() failure as abort-level: it only fails on
            // allocation failure, which the rustls hash trait cannot propagate.
            sha: SHA256::new().expect("SHA256::new failed"),
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
}

impl hash::Context for WCSha256Context {
    fn fork_finish(&self) -> hash::Output {
        self.fork().finish()
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        // wc_Sha256Copy clones the internal wolfSSL SHA-256 state in O(1),
        // avoiding O(N) data-replay of all bytes fed so far.
        Box::new(WCSha256Context {
            sha: self.sha.copy().expect("SHA256::copy failed"),
        })
    }

    fn finish(mut self: Box<Self>) -> hash::Output {
        let mut hash = [0u8; SHA256::DIGEST_SIZE];
        self.sha.finalize(&mut hash).expect("SHA256::finalize failed");
        hash::Output::new(&hash)
    }

    fn update(&mut self, data: &[u8]) {
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

    #[test]
    fn test_sha256_fork() {
        // Verify that fork() produces the same result as finishing the original,
        // and that subsequent updates to the fork don't affect the original.
        let wcsha256 = WCSha256;
        let mut ctx = wcsha256.start();
        ctx.update(b"hello ");

        let forked = ctx.fork();
        ctx.update(b"world");
        let forked_finish = {
            let mut f = forked;
            f.update(b"world");
            f.finish()
        };
        let orig_finish = ctx.finish();

        assert_eq!(hex::encode(orig_finish), hex::encode(forked_finish));
    }
}
