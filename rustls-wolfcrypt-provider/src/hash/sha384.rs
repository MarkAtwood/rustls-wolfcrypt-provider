use alloc::boxed::Box;
use rustls::crypto::hash;
use wolfssl_wolfcrypt::sha::SHA384;

pub struct WCSha384;

impl hash::Hash for WCSha384 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(WCSha384Context {
            // Treat SHA384::new() failure as abort-level: it only fails on
            // allocation failure, which the rustls hash trait cannot propagate.
            sha: SHA384::new().expect("SHA384::new failed"),
        })
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        let mut hasher = self.start();
        hasher.update(data);
        hasher.finish()
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA384
    }

    fn output_len(&self) -> usize {
        SHA384::DIGEST_SIZE
    }
}

struct WCSha384Context {
    sha: SHA384,
}

impl hash::Context for WCSha384Context {
    fn fork_finish(&self) -> hash::Output {
        self.fork().finish()
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        // wc_Sha384Copy clones the internal wolfSSL SHA-384 state in O(1),
        // avoiding O(N) data-replay of all bytes fed so far.
        Box::new(WCSha384Context {
            sha: self.sha.copy().expect("SHA384::copy failed"),
        })
    }

    fn finish(mut self: Box<Self>) -> hash::Output {
        let mut hash = [0u8; SHA384::DIGEST_SIZE];
        self.sha.finalize(&mut hash).expect("SHA384::finalize failed");
        hash::Output::new(&hash)
    }

    fn update(&mut self, data: &[u8]) {
        self.sha.update(data).expect("SHA384::update failed");
    }
}

unsafe impl Sync for WCSha384Context {}
unsafe impl Send for WCSha384Context {}

#[cfg(test)]
mod tests {
    use super::WCSha384;
    use rustls::crypto::hash::Hash;

    #[test]
    fn test_sha384() {
        let wcsha384_c_type = WCSha384;
        let hash1 = wcsha384_c_type.hash("hello".as_bytes());
        let hash2 = wcsha384_c_type.hash("hello".as_bytes());

        let hash_str1 = hex::encode(hash1);
        let hash_str2 = hex::encode(hash2);

        assert_eq!(hash_str1, hash_str2);
    }

    #[test]
    fn test_sha384_fork() {
        let wcsha384 = WCSha384;
        let mut ctx = wcsha384.start();
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
