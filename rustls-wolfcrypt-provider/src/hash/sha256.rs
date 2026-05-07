use alloc::boxed::Box;
use rustls::crypto::hash;
use wolfssl_wolfcrypt::sha::SHA256;

pub struct WCSha256;

impl hash::Hash for WCSha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        // SHA256::new() can only fail on allocation failure; the rustls
        // hash::Hash::start() method returns Box<dyn Context> — no Result.
        let sha = SHA256::new()
            .unwrap_or_else(|e| panic!("SHA256::new failed: wolfSSL error {}", e));
        Box::new(WCSha256Context { sha })
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
        // SHA256::copy() clones the hash state in O(1); failure means OOM or
        // state corruption — both abort-level in a no-Result trait method.
        let sha = self.sha
            .copy()
            .unwrap_or_else(|e| panic!("SHA256::copy failed: wolfSSL error {}", e));
        Box::new(WCSha256Context { sha })
    }

    fn finish(mut self: Box<Self>) -> hash::Output {
        let mut hash = [0u8; SHA256::DIGEST_SIZE];
        self.sha
            .finalize(&mut hash)
            .unwrap_or_else(|e| panic!("SHA256::finalize failed: wolfSSL error {}", e));
        hash::Output::new(&hash)
    }

    fn update(&mut self, data: &[u8]) {
        self.sha
            .update(data)
            .unwrap_or_else(|e| panic!("SHA256::update failed: wolfSSL error {}", e));
    }
}

// SAFETY: WCSha256Context is exclusively owned — rustls::crypto::hash::Context
// is consumed (Box<Self>) on finish() and moved into fork().  No caller holds
// simultaneous references, so there is no aliasing across threads.  The Sync
// impl satisfies trait-object bounds; the Send impl allows Box<dyn Context>
// to be moved across threads, which is the only cross-thread transfer path.
// wc_Sha256 itself is not internally synchronized, so callers must not share
// a WCSha256Context between threads — the exclusive-ownership invariant above
// ensures this is never the case.
// Note: Sync is only safe here because the rustls hash::Context API exposes
// only Box<dyn Context> ownership and does not implement Clone; no Arc-based
// sharing path exists, so concurrent fork() calls on the same instance are
// unreachable through the public API.
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
    fn test_sha256_known_answer() {
        // Cross-validated with openssl: echo -n "abc" | openssl sha256
        let wcsha256 = WCSha256;
        let hash = wcsha256.hash(b"abc");
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert_eq!(hash.as_ref(), expected.as_slice(), "SHA-256('abc') mismatch");
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
