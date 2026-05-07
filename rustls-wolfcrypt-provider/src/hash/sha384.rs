use alloc::boxed::Box;
use rustls::crypto::hash;
use wolfssl_wolfcrypt::sha::SHA384;

pub struct WCSha384;

impl hash::Hash for WCSha384 {
    fn start(&self) -> Box<dyn hash::Context> {
        // SHA384::new() can only fail on allocation failure; the rustls
        // hash::Hash::start() method returns Box<dyn Context> — no Result.
        let sha = SHA384::new()
            .unwrap_or_else(|e| panic!("SHA384::new failed: wolfSSL error {}", e));
        Box::new(WCSha384Context { sha })
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
        // SHA384::copy() clones the hash state in O(1); failure means OOM or
        // state corruption — both abort-level in a no-Result trait method.
        let sha = self.sha
            .copy()
            .unwrap_or_else(|e| panic!("SHA384::copy failed: wolfSSL error {}", e));
        Box::new(WCSha384Context { sha })
    }

    fn finish(mut self: Box<Self>) -> hash::Output {
        let mut hash = [0u8; SHA384::DIGEST_SIZE];
        self.sha
            .finalize(&mut hash)
            .unwrap_or_else(|e| panic!("SHA384::finalize failed: wolfSSL error {}", e));
        hash::Output::new(&hash)
    }

    fn update(&mut self, data: &[u8]) {
        self.sha
            .update(data)
            .unwrap_or_else(|e| panic!("SHA384::update failed: wolfSSL error {}", e));
    }
}

// SAFETY: WCSha384Context is exclusively owned — rustls::crypto::hash::Context
// is consumed (Box<Self>) on finish() and moved into fork().  No caller holds
// simultaneous references, so there is no aliasing across threads.  The Sync
// impl satisfies trait-object bounds; the Send impl allows Box<dyn Context>
// to be moved across threads, which is the only cross-thread transfer path.
// wc_Sha384 itself is not internally synchronized, so callers must not share
// a WCSha384Context between threads — the exclusive-ownership invariant above
// ensures this is never the case.
// Note: Sync is only safe here because the rustls hash::Context API exposes
// only Box<dyn Context> ownership and does not implement Clone; no Arc-based
// sharing path exists, so concurrent fork() calls on the same instance are
// unreachable through the public API.
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
    fn test_sha384_known_answer() {
        // Cross-validated with openssl: echo -n "abc" | openssl sha384
        let wcsha384 = WCSha384;
        let hash = wcsha384.hash(b"abc");
        let expected = hex::decode(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7",
        )
        .unwrap();
        assert_eq!(hash.as_ref(), expected.as_slice(), "SHA-384('abc') mismatch");
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
