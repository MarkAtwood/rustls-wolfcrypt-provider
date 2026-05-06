use lazy_static::lazy_static;
use rayon::prelude::*;
use rustls::version::{TLS12, TLS13};
use rustls::SignatureScheme;
use rustls_wolfcrypt_provider::{
    TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
};
use std::env;
use std::fs::File;
use std::io::stdout;
use std::io::BufReader;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::sync::Once;
use std::sync::{Arc, Mutex};
use std::thread;

/*
 * Version config used by the server to specify
 * the tls version that we wanna use.
 * */
const TLSV1_2: &str = "-v 3";
const TLSV1_3: &str = "-v 4";

/*
 * Global mutex to ensure only one test can access the server at a time.
 * This is needed because both TLS 1.2 and TLS 1.3 tests spin up a local server
 * on the same port (4443). Without synchronization, tests running in parallel
 * could try to bind to the same port or interact with the wrong server instance.
*/
lazy_static! {
    static ref SERVER_LOCK: Mutex<()> = Mutex::new(());
}

/*
 * Initiliaze the thread pool once for all tests.
 * */
static INIT: Once = Once::new();

fn init_thread_pool() {
    INIT.call_once(|| {
        let num_cpus = num_cpus::get();
        rayon::ThreadPoolBuilder::new()
            .num_threads(num_cpus)
            .build_global()
            .unwrap();
    });
}

/*
 * Starts background job for wolfssl server (localhost:4443).
 * */
fn start_wolfssl_server(current_dir_string: String, tls_version: &str) -> Child {
    if let Err(e) = env::set_current_dir("../wolfcrypt-rs/wolfssl-5.7.6-stable/") {
        panic!("Error changing directory: {}", e);
    } else {
        println!("Changed directory to wolfssl-5.7.6-stable.");

        Command::new("./examples/server/server")
            .arg("-d")
            .arg("-c")
            .arg(current_dir_string.clone() + "/tests/certs/localhost.pem")
            .arg("-k")
            .arg(current_dir_string.clone() + "/tests/certs/localhost.key")
            .arg("-p")
            .arg("4443")
            .arg(tls_version)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("Failed to start wolfssl server.")
    }
}

#[cfg(test)]
mod tests {
    use rustls::crypto::CryptoProvider;
    use rustls_pki_types::{
        PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    };

    use super::*;

    #[test]
    fn test_tls12_against_server() {
        let _guard = SERVER_LOCK.lock().unwrap();
        let current_dir = env::current_dir().unwrap();
        let current_dir_string = current_dir.to_string_lossy().into_owned();

        let ciphers = [
            TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let server_thread = {
                let wolfssl_server = Arc::new(Mutex::new(start_wolfssl_server(
                    current_dir_string.clone(),
                    TLSV1_2,
                )));
                thread::spawn(move || {
                    wolfssl_server
                        .lock()
                        .unwrap()
                        .wait()
                        .expect("wolfssl server stopped unexpectedly");
                })
            };

            // Wait for the server to start
            thread::sleep(std::time::Duration::from_secs(1));

            let mut root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let certs = rustls_pemfile::certs(&mut BufReader::new(
                &mut File::open(current_dir_string.clone() + "/tests/certs/RootCA.pem").unwrap(),
            ))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

            root_store.add_parsable_certificates(certs);

            let config = rustls::ClientConfig::builder_with_provider(
                rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec())
                    .into(),
            )
            .with_protocol_versions(&[&TLS12])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

            let server_name = "localhost".try_into().unwrap();
            let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
            let mut sock = TcpStream::connect("localhost:4443").unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);

            tls.write_all(
                concat!(
                    "GET / HTTP/1.1\r\n",
                    "Host: localhost\r\n",
                    "Connection: close\r\n",
                    "Accept-Encoding: identity\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

            let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite()
            )
            .unwrap();

            let mut plaintext = Vec::new();
            tls.read_to_end(&mut plaintext).unwrap();

            // Convert plaintext to a String
            let plaintext_str = String::from_utf8_lossy(&plaintext);

            // Split the string into lines and take the first line
            if let Some(first_line) = plaintext_str.lines().next() {
                stdout().write_all(first_line.as_bytes()).unwrap();
                stdout().write_all(b"\n").unwrap();
            }

            let _ = env::set_current_dir(current_dir_string.clone());

            drop(server_thread);
        }
    }

    #[test]
    fn test_tls13_against_server() {
        let _guard = SERVER_LOCK.lock().unwrap();
        let current_dir = env::current_dir().unwrap();
        let current_dir_string = current_dir.to_string_lossy().into_owned();

        let ciphers = [
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS13_AES_128_GCM_SHA256,
            TLS13_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let server_thread = {
                let wolfssl_server = Arc::new(Mutex::new(start_wolfssl_server(
                    current_dir_string.clone(),
                    TLSV1_3,
                )));
                thread::spawn(move || {
                    wolfssl_server
                        .lock()
                        .unwrap()
                        .wait()
                        .expect("wolfssl server stopped unexpectedly");
                })
            };

            // Wait for the server to start
            thread::sleep(std::time::Duration::from_secs(1));

            let mut root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let certs = rustls_pemfile::certs(&mut BufReader::new(
                &mut File::open(current_dir_string.clone() + "/tests/certs/RootCA.pem").unwrap(),
            ))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

            root_store.add_parsable_certificates(certs);

            let config = rustls::ClientConfig::builder_with_provider(
                rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec())
                    .into(),
            )
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

            let server_name = "localhost".try_into().unwrap();
            let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
            let mut sock = TcpStream::connect("localhost:4443").unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);

            tls.write_all(
                concat!(
                    "GET / HTTP/1.1\r\n",
                    "Host: localhost\r\n",
                    "Connection: close\r\n",
                    "Accept-Encoding: identity\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

            let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite()
            )
            .unwrap();

            let mut plaintext = Vec::new();
            tls.read_to_end(&mut plaintext).unwrap();

            // Convert plaintext to a String
            let plaintext_str = String::from_utf8_lossy(&plaintext);

            // Split the string into lines and take the first line
            if let Some(first_line) = plaintext_str.lines().next() {
                stdout().write_all(first_line.as_bytes()).unwrap();
                stdout().write_all(b"\n").unwrap();
            }

            let _ = env::set_current_dir(current_dir_string.clone());

            drop(server_thread);
        }
    }

    #[test]
    fn test_tl12_against_website() {
        let ciphers = [
            TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let config = rustls::ClientConfig::builder_with_provider(
                rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec())
                    .into(),
            )
            .with_protocol_versions(&[&TLS12])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

            let server_name = "www.rust-lang.org".try_into().unwrap();
            let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
            let mut sock = TcpStream::connect("www.rust-lang.org:443").unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);

            tls.write_all(
                concat!(
                    "GET / HTTP/1.1\r\n",
                    "Host: www.rust-lang.org\r\n",
                    "Connection: close\r\n",
                    "Accept-Encoding: identity\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

            let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite()
            )
            .unwrap();

            let mut plaintext = Vec::new();
            tls.read_to_end(&mut plaintext).unwrap();

            // Convert plaintext to a String
            let plaintext_str = String::from_utf8_lossy(&plaintext);

            // Split the string into lines and take the first line
            if let Some(first_line) = plaintext_str.lines().next() {
                stdout().write_all(first_line.as_bytes()).unwrap();
                stdout().write_all(b"\n").unwrap();
            }
        }
    }

    #[test]
    fn test_tl13_against_website() {
        let ciphers = [
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS13_AES_128_GCM_SHA256,
            TLS13_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let config = rustls::ClientConfig::builder_with_provider(
                rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec())
                    .into(),
            )
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

            let server_name = "www.rust-lang.org".try_into().unwrap();
            let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
            let mut sock = TcpStream::connect("www.rust-lang.org:443").unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);

            tls.write_all(
                concat!(
                    "GET / HTTP/1.1\r\n",
                    "Host: www.rust-lang.org\r\n",
                    "Connection: close\r\n",
                    "Accept-Encoding: identity\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

            let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite(),
            )
            .unwrap();

            let mut plaintext = Vec::new();
            tls.read_to_end(&mut plaintext).unwrap();

            // Convert plaintext to a String
            let plaintext_str = String::from_utf8_lossy(&plaintext);

            // Split the string into lines and take the first line
            if let Some(first_line) = plaintext_str.lines().next() {
                stdout().write_all(first_line.as_bytes()).unwrap();
                stdout().write_all(b"\n").unwrap();
            }
        }
    }

    #[test]
    fn ecdsa_sign_and_verify() {
        use der::{asn1::ObjectIdentifier, Encode};
        use sec1::{EcParameters, EcPrivateKey};
        use wolfssl_wolfcrypt::{ecc::ECC, random::RNG};

        let wolfcrypt_default_provider = rustls_wolfcrypt_provider::provider();

        // OIDs for the three named curves (from RFC 5480)
        const OID_P256: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
        const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
        const OID_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

        // (scheme, wolfSSL curve ID, field byte length, curve OID)
        let test_configs = [
            (
                SignatureScheme::ECDSA_NISTP256_SHA256,
                ECC::SECP256R1,
                32usize,
                OID_P256,
            ),
            (
                SignatureScheme::ECDSA_NISTP384_SHA384,
                ECC::SECP384R1,
                48usize,
                OID_P384,
            ),
            (
                SignatureScheme::ECDSA_NISTP521_SHA512,
                ECC::SECP521R1,
                66usize,
                OID_P521,
            ),
        ];

        for (scheme, curve_id, key_size, curve_oid) in test_configs {
            let mut rng = RNG::new().expect("RNG::new failed");

            // Generate ECC key pair via the wolfssl-wolfcrypt safe wrapper.
            let mut ecc = ECC::generate_ex(key_size as i32, &mut rng, curve_id, None, None)
                .expect("ECC::generate_ex failed");

            // Export the raw private scalar d (big-endian, zero-padded to key_size).
            let mut priv_scalar = vec![0u8; key_size];
            let priv_len = ecc
                .export_private(&mut priv_scalar)
                .expect("ECC::export_private failed");
            let priv_scalar = &priv_scalar[..priv_len];

            // Export the uncompressed public point: 04 || Qx || Qy.
            // The maximum X9.63 uncompressed encoding is 1 + 2*key_size bytes.
            let mut pub_x963 = vec![0u8; 1 + 2 * key_size];
            let pub_len = ecc
                .export_x963(&mut pub_x963)
                .expect("ECC::export_x963 failed");
            let pub_x963 = &pub_x963[..pub_len];

            // Build a SEC1 ECPrivateKey DER structure:
            //   SEQUENCE {
            //     INTEGER 1,
            //     OCTET STRING (privkey),
            //     [0] EXPLICIT OID (namedCurve),
            //     [1] EXPLICIT BIT STRING (pubkey)
            //   }
            // Both PrivatePkcs8KeyDer and PrivateSec1KeyDer accept this SEC1 encoding —
            // the provider's key loader auto-detects the encapsulation format.
            let ec_private_key = EcPrivateKey {
                version: 1,
                private_key: priv_scalar,
                parameters: Some(EcParameters::NamedCurve(curve_oid)),
                public_key: Some(pub_x963),
            };
            let der_ecc_key = ec_private_key
                .to_der()
                .expect("EcPrivateKey::to_der failed");

            // Verify with PKCS#8 key container.
            let rustls_private_key_pkcs8 =
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(der_ecc_key.as_slice()));
            sign_and_verify(
                &wolfcrypt_default_provider,
                scheme,
                rustls_private_key_pkcs8.clone_key(),
                pub_x963,
            );

            // Verify with SEC1 key container.
            let rustls_private_key_sec1 =
                PrivateKeyDer::from(PrivateSec1KeyDer::from(der_ecc_key.as_slice()));
            sign_and_verify(
                &wolfcrypt_default_provider,
                scheme,
                rustls_private_key_sec1.clone_key(),
                pub_x963,
            );
        }
    }

    #[test]
    fn eddsa_sign_and_verify() {
        use der::{
            asn1::{ObjectIdentifier, OctetString},
            Encode,
        };
        use pkcs8::{AlgorithmIdentifierRef, PrivateKeyInfo};
        use wolfssl_wolfcrypt::{ed25519::Ed25519, random::RNG};

        let wolfcrypt_default_provider = rustls_wolfcrypt_provider::provider();

        let mut rng = RNG::new().expect("RNG::new failed");

        // Generate Ed25519 key pair via the wolfssl-wolfcrypt safe wrapper.
        let ed = Ed25519::generate(&mut rng).expect("Ed25519::generate failed");

        // Export the 32-byte private seed.
        let mut priv_seed = [0u8; 32];
        ed.export_private_only(&mut priv_seed)
            .expect("Ed25519::export_private_only failed");

        // Export the 32-byte public key.
        let mut pub_key_raw = [0u8; 32];
        ed.export_public(&mut pub_key_raw)
            .expect("Ed25519::export_public failed");

        // Build PKCS#8 PrivateKeyInfo DER for Ed25519 (RFC 8410).
        // AlgorithmIdentifier: { OID 1.3.101.112, no parameters }
        // privateKey: OCTET STRING { OCTET STRING(seed) }   (double-wrapped per RFC 8410 §7)
        let ed25519_oid = ObjectIdentifier::new_unwrap("1.3.101.112");
        let algorithm = AlgorithmIdentifierRef {
            oid: ed25519_oid,
            parameters: None,
        };
        // The inner value is an OCTET STRING wrapping the raw seed bytes.
        let inner_octet_string = OctetString::new(priv_seed.as_slice())
            .expect("OctetString::new for Ed25519 seed failed");
        let inner_der = inner_octet_string
            .to_der()
            .expect("OctetString::to_der for Ed25519 seed failed");
        let pki = PrivateKeyInfo {
            algorithm,
            private_key: &inner_der,
            public_key: None,
        };
        let pkcs8_der = pki.to_der().expect("PrivateKeyInfo::to_der failed");

        let rustls_private_key =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(pkcs8_der.as_slice()));

        sign_and_verify(
            &wolfcrypt_default_provider,
            SignatureScheme::ED25519,
            rustls_private_key.clone_key(),
            pub_key_raw.as_slice(),
        );
    }

    #[test]
    fn rsa_pss_sign_and_verify() {
        init_thread_pool();

        let wolfcrypt_default_provider = rustls_wolfcrypt_provider::provider();
        let schemes = [
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ];

        let test_cases: Vec<_> = schemes
            .iter()
            .flat_map(|&scheme| [2048, 4096].iter().map(move |&key_size| (scheme, key_size)))
            .collect();

        test_cases.par_iter().for_each(|&(scheme, key_size)| {
            generate_and_test_rsa_pkcs8_key(&wolfcrypt_default_provider, scheme, key_size).expect(
                &format!("Failed for scheme {:?} with key size {}", scheme, key_size),
            );
        });

        test_cases.par_iter().for_each(|&(scheme, key_size)| {
            generate_and_test_rsa_pkcs1_key(&wolfcrypt_default_provider, scheme, key_size).expect(
                &format!("Failed for scheme {:?} with key size {}", scheme, key_size),
            );
        });
    }

    fn generate_and_test_rsa_pkcs8_key(
        provider: &CryptoProvider,
        scheme: SignatureScheme,
        key_size: usize,
    ) -> Result<(), anyhow::Error> {
        use pkcs8::EncodePrivateKey;
        use pkcs8::EncodePublicKey;
        use rand_core::OsRng;
        use rsa::RsaPrivateKey;

        // Generate RSA key pair using the pure-Rust rsa crate (already a library dep).
        // OsRng implements CryptoRngCore via rand_core's getrandom feature.
        let priv_key = RsaPrivateKey::new(&mut OsRng, key_size)
            .expect("RsaPrivateKey::new failed");

        // PKCS#8-wrapped DER (AlgorithmIdentifier + PKCS#1 inner key).
        let pkcs8_doc = priv_key
            .to_pkcs8_der()
            .expect("RsaPrivateKey::to_pkcs8_der failed");
        let rustls_private_key =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(pkcs8_doc.as_bytes()));

        // SubjectPublicKeyInfo DER for the verifying side.
        let pub_key = priv_key.to_public_key();
        let pub_der = pub_key
            .to_public_key_der()
            .expect("RsaPublicKey::to_public_key_der failed");

        sign_and_verify(
            provider,
            scheme,
            rustls_private_key.clone_key(),
            pub_der.as_bytes(),
        );

        Ok(())
    }

    #[test]
    fn rsa_pkcs1_sign_and_verify() {
        init_thread_pool();

        let wolfcrypt_default_provider = rustls_wolfcrypt_provider::provider();
        let test_cases: Vec<_> = [
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
        .iter()
        .flat_map(|&scheme| [2048, 4096].iter().map(move |&key_size| (scheme, key_size)))
        .collect();

        test_cases.par_iter().for_each(|&(scheme, key_size)| {
            generate_and_test_rsa_pkcs1_key(&wolfcrypt_default_provider, scheme, key_size).expect(
                &format!("Failed for scheme {:?} with key size {}", scheme, key_size),
            );
        });

        test_cases.par_iter().for_each(|&(scheme, key_size)| {
            generate_and_test_rsa_pkcs8_key(&wolfcrypt_default_provider, scheme, key_size).expect(
                &format!("Failed for scheme {:?} with key size {}", scheme, key_size),
            );
        });
    }

    fn generate_and_test_rsa_pkcs1_key(
        provider: &CryptoProvider,
        scheme: SignatureScheme,
        key_size: usize,
    ) -> Result<(), anyhow::Error> {
        use pkcs1::EncodeRsaPrivateKey;
        use pkcs8::EncodePublicKey;
        use rand_core::OsRng;
        use rsa::RsaPrivateKey;

        // Generate RSA key pair using the pure-Rust rsa crate (already a library dep).
        let priv_key = RsaPrivateKey::new(&mut OsRng, key_size)
            .expect("RsaPrivateKey::new failed");

        // Raw PKCS#1 RSAPrivateKey DER (unwrapped, no AlgorithmIdentifier header).
        // The pkcs1::EncodeRsaPrivateKey blanket-impl extracts this from the PKCS#8
        // encoding produced by pkcs8::EncodePrivateKey.
        let pkcs1_doc = priv_key
            .to_pkcs1_der()
            .expect("RsaPrivateKey::to_pkcs1_der failed");
        let rustls_private_key =
            PrivateKeyDer::from(PrivatePkcs1KeyDer::from(pkcs1_doc.as_bytes()));

        // SubjectPublicKeyInfo DER for the verifying side.
        let pub_key = priv_key.to_public_key();
        let pub_der = pub_key
            .to_public_key_der()
            .expect("RsaPublicKey::to_public_key_der failed");

        sign_and_verify(
            provider,
            scheme,
            rustls_private_key.clone_key(),
            pub_der.as_bytes(),
        );
        Ok(())
    }

    fn sign_and_verify(
        provider: &rustls::crypto::CryptoProvider,
        scheme: SignatureScheme,
        rustls_private_key: PrivateKeyDer<'static>,
        pub_key: &[u8],
    ) {
        let data = "data to sign and verify".as_bytes();

        // Signing...
        let signing_key = provider
            .key_provider
            .load_private_key(rustls_private_key)
            .unwrap();

        let signer = signing_key
            .choose_scheme(&[scheme])
            .expect("signing provider supports this scheme");
        let signature = signer.sign(data).unwrap();

        // Verifying...
        let algs = provider
            .signature_verification_algorithms
            .mapping
            .iter()
            .find(|(k, _v)| *k == scheme)
            .map(|(_k, v)| *v)
            .expect("verifying provider supports this scheme");
        assert!(!algs.is_empty());
        assert!(algs
            .iter()
            .any(|alg| { alg.verify_signature(pub_key, data, &signature).is_ok() }));
    }
}
