//! Independent cryptographic foundation for the limited GHOST showcase.
//!
//! This module does not import or copy the private production crate.
//! The protocol/network integration has not yet been implemented.

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    use pqcrypto_mldsa::mldsa87;
    use pqcrypto_mlkem::mlkem768;
    use pqcrypto_traits::kem::SharedSecret as _;
    use rand::{rngs::OsRng, RngCore};
    use zeroize::Zeroizing;

    #[test]
    fn real_mlkem768_encapsulation_and_decapsulation() {
        let (public_key, secret_key) = mlkem768::keypair();

        let (shared_sender, ciphertext) = mlkem768::encapsulate(&public_key);

        let shared_receiver = mlkem768::decapsulate(&ciphertext, &secret_key);

        assert_eq!(shared_sender.as_bytes(), shared_receiver.as_bytes());
    }

    #[test]
    fn real_mldsa87_signature_and_tamper_rejection() {
        let (public_key, secret_key) = mldsa87::keypair();

        let message = b"GHOST public cryptographic evaluation";

        let signature = mldsa87::detached_sign(message, &secret_key);

        assert!(mldsa87::verify_detached_signature(&signature, message, &public_key).is_ok());

        assert!(
            mldsa87::verify_detached_signature(&signature, b"ALTERED MESSAGE", &public_key)
                .is_err()
        );
    }

    #[test]
    fn real_aes256_gcm_roundtrip_and_tamper_rejection() {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *key);

        let cipher = Aes256Gcm::new_from_slice(&*key).expect("valid AES-256 key length");

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = b"GHOST-public-evaluation-context";
        let plaintext = b"Real encrypted evaluation payload";

        let encrypted = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("real authenticated encryption");

        let decrypted = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &encrypted,
                    aad,
                },
            )
            .expect("real authenticated decryption");

        assert_eq!(decrypted, plaintext);

        let mut altered = encrypted.clone();
        altered[0] ^= 1;

        assert!(cipher
            .decrypt(nonce, Payload { msg: &altered, aad })
            .is_err());

        assert!(cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &encrypted,
                    aad: b"wrong-context"
                }
            )
            .is_err());
    }
}

pub mod primitives;

pub mod shamir;

pub mod sealed_message;

pub mod wire;
