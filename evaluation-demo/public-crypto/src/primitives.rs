use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};

use pqcrypto_mldsa::mldsa87;
use pqcrypto_mlkem::mlkem768;

use pqcrypto_traits::{
    kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _},
    sign::{DetachedSignature as _, PublicKey as _, SecretKey as _},
};

use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

type CryptoResult<T> = Result<T, String>;

pub struct MlKemKeys {
    pub public: Vec<u8>,
    pub secret: Zeroizing<Vec<u8>>,
}

pub struct MlDsaKeys {
    pub public: Vec<u8>,
    pub secret: Zeroizing<Vec<u8>>,
}

pub fn generate_mlkem768() -> MlKemKeys {
    let (public, secret) = mlkem768::keypair();

    MlKemKeys {
        public: public.as_bytes().to_vec(),
        secret: Zeroizing::new(secret.as_bytes().to_vec()),
    }
}

pub fn encapsulate_mlkem768(public_key: &[u8]) -> CryptoResult<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let public =
        mlkem768::PublicKey::from_bytes(public_key).map_err(|_| "Invalid ML-KEM public key")?;

    let (shared, ciphertext) = mlkem768::encapsulate(&public);

    Ok((
        ciphertext.as_bytes().to_vec(),
        Zeroizing::new(shared.as_bytes().to_vec()),
    ))
}

pub fn decapsulate_mlkem768(
    ciphertext: &[u8],
    secret_key: &[u8],
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    let ciphertext =
        mlkem768::Ciphertext::from_bytes(ciphertext).map_err(|_| "Invalid ML-KEM ciphertext")?;

    let secret =
        mlkem768::SecretKey::from_bytes(secret_key).map_err(|_| "Invalid ML-KEM secret key")?;

    let shared = mlkem768::decapsulate(&ciphertext, &secret);

    Ok(Zeroizing::new(shared.as_bytes().to_vec()))
}

pub fn generate_mldsa87() -> MlDsaKeys {
    let (public, secret) = mldsa87::keypair();

    MlDsaKeys {
        public: public.as_bytes().to_vec(),
        secret: Zeroizing::new(secret.as_bytes().to_vec()),
    }
}

pub fn sign_mldsa87(message: &[u8], secret_key: &[u8]) -> CryptoResult<Vec<u8>> {
    let secret =
        mldsa87::SecretKey::from_bytes(secret_key).map_err(|_| "Invalid ML-DSA secret key")?;

    let signature = mldsa87::detached_sign(message, &secret);

    Ok(signature.as_bytes().to_vec())
}

pub fn verify_mldsa87(message: &[u8], public_key: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    let public =
        mldsa87::PublicKey::from_bytes(public_key).map_err(|_| "Invalid ML-DSA public key")?;

    let signature = mldsa87::DetachedSignature::from_bytes(signature)
        .map_err(|_| "Invalid ML-DSA signature encoding")?;

    Ok(mldsa87::verify_detached_signature(&signature, message, &public).is_ok())
}

pub fn encrypt_aes256_gcm(key: &[u8], plaintext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Invalid AES-256 key")?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "AES-GCM encryption failed")?;

    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

pub fn decrypt_aes256_gcm(
    key: &[u8],
    encrypted: &[u8],
    aad: &[u8],
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    if encrypted.len() < 28 {
        return Err("Invalid AES-GCM envelope".into());
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Invalid AES-256 key")?;

    let (nonce, ciphertext) = encrypted.split_at(12);

    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "AES-GCM authentication failed")?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_mlkem768_roundtrip() {
        let keys = generate_mlkem768();

        let (ciphertext, sender_secret) = encapsulate_mlkem768(&keys.public).unwrap();

        let receiver_secret = decapsulate_mlkem768(&ciphertext, &keys.secret).unwrap();

        assert_eq!(*sender_secret, *receiver_secret);
    }

    #[test]
    fn actual_mldsa87_signature_and_tamper_rejection() {
        let keys = generate_mldsa87();
        let message = b"GHOST PUBLIC REAL SIGNATURE";

        let signature = sign_mldsa87(message, &keys.secret).unwrap();

        assert!(verify_mldsa87(message, &keys.public, &signature).unwrap());

        assert!(!verify_mldsa87(b"ALTERED MESSAGE", &keys.public, &signature).unwrap());
    }

    #[test]
    fn actual_aes256_gcm_with_authenticated_context() {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *key);

        let message = b"GHOST REAL ENCRYPTED PAYLOAD";
        let aad = b"GHOST-PUBLIC-DEMO-V1";

        let encrypted = encrypt_aes256_gcm(&*key, message, aad).unwrap();

        let decrypted = decrypt_aes256_gcm(&*key, &encrypted, aad).unwrap();

        assert_eq!(decrypted.as_slice(), message);

        assert!(decrypt_aes256_gcm(&*key, &encrypted, b"WRONG-CONTEXT").is_err());

        let mut tampered = encrypted;
        tampered[15] ^= 1;

        assert!(decrypt_aes256_gcm(&*key, &tampered, aad).is_err());
    }
}
