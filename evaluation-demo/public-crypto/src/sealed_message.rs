//! Independent, limited GHOST public message-crypto workflow.
//!
//! This module performs real cryptographic operations.
//! It is not the production wire protocol or a network transport.
//! Sender identity pinning, network replay protection and packet
//! framing remain separate integration responsibilities.

use rand::{rngs::OsRng, RngCore};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    primitives::{
        decapsulate_mlkem768, decrypt_aes256_gcm, encapsulate_mlkem768, encrypt_aes256_gcm,
        sign_mldsa87, verify_mldsa87,
    },
    shamir::{combine_3_of_5, split_3_of_5},
};

pub type MessageResult<T> = Result<T, String>;

const DOMAIN: &[u8] = b"GHOST-PUBLIC-SEALED-MESSAGE-V1";
const WRAP_DOMAIN: &[u8] = b"GHOST-PUBLIC-MLKEM-SHARE-WRAP-V2-HKDF-SHA256";
const MAX_PLAINTEXT: usize = 256;

#[derive(Clone)]
pub struct RecipientEnvelope {
    pub index: u8,
    pub recipient_public: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub encrypted_share: Vec<u8>,
}

#[derive(Clone)]
pub struct SealedMessage {
    pub message_id: [u8; 16],
    pub sender_public: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub recipients: Vec<RecipientEnvelope>,
    pub signature: Vec<u8>,
}

fn field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn message_aad(id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::from(DOMAIN);
    aad.extend_from_slice(id);
    aad
}

fn share_aad(id: &[u8; 16], index: u8, public_key: &[u8]) -> Vec<u8> {
    let mut aad = Vec::from(WRAP_DOMAIN);
    aad.extend_from_slice(id);
    aad.push(index);
    field(&mut aad, public_key);
    aad
}

fn wrap_key(
    kem_shared_secret: &[u8],
    id: &[u8; 16],
    index: u8,
    public_key: &[u8],
) -> MessageResult<Zeroizing<[u8; 32]>> {
    // HKDF-Extract uses a domain-separated salt; HKDF-Expand binds the
    // message ID, share index and recipient key to the derived wrap key.
    let hk = Hkdf::<Sha256>::new(Some(WRAP_DOMAIN), kem_shared_secret);
    let mut info = Vec::new();
    field(&mut info, id);
    info.push(index);
    field(&mut info, public_key);

    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *key)
        .map_err(|_| "HKDF-SHA256 expansion failed".to_owned())?;
    Ok(key)
}

pub(crate) fn signed_transcript(message: &SealedMessage) -> Vec<u8> {
    let mut transcript = Vec::new();

    field(&mut transcript, DOMAIN);
    field(&mut transcript, &message.message_id);
    field(&mut transcript, &message.sender_public);
    field(&mut transcript, &message.ciphertext);

    transcript.extend_from_slice(&(message.recipients.len() as u32).to_be_bytes());

    for recipient in &message.recipients {
        transcript.push(recipient.index);
        field(&mut transcript, &recipient.recipient_public);
        field(&mut transcript, &recipient.kem_ciphertext);
        field(&mut transcript, &recipient.encrypted_share);
    }

    transcript
}

/// Seal a real message for five independently generated ML-KEM keys.
/// A separate trusted channel must bind the sender signing key.
pub fn seal_message(
    plaintext: &[u8],
    sender_public: &[u8],
    sender_secret: &[u8],
    recipients_public: &[Vec<u8>; 5],
) -> MessageResult<SealedMessage> {
    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT {
        return Err("Invalid public demo plaintext length".into());
    }

    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);

    let mut aes_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *aes_key);

    let ciphertext = encrypt_aes256_gcm(&*aes_key, plaintext, &message_aad(&id))?;

    let shares = split_3_of_5(&*aes_key).map_err(str::to_owned)?;

    let mut recipients = Vec::with_capacity(5);

    for (position, public_key) in recipients_public.iter().enumerate() {
        let index = (position + 1) as u8;

        let (kem_ciphertext, shared_secret) = encapsulate_mlkem768(public_key)?;

        let key = wrap_key(&shared_secret, &id, index, public_key)?;

        let encrypted_share = encrypt_aes256_gcm(
            &*key,
            shares[position].as_slice(),
            &share_aad(&id, index, public_key),
        )?;

        recipients.push(RecipientEnvelope {
            index,
            recipient_public: public_key.clone(),
            kem_ciphertext,
            encrypted_share,
        });
    }

    let mut message = SealedMessage {
        message_id: id,
        sender_public: sender_public.to_vec(),
        ciphertext,
        recipients,
        signature: Vec::new(),
    };

    message.signature = sign_mldsa87(&signed_transcript(&message), sender_secret)?;

    // Reject a mismatched supplied signing key before any packet is sent.
    if !verify_mldsa87(&signed_transcript(&message), sender_public, &message.signature)? {
        return Err("Sender signing public/secret key mismatch".into());
    }

    Ok(message)
}

/// Verify the pinned sender and recover plaintext from three
/// distinct recipient secrets. A network caller must separately
/// enforce replay protection, TTL, and authenticated routing.
pub fn open_message(
    message: &SealedMessage,
    trusted_sender_public: &[u8],
    selected: [(usize, &[u8]); 3],
) -> MessageResult<Zeroizing<Vec<u8>>> {
    if message.sender_public != trusted_sender_public {
        return Err("Untrusted sender identity".into());
    }

    if message.recipients.len() != 5
        || message.ciphertext.len() < 28
        || message.ciphertext.len() > MAX_PLAINTEXT + 28
    {
        return Err("Invalid message envelope".into());
    }

    for (position, recipient) in message.recipients.iter().enumerate() {
        if recipient.index != (position + 1) as u8 {
            return Err("Invalid recipient ordering".into());
        }
    }

    let authenticated = verify_mldsa87(
        &signed_transcript(message),
        trusted_sender_public,
        &message.signature,
    )?;

    if !authenticated {
        return Err("Message signature verification failed".into());
    }

    let mut recovered_shares = Vec::with_capacity(3);
    let mut seen = [false; 5];

    for (position, recipient_secret) in selected {
        if position >= 5 || seen[position] {
            return Err("Invalid or repeated recipient selection".into());
        }

        seen[position] = true;

        let recipient = &message.recipients[position];

        let shared_secret = decapsulate_mlkem768(&recipient.kem_ciphertext, recipient_secret)?;

        let key = wrap_key(
            &shared_secret,
            &message.message_id,
            recipient.index,
            &recipient.recipient_public,
        )?;

        let share = decrypt_aes256_gcm(
            &*key,
            &recipient.encrypted_share,
            &share_aad(
                &message.message_id,
                recipient.index,
                &recipient.recipient_public,
            ),
        )?;

        if share.len() != 33 || share[0] != recipient.index {
            return Err("Invalid decrypted Shamir share".into());
        }

        recovered_shares.push(share);
    }

    let aes_key = combine_3_of_5([
        recovered_shares[0].as_slice(),
        recovered_shares[1].as_slice(),
        recovered_shares[2].as_slice(),
    ])
    .map_err(str::to_owned)?;

    if aes_key.len() != 32 {
        return Err("Invalid reconstructed AES key".into());
    }

    decrypt_aes256_gcm(
        aes_key.as_slice(),
        &message.ciphertext,
        &message_aad(&message.message_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::primitives::{generate_mldsa87, generate_mlkem768};

    #[test]
    fn real_five_recipient_three_share_delivery() {
        let sender = generate_mldsa87();

        let receivers: [_; 5] = std::array::from_fn(|_| generate_mlkem768());

        let public_keys: [Vec<u8>; 5] = std::array::from_fn(|i| receivers[i].public.clone());

        let plaintext = b"GHOST genuine independently encrypted message";

        let sealed = seal_message(plaintext, &sender.public, &sender.secret, &public_keys).unwrap();

        let mut combinations = 0;

        for a in 0..5 {
            for b in (a + 1)..5 {
                for c in (b + 1)..5 {
                    let opened = open_message(
                        &sealed,
                        &sender.public,
                        [
                            (a, receivers[a].secret.as_slice()),
                            (b, receivers[b].secret.as_slice()),
                            (c, receivers[c].secret.as_slice()),
                        ],
                    )
                    .unwrap();

                    assert_eq!(opened.as_slice(), plaintext);
                    combinations += 1;
                }
            }
        }

        assert_eq!(combinations, 10);
    }

    #[test]
    fn real_tampering_and_wrong_identity_are_rejected() {
        let sender = generate_mldsa87();
        let other_sender = generate_mldsa87();

        let receivers: [_; 5] = std::array::from_fn(|_| generate_mlkem768());

        let public_keys: [Vec<u8>; 5] = std::array::from_fn(|i| receivers[i].public.clone());

        let sealed = seal_message(
            b"Authenticated private showcase message",
            &sender.public,
            &sender.secret,
            &public_keys,
        )
        .unwrap();

        let selection = || {
            [
                (0, receivers[0].secret.as_slice()),
                (1, receivers[1].secret.as_slice()),
                (2, receivers[2].secret.as_slice()),
            ]
        };

        assert!(open_message(&sealed, &other_sender.public, selection(),).is_err());

        let mut tampered = sealed.clone();
        tampered.ciphertext[15] ^= 1;

        assert!(open_message(&tampered, &sender.public, selection(),).is_err());

        let mut altered_share = sealed.clone();
        altered_share.recipients[0].encrypted_share[15] ^= 1;

        assert!(open_message(&altered_share, &sender.public, selection(),).is_err());

        assert!(open_message(
            &sealed,
            &sender.public,
            [
                (0, receivers[1].secret.as_slice()),
                (1, receivers[1].secret.as_slice()),
                (2, receivers[2].secret.as_slice()),
            ],
        )
        .is_err());

        assert!(open_message(
            &sealed,
            &sender.public,
            [
                (0, receivers[0].secret.as_slice()),
                (0, receivers[0].secret.as_slice()),
                (2, receivers[2].secret.as_slice()),
            ],
        )
        .is_err());
    }
    #[test]
    fn sender_public_secret_mismatch_rejected_before_wire() {
        let signer = generate_mldsa87();
        let wrong_signer = generate_mldsa87();
        let receivers: [_; 5] = std::array::from_fn(|_| generate_mlkem768());
        let pubs: [Vec<u8>; 5] = std::array::from_fn(|i| receivers[i].public.clone());
        assert!(seal_message(
            b"Authenticated test",
            &signer.public,
            &wrong_signer.secret,
            &pubs,
        ).is_err());
    }

}
