//! Public-only signed network message serialization.
//!
//! No secret keys, plaintext, or production wire types are serialized.
//! Successful decoding verifies the pinned sender's ML-DSA signature.
//! Replay protection, TTL, fragmentation and transport remain separate.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::{
    primitives::verify_mldsa87,
    sealed_message::{signed_transcript, RecipientEnvelope, SealedMessage},
};

// Version 2 uses HKDF-SHA256 to wrap Shamir shares.
const VERSION: u8 = 2;
const MAX_WIRE_BYTES: usize = 65_536;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRecipient {
    index: u8,
    recipient_public_b64: String,
    kem_ciphertext_b64: String,
    encrypted_share_b64: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMessage {
    version: u8,
    message_id_b64: String,
    sender_public_b64: String,
    ciphertext_b64: String,
    recipients: Vec<WireRecipient>,
    signature_b64: String,
}

fn decode_field(value: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(value)
        .map_err(|_| "Invalid wire base64 encoding".to_owned())
}

pub fn encode_wire(message: &SealedMessage) -> Result<Vec<u8>, String> {
    if message.recipients.len() != 5 {
        return Err("Invalid recipient count".into());
    }

    let wire = WireMessage {
        version: VERSION,
        message_id_b64: STANDARD.encode(message.message_id),
        sender_public_b64: STANDARD.encode(&message.sender_public),
        ciphertext_b64: STANDARD.encode(&message.ciphertext),
        recipients: message
            .recipients
            .iter()
            .map(|recipient| WireRecipient {
                index: recipient.index,
                recipient_public_b64: STANDARD.encode(&recipient.recipient_public),
                kem_ciphertext_b64: STANDARD.encode(&recipient.kem_ciphertext),
                encrypted_share_b64: STANDARD.encode(&recipient.encrypted_share),
            })
            .collect(),
        signature_b64: STANDARD.encode(&message.signature),
    };

    let encoded =
        serde_json::to_vec(&wire).map_err(|_| "Failed to encode wire message".to_owned())?;

    if encoded.len() > MAX_WIRE_BYTES {
        return Err("Wire message exceeds size limit".into());
    }

    Ok(encoded)
}

/// Authenticate before making a decoded message available to callers.
/// `trusted_sender_public` must be pinned by the surrounding application.
pub fn decode_authenticated_wire(
    bytes: &[u8],
    trusted_sender_public: &[u8],
) -> Result<SealedMessage, String> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE_BYTES {
        return Err("Invalid wire message length".into());
    }

    let wire: WireMessage =
        serde_json::from_slice(bytes).map_err(|_| "Malformed public wire message".to_owned())?;

    if wire.version != VERSION {
        return Err("Unsupported public wire version".into());
    }

    if wire.recipients.len() != 5 {
        return Err("Invalid recipient count".into());
    }

    let raw_id = decode_field(&wire.message_id_b64)?;
    let message_id: [u8; 16] = raw_id
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid message identifier".to_owned())?;

    let sender_public = decode_field(&wire.sender_public_b64)?;

    if sender_public != trusted_sender_public {
        return Err("Untrusted sender signing key".into());
    }

    if sender_public.is_empty() || sender_public.len() > 4096 {
        return Err("Invalid sender key size".into());
    }

    let ciphertext = decode_field(&wire.ciphertext_b64)?;

    if !(28..=284).contains(&ciphertext.len()) {
        return Err("Invalid encrypted message size".into());
    }

    let signature = decode_field(&wire.signature_b64)?;

    if signature.is_empty() || signature.len() > 8192 {
        return Err("Invalid signature size".into());
    }

    let mut seen_public_keys = HashSet::new();
    let mut recipients = Vec::with_capacity(5);

    for (position, entry) in wire.recipients.into_iter().enumerate() {
        if entry.index != (position + 1) as u8 {
            return Err("Invalid recipient order or index".into());
        }

        let recipient_public = decode_field(&entry.recipient_public_b64)?;
        let kem_ciphertext = decode_field(&entry.kem_ciphertext_b64)?;
        let encrypted_share = decode_field(&entry.encrypted_share_b64)?;

        if recipient_public.is_empty()
            || recipient_public.len() > 2048
            || kem_ciphertext.is_empty()
            || kem_ciphertext.len() > 4096
            || !(28..=512).contains(&encrypted_share.len())
        {
            return Err("Invalid recipient envelope".into());
        }

        if !seen_public_keys.insert(recipient_public.clone()) {
            return Err("Duplicate recipient public key".into());
        }

        recipients.push(RecipientEnvelope {
            index: entry.index,
            recipient_public,
            kem_ciphertext,
            encrypted_share,
        });
    }

    let message = SealedMessage {
        message_id,
        sender_public,
        ciphertext,
        recipients,
        signature,
    };

    let authentic = verify_mldsa87(
        &signed_transcript(&message),
        trusted_sender_public,
        &message.signature,
    )?;

    if !authentic {
        return Err("Invalid signed wire message".into());
    }

    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        primitives::{generate_mldsa87, generate_mlkem768},
        sealed_message::{open_message, seal_message},
    };

    fn fixture() -> (
        SealedMessage,
        crate::primitives::MlDsaKeys,
        [crate::primitives::MlKemKeys; 5],
    ) {
        let sender = generate_mldsa87();
        let receivers = std::array::from_fn(|_| generate_mlkem768());
        let public_keys = std::array::from_fn(|i| receivers[i].public.clone());

        let message = seal_message(
            b"GHOST independent authenticated network payload",
            &sender.public,
            &sender.secret,
            &public_keys,
        )
        .unwrap();

        (message, sender, receivers)
    }

    #[test]
    fn genuine_wire_roundtrip_and_real_decryption() {
        let (message, sender, receivers) = fixture();

        let encoded = encode_wire(&message).unwrap();

        let decoded = decode_authenticated_wire(&encoded, &sender.public).unwrap();

        let recovered = open_message(
            &decoded,
            &sender.public,
            [
                (0, receivers[0].secret.as_slice()),
                (2, receivers[2].secret.as_slice()),
                (4, receivers[4].secret.as_slice()),
            ],
        )
        .unwrap();

        assert_eq!(
            recovered.as_slice(),
            b"GHOST independent authenticated network payload"
        );
    }

    #[test]
    fn forged_wire_and_wrong_sender_are_rejected() {
        let (message, sender, _) = fixture();
        let encoded = encode_wire(&message).unwrap();

        let wrong_sender = generate_mldsa87();

        assert!(decode_authenticated_wire(&encoded, &wrong_sender.public,).is_err());

        let mut altered: serde_json::Value = serde_json::from_slice(&encoded).unwrap();

        altered["ciphertext_b64"] = serde_json::Value::String("AAAA".into());

        let forged = serde_json::to_vec(&altered).unwrap();

        assert!(decode_authenticated_wire(&forged, &sender.public,).is_err());
    }

    #[test]
    fn unsupported_version_malformed_and_oversized_rejected() {
        let (message, sender, _) = fixture();
        let encoded = encode_wire(&message).unwrap();

        let mut changed: serde_json::Value = serde_json::from_slice(&encoded).unwrap();

        changed["version"] = serde_json::json!(99);

        assert!(
            decode_authenticated_wire(&serde_json::to_vec(&changed).unwrap(), &sender.public,)
                .is_err()
        );

        assert!(decode_authenticated_wire(b"not a real wire packet", &sender.public,).is_err());

        assert!(
            decode_authenticated_wire(&vec![0u8; MAX_WIRE_BYTES + 1], &sender.public,).is_err()
        );
    }
}
