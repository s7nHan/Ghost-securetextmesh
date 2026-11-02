use std::collections::HashMap;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use ghost_public_crypto::{
    primitives::{sign_mldsa87, verify_mldsa87},
    wire::decode_authenticated_wire,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ACK_DOMAIN: &[u8] = b"GHOST-PUBLIC-DTN-ACK-V1";
const MAX_WIRE: usize = 65_536;
const MAX_ACK: usize = 60_000;
const RETRY: Duration = Duration::from_secs(2);
const REPLAY_WINDOW: Duration = Duration::from_secs(3600);
const REPLAY_CAPACITY: usize = 1024;

type DtnResult<T> = Result<T, String>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAck {
    pub message_id: [u8; 16],
    pub packet_hash: [u8; 32],
    pub sender_public: Vec<u8>,
    pub receiver_public: Vec<u8>,
    pub signature: Vec<u8>,
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn transcript(ack: &SignedAck) -> Vec<u8> {
    let mut out = Vec::new();
    field(&mut out, ACK_DOMAIN);
    field(&mut out, &ack.message_id);
    field(&mut out, &ack.packet_hash);
    field(&mut out, &ack.sender_public);
    field(&mut out, &ack.receiver_public);
    out
}

/// Only the caller that has successfully decrypted the authenticated
/// message should invoke this function.
pub fn issue_ack(
    message_id: [u8; 16],
    encrypted_wire: &[u8],
    sender_public: &[u8],
    receiver_public: &[u8],
    receiver_secret: &[u8],
) -> DtnResult<Vec<u8>> {
    if encrypted_wire.is_empty() || encrypted_wire.len() > MAX_WIRE {
        return Err("Invalid acknowledged packet size".into());
    }

    let mut ack = SignedAck {
        message_id,
        packet_hash: hash(encrypted_wire),
        sender_public: sender_public.to_vec(),
        receiver_public: receiver_public.to_vec(),
        signature: Vec::new(),
    };

    ack.signature = sign_mldsa87(&transcript(&ack), receiver_secret)?;

    let wire = serde_json::to_vec(&ack).map_err(|e| e.to_string())?;

    if wire.len() > MAX_ACK {
        return Err("ACK exceeds size limit".into());
    }

    Ok(wire)
}

struct Pending {
    id: [u8; 16],
    wire: Vec<u8>,
    digest: [u8; 32],
    sender_public: Vec<u8>,
    receiver_public: Vec<u8>,
    expires_at: Instant,
    retry_at: Instant,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.wire.zeroize();
    }
}

/// Intentionally limited to one pending message for this
/// guided public demonstration. No disk persistence.
#[derive(Default)]
pub struct RamDtnQueue {
    pending: Option<Pending>,
    seen: HashMap<[u8; 16], Instant>,
}

impl RamDtnQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        usize::from(self.pending.is_some())
    }

    pub fn bytes_used(&self) -> usize {
        self.pending.as_ref().map_or(0, |p| p.wire.len())
    }

    pub fn enqueue(
        &mut self,
        wire: Vec<u8>,
        sender_public: &[u8],
        receiver_public: &[u8],
        now: Instant,
        ttl: Duration,
    ) -> DtnResult<[u8; 16]> {
        if self.pending.is_some() {
            return Err("Queue full or duplicate message".into());
        }

        if wire.is_empty() || wire.len() > MAX_WIRE {
            return Err("Invalid encrypted message size".into());
        }

        if ttl.is_zero() || ttl > Duration::from_secs(3600) {
            return Err("Invalid TTL".into());
        }

        if receiver_public.is_empty() {
            return Err("Missing pinned receiver signing key".into());
        }

        let message = decode_authenticated_wire(&wire, sender_public)?;

        let expires_at = now.checked_add(ttl).ok_or("Invalid expiration deadline")?;

        let id = message.message_id;

        self.seen.retain(|_, expiry| *expiry > now);

        if self.seen.contains_key(&id) {
            return Err("Replay rejected".into());
        }

        if self.seen.len() >= REPLAY_CAPACITY {
            return Err("Replay cache at capacity".into());
        }

        let retention = now
            .checked_add(REPLAY_WINDOW)
            .ok_or("Replay deadline overflow")?;

        self.seen.insert(id, retention);

        self.pending = Some(Pending {
            id,
            digest: hash(&wire),
            wire,
            sender_public: sender_public.to_vec(),
            receiver_public: receiver_public.to_vec(),
            expires_at,
            retry_at: now,
        });

        Ok(id)
    }

    pub fn next_due(&self, now: Instant) -> Option<&[u8]> {
        self.pending.as_ref().and_then(|p| {
            if now >= p.retry_at && now < p.expires_at {
                Some(p.wire.as_slice())
            } else {
                None
            }
        })
    }

    /// A publish attempt never removes the pending message.
    pub fn record_attempt(&mut self, now: Instant) -> DtnResult<()> {
        let p = self.pending.as_mut().ok_or("No pending message")?;

        if now >= p.expires_at {
            return Err("Pending message expired".into());
        }

        p.retry_at = now.checked_add(RETRY).ok_or("Invalid retry deadline")?;

        Ok(())
    }

    /// Network caller must additionally verify the ACK's original
    /// authenticated libp2p Peer ID against the pinned receiver.
    pub fn acknowledge(&mut self, wire: &[u8], now: Instant) -> DtnResult<bool> {
        if wire.is_empty() || wire.len() > MAX_ACK {
            return Err("Invalid ACK length".into());
        }

        let ack: SignedAck =
            serde_json::from_slice(wire).map_err(|_| "Malformed ACK".to_owned())?;

        let Some(p) = self.pending.as_ref() else {
            return Ok(false);
        };

        if now >= p.expires_at {
            return Err("Expired delivery".into());
        }

        if ack.message_id != p.id
            || ack.packet_hash != p.digest
            || ack.sender_public != p.sender_public
            || ack.receiver_public != p.receiver_public
        {
            return Err("ACK delivery binding mismatch".into());
        }

        if !verify_mldsa87(&transcript(&ack), &p.receiver_public, &ack.signature)? {
            return Err("Forged delivery ACK".into());
        }

        self.pending = None;
        Ok(true)
    }

    pub fn expire(&mut self, now: Instant) -> bool {
        if self.pending.as_ref().is_some_and(|p| now >= p.expires_at) {
            self.pending = None;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_public_crypto::{
        primitives::{generate_mldsa87, generate_mlkem768},
        sealed_message::seal_message,
        wire::encode_wire,
    };

    fn fixture() -> (
        Vec<u8>,
        [u8; 16],
        ghost_public_crypto::primitives::MlDsaKeys,
        ghost_public_crypto::primitives::MlDsaKeys,
    ) {
        let sender = generate_mldsa87();
        let receiver = generate_mldsa87();
        let keys: [_; 5] = std::array::from_fn(|_| generate_mlkem768());
        let pubs: [Vec<u8>; 5] = std::array::from_fn(|i| keys[i].public.clone());

        let message = seal_message(
            b"GHOST genuine encrypted DTN test",
            &sender.public,
            &sender.secret,
            &pubs,
        )
        .unwrap();

        let wire = encode_wire(&message).unwrap();
        (wire, message.message_id, sender, receiver)
    }

    #[test]
    fn retry_retains_packet_until_valid_ack() {
        let (wire, id, sender, receiver) = fixture();
        let now = Instant::now();
        let mut queue = RamDtnQueue::new();

        queue
            .enqueue(
                wire.clone(),
                &sender.public,
                &receiver.public,
                now,
                Duration::from_secs(60),
            )
            .unwrap();

        assert_eq!(queue.next_due(now), Some(wire.as_slice()));
        queue.record_attempt(now).unwrap();
        assert_eq!(queue.len(), 1);

        assert!(queue.next_due(now + Duration::from_secs(1)).is_none());

        assert_eq!(
            queue.next_due(now + Duration::from_secs(3)),
            Some(wire.as_slice())
        );

        let ack = issue_ack(
            id,
            &wire,
            &sender.public,
            &receiver.public,
            &receiver.secret,
        )
        .unwrap();

        assert!(queue
            .acknowledge(&ack, now + Duration::from_secs(3))
            .unwrap());

        assert_eq!(queue.len(), 0);
        assert_eq!(queue.bytes_used(), 0);
        assert!(!queue.acknowledge(&ack, now).unwrap());
    }

    #[test]
    fn forged_and_wrong_packet_ack_rejected() {
        let (wire, id, sender, receiver) = fixture();
        let attacker = generate_mldsa87();
        let now = Instant::now();
        let mut queue = RamDtnQueue::new();

        queue
            .enqueue(
                wire.clone(),
                &sender.public,
                &receiver.public,
                now,
                Duration::from_secs(60),
            )
            .unwrap();

        let forged = issue_ack(
            id,
            &wire,
            &sender.public,
            &receiver.public,
            &attacker.secret,
        )
        .unwrap();

        assert!(queue.acknowledge(&forged, now).is_err());
        assert_eq!(queue.len(), 1);

        let mut altered = wire.clone();
        altered[10] ^= 1;

        let wrong = issue_ack(
            id,
            &altered,
            &sender.public,
            &receiver.public,
            &receiver.secret,
        )
        .unwrap();

        assert!(queue.acknowledge(&wrong, now).is_err());
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn ttl_and_invalid_wire_fail_closed() {
        let (wire, _, sender, receiver) = fixture();
        let now = Instant::now();
        let mut queue = RamDtnQueue::new();

        assert!(queue
            .enqueue(
                vec![1, 2, 3],
                &sender.public,
                &receiver.public,
                now,
                Duration::from_secs(5),
            )
            .is_err());

        assert!(queue
            .enqueue(
                wire.clone(),
                &sender.public,
                &receiver.public,
                now,
                Duration::ZERO,
            )
            .is_err());

        queue
            .enqueue(
                wire.clone(),
                &sender.public,
                &receiver.public,
                now,
                Duration::from_secs(2),
            )
            .unwrap();

        assert!(queue
            .enqueue(
                wire,
                &sender.public,
                &receiver.public,
                now,
                Duration::from_secs(2),
            )
            .is_err());

        assert!(queue.expire(now + Duration::from_secs(3)));

        assert_eq!(queue.len(), 0);
        assert_eq!(queue.bytes_used(), 0);
    }

    #[test]
    fn signed_message_replay_after_ack_rejected() {
        let (wire, id, sender, receiver) = fixture();
        let now = Instant::now();
        let mut queue = RamDtnQueue::new();

        queue
            .enqueue(
                wire.clone(),
                &sender.public,
                &receiver.public,
                now,
                Duration::from_secs(60),
            )
            .unwrap();

        let ack = issue_ack(
            id,
            &wire,
            &sender.public,
            &receiver.public,
            &receiver.secret,
        )
        .unwrap();

        assert!(queue.acknowledge(&ack, now).unwrap());

        assert!(queue
            .enqueue(
                wire,
                &sender.public,
                &receiver.public,
                now + Duration::from_secs(1),
                Duration::from_secs(60),
            )
            .is_err());
    }
}
