use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const DOMAIN: &[u8] = b"GHOST-EVAL-POW-V1";
const MAX_WIRE: usize = 45_000;
const MAX_ENVELOPE: usize = 60_000;
const DIFFICULTY: u32 = 16;
const MAX_BURST: u8 = 4;
const REFILL_SECONDS: u64 = 3;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    nonce: u64,
    wire: String,
}

fn proof_ok(digest: &[u8; 32], nonce: u64) -> bool {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(digest);
    h.update(nonce.to_be_bytes());

    let result = h.finalize();

    result[0] == 0 && result[1] == 0 && DIFFICULTY == 16
}

pub fn make_pow_packet(wire: &[u8]) -> Result<Vec<u8>, String> {
    if wire.is_empty() || wire.len() > MAX_WIRE {
        return Err("Invalid inner size".into());
    }

    let digest: [u8; 32] = Sha256::digest(wire).into();

    let nonce = (0..=u64::MAX)
        .find(|n| proof_ok(&digest, *n))
        .ok_or("No valid PoW nonce")?;

    let out = serde_json::to_vec(&Envelope {
        version: 1,
        nonce,
        wire: B64.encode(wire),
    })
    .map_err(|e| e.to_string())?;

    if out.len() > MAX_ENVELOPE {
        return Err("Oversized PoW envelope".into());
    }

    Ok(out)
}

pub fn verify_pow_packet(packet: &[u8]) -> Result<Vec<u8>, String> {
    if packet.is_empty() || packet.len() > MAX_ENVELOPE {
        return Err("Oversized inbound packet".into());
    }

    let e: Envelope =
        serde_json::from_slice(packet).map_err(|_| "Malformed PoW envelope".to_owned())?;

    if e.version != 1 {
        return Err("Unknown PoW version".into());
    }

    let wire = B64
        .decode(e.wire)
        .map_err(|_| "Invalid encoding".to_owned())?;

    if wire.is_empty() || wire.len() > MAX_WIRE {
        return Err("Invalid wire size".into());
    }

    let digest: [u8; 32] = Sha256::digest(&wire).into();

    if !proof_ok(&digest, e.nonce) {
        return Err("Invalid proof of work".into());
    }

    Ok(wire)
}

pub struct RateLimiter {
    tokens: u8,
    last: Instant,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            tokens: MAX_BURST,
            last: Instant::now(),
        }
    }

    pub fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now
            .checked_duration_since(self.last)
            .unwrap_or(Duration::ZERO);

        let count = elapsed.as_secs() / REFILL_SECONDS;

        if count > 0 {
            self.tokens = (u64::from(self.tokens) + count).min(u64::from(MAX_BURST)) as u8;

            // Preserve sub-interval time rather than discarding it.
            self.last += Duration::from_secs(count * REFILL_SECONDS);
        }

        if self.tokens == 0 {
            return false;
        }

        self.tokens -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_of_work_is_real_and_verifiable() {
        let p = make_pow_packet(b"encrypted payload").unwrap();

        assert_eq!(verify_pow_packet(&p).unwrap(), b"encrypted payload");
    }

    #[test]
    fn tampering_unsupported_version_and_oversize_rejected() {
        let p = make_pow_packet(b"good packet").unwrap();

        let mut e: Envelope = serde_json::from_slice(&p).unwrap();

        e.wire = B64.encode(b"tampered packet");

        assert!(verify_pow_packet(&serde_json::to_vec(&e).unwrap()).is_err());

        e.version = 2;

        assert!(verify_pow_packet(&serde_json::to_vec(&e).unwrap()).is_err());

        assert!(verify_pow_packet(&vec![0; 60_001]).is_err());
    }

    #[test]
    fn rate_limit_is_enforced() {
        let mut r = RateLimiter::new();
        let now = Instant::now();

        for _ in 0..4 {
            assert!(r.allow(now));
        }

        assert!(!r.allow(now));

        assert!(r.allow(now + Duration::from_secs(3)));

        assert!(!r.allow(now + Duration::from_secs(3)));
    }
    #[test]
    fn real_pow_nonce_tampering_is_rejected() {
        let original = make_pow_packet(b"signed and encrypted payload").unwrap();
        let mut env: Envelope = serde_json::from_slice(&original).unwrap();
        let digest: [u8; 32] = Sha256::digest(b"signed and encrypted payload").into();
        let mut replacement = env.nonce.wrapping_add(1);
        while proof_ok(&digest, replacement) {
            replacement = replacement.wrapping_add(1);
        }
        env.nonce = replacement;
        let tampered = serde_json::to_vec(&env).unwrap();
        assert!(verify_pow_packet(&tampered).is_err());
    }

    #[test]
    fn rate_limiter_preserves_fractional_refill() {
        let mut limiter = RateLimiter::new();
        let t = Instant::now();
        for _ in 0..4 { assert!(limiter.allow(t)); }
        assert!(!limiter.allow(t + Duration::from_secs(2)));
        assert!(limiter.allow(t + Duration::from_secs(4)));
        assert!(!limiter.allow(t + Duration::from_secs(5)));
        assert!(limiter.allow(t + Duration::from_secs(6)));
    }

}
