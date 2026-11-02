use ghost_public_crypto::wire::decode_authenticated_wire;
use ghost_public_runtime::security::{verify_pow_packet, RateLimiter};
use std::time::{Duration, Instant};

#[test]
fn reject_thousands_of_untrusted_network_packets() {
    let sender = vec![0u8; 2592];
    for n in 1..=4096 {
        let malformed = vec![b'X'; n.min(1024)];
        assert!(verify_pow_packet(&malformed).is_err());
        assert!(decode_authenticated_wire(&malformed, &sender).is_err());
    }
}

#[test]
fn sustained_admission_attack_is_bounded() {
    let mut limiter = RateLimiter::new();
    let now = Instant::now();
    let permitted = (0..100_000).filter(|_| limiter.allow(now)).count();
    assert_eq!(permitted, 4, "admission control failed under burst");
    assert!(limiter.allow(now + Duration::from_secs(3)));
    assert!(!limiter.allow(now + Duration::from_secs(3)));
}

#[test]
fn oversized_attack_does_not_enter_decoder() {
    assert!(verify_pow_packet(&vec![b'X'; 100_000]).is_err());
    assert!(decode_authenticated_wire(&vec![b'X'; 100_000], &[]).is_err());
}
