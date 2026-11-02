//! Independent Shamir 3-of-5 sharing over GF(256).
//!
//! This is threshold confidentiality, not share authentication.
//! All received shares must be authenticated by the surrounding
//! signed protocol before reconstruction.

use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

pub const SHARE_COUNT: usize = 5;
pub const THRESHOLD: usize = 3;
const MAX_SECRET_BYTES: usize = 4096;

pub type SecretShare = Zeroizing<Vec<u8>>;

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;

    for _ in 0..8 {
        result ^= a & 0u8.wrapping_sub(b & 1);

        let high = a >> 7;
        a = (a << 1) ^ (0x1b & 0u8.wrapping_sub(high));
        b >>= 1;
    }

    result
}

fn gf_pow(mut base: u8, mut exponent: u16) -> u8 {
    let mut result = 1u8;

    while exponent > 0 {
        let mask = 0u8.wrapping_sub((exponent & 1) as u8);
        let candidate = gf_mul(result, base);
        result = (result & !mask) | (candidate & mask);

        base = gf_mul(base, base);
        exponent >>= 1;
    }

    result
}

fn gf_inverse(value: u8) -> Result<u8, &'static str> {
    if value == 0 {
        return Err("Zero has no finite-field inverse");
    }

    Ok(gf_pow(value, 254))
}

pub fn split_3_of_5(secret: &[u8]) -> Result<[SecretShare; SHARE_COUNT], &'static str> {
    if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
        return Err("Invalid secret length");
    }

    // Two independently random coefficients per secret byte.
    // Polynomial: f(x) = secret + a*x + b*x^2.
    let mut coefficient_a = Zeroizing::new(vec![0u8; secret.len()]);

    let mut coefficient_b = Zeroizing::new(vec![0u8; secret.len()]);

    OsRng.fill_bytes(&mut coefficient_a);
    OsRng.fill_bytes(&mut coefficient_b);

    let mut shares: [SecretShare; SHARE_COUNT] = std::array::from_fn(|index| {
        let mut share = vec![0u8; secret.len() + 1];
        share[0] = (index + 1) as u8;
        Zeroizing::new(share)
    });

    for share in &mut shares {
        let x = share[0];

        for index in 0..secret.len() {
            share[index + 1] = secret[index]
                ^ gf_mul(coefficient_a[index], x)
                ^ gf_mul(coefficient_b[index], gf_mul(x, x));
        }
    }

    Ok(shares)
}

pub fn combine_3_of_5(shares: [&[u8]; THRESHOLD]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let len = shares[0].len();

    if len < 2 || len > MAX_SECRET_BYTES + 1 {
        return Err("Invalid share length");
    }

    let mut indexes = [0u8; THRESHOLD];

    for (position, share) in shares.iter().enumerate() {
        if share.len() != len {
            return Err("Inconsistent share lengths");
        }

        let index = share[0];

        if index == 0 || usize::from(index) > SHARE_COUNT {
            return Err("Invalid share index");
        }

        if indexes[..position].contains(&index) {
            return Err("Duplicate share index");
        }

        indexes[position] = index;
    }

    let mut coefficients = [0u8; THRESHOLD];

    for i in 0..THRESHOLD {
        let mut numerator = 1u8;
        let mut denominator = 1u8;

        for j in 0..THRESHOLD {
            if i == j {
                continue;
            }

            numerator = gf_mul(numerator, indexes[j]);
            denominator = gf_mul(denominator, indexes[i] ^ indexes[j]);
        }

        coefficients[i] = gf_mul(numerator, gf_inverse(denominator)?);
    }

    let mut recovered = Zeroizing::new(vec![0u8; len - 1]);

    for index in 0..recovered.len() {
        let mut value = 0u8;

        for i in 0..THRESHOLD {
            value ^= gf_mul(shares[i][index + 1], coefficients[i]);
        }

        recovered[index] = value;
    }

    Ok(recovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_three_of_five_reconstruct_real_secret() {
        let original = Zeroizing::new(b"GHOST AES-256 KEY MATERIAL 12345".to_vec());

        assert_eq!(original.len(), 32);

        let shares = split_3_of_5(&original).unwrap();

        // Verify all ten independent three-share combinations.
        let mut combinations = 0;

        for a in 0..SHARE_COUNT {
            for b in (a + 1)..SHARE_COUNT {
                for c in (b + 1)..SHARE_COUNT {
                    let recovered = combine_3_of_5([&shares[a], &shares[b], &shares[c]]).unwrap();

                    assert_eq!(recovered.as_slice(), original.as_slice());

                    combinations += 1;
                }
            }
        }

        assert_eq!(combinations, 10);
    }

    #[test]
    fn different_splits_use_fresh_randomness() {
        let secret = [42u8; 32];

        let first = split_3_of_5(&secret).unwrap();
        let second = split_3_of_5(&secret).unwrap();

        assert_ne!(*first[0], *second[0]);
    }

    #[test]
    fn invalid_share_sets_fail_closed() {
        let shares = split_3_of_5(&[7u8; 32]).unwrap();

        assert!(combine_3_of_5([&shares[0], &shares[0], &shares[2],]).is_err());

        let mut zero_index = shares[0].to_vec();
        zero_index[0] = 0;

        assert!(combine_3_of_5([&zero_index, &shares[1], &shares[2],]).is_err());

        let truncated = &shares[2][..10];

        assert!(combine_3_of_5([&shares[0], &shares[1], truncated,]).is_err());

        assert!(split_3_of_5(&[]).is_err());
    }
}
