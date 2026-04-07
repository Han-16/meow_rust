use ark_bn254::{Fr, G1Affine};
use ark_crypto_primitives::sponge::{
    poseidon::{traits::find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField, Zero};
use sha3::{Digest, Keccak256};

use crate::crypto::CryptoError;

fn fr_to_be_bytes(x: &Fr) -> [u8; 32] {
    let src = x.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(src.len());
    out[start..start + src.len()].copy_from_slice(&src);
    out
}

pub fn hash_elements(elements: &[Fr]) -> Fr {
    let mut hasher = Keccak256::new();
    for e in elements {
        hasher.update(fr_to_be_bytes(e));
    }
    let digest = hasher.finalize();
    Fr::from_be_bytes_mod_order(&digest)
}

pub fn fp_to_fr<F: PrimeField>(fp: &F) -> Fr {
    Fr::from_be_bytes_mod_order(&fp.into_bigint().to_bytes_be())
}

pub fn hash_point(point: &G1Affine) -> Fr {
    if point.is_zero() {
        return Fr::zero();
    }
    let x = fp_to_fr(&point.x().expect("point is not infinity"));
    let y = fp_to_fr(&point.y().expect("point is not infinity"));
    hash_elements(&[x, y])
}

pub fn generate_challenge_vector(seed: Fr, size: usize) -> Vec<Fr> {
    let mut out = Vec::with_capacity(size);
    let mut cur = seed;
    for _ in 0..size {
        cur = hash_elements(&[cur]);
        out.push(cur);
    }
    out
}

pub fn generate_unique_indices(seed: Fr, n: usize, l: usize) -> Result<Vec<usize>, CryptoError> {
    if l > n {
        return Err(CryptoError::InvalidInputLength(
            "requested indices exceed pool",
        ));
    }
    if n == 0 {
        return Err(CryptoError::EmptyInput);
    }

    let mut out = Vec::with_capacity(l);
    let mut selected = vec![false; n];
    let mut cur = seed;
    while out.len() < l {
        cur = hash_elements(&[cur]);
        let be = cur.into_bigint().to_bytes_be();
        let mut last8 = [0u8; 8];
        let copy_start = be.len().saturating_sub(8);
        last8[8 - (be.len() - copy_start)..].copy_from_slice(&be[copy_start..]);
        let idx = u64::from_be_bytes(last8) as usize % n;
        if !selected[idx] {
            selected[idx] = true;
            out.push(idx);
        }
    }
    Ok(out)
}

pub fn poseidon_sponge_config_bn254() -> PoseidonConfig<Fr> {
    let rate = 2usize;
    let full_rounds = 8usize;
    let partial_rounds = 56usize;
    let alpha = 5u64;
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );
    PoseidonConfig {
        full_rounds,
        partial_rounds,
        alpha,
        ark,
        mds,
        rate,
        capacity: 1,
    }
}

pub fn poseidon_hash_elements_bn254(cfg: &PoseidonConfig<Fr>, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::<Fr>::new(cfg);
    sponge.absorb(&inputs.to_vec());
    sponge.squeeze_field_elements::<Fr>(1)[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_elements_deterministic() {
        let a = hash_elements(&[Fr::from(1u64), Fr::from(2u64)]);
        let b = hash_elements(&[Fr::from(1u64), Fr::from(2u64)]);
        assert_eq!(a, b);
    }

    #[test]
    fn test_generate_unique_indices() {
        let indices = generate_unique_indices(Fr::from(123u64), 32, 8).unwrap();
        assert_eq!(indices.len(), 8);
        let mut dedup = indices.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(dedup.len(), 8);
    }
}
