use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, UniformRand, Zero};
use rand::Rng;

use crate::crypto::CryptoError;

#[derive(Clone, Debug)]
pub struct CommitKey {
    pub g: Vec<G1Affine>,
    pub h: G1Affine,
}

pub fn setup_commit_key<R: Rng>(k: usize, rng: &mut R) -> CommitKey {
    let gen = G1Projective::generator();
    let g = (0..k)
        .map(|_| (gen * Fr::rand(rng)).into_affine())
        .collect::<Vec<_>>();
    let h = (gen * Fr::rand(rng)).into_affine();
    CommitKey { g, h }
}

pub fn pedersen_commit_blinded(
    data: &[Fr],
    blinding: Fr,
    ck: &CommitKey,
) -> Result<G1Affine, CryptoError> {
    if data.len() != ck.g.len() {
        return Err(CryptoError::InvalidInputLength(
            "data length must match commit key length",
        ));
    }

    let mut acc = G1Projective::zero();
    for (m, g) in data.iter().zip(ck.g.iter()) {
        acc += g.mul_bigint(m.into_bigint());
    }
    acc += ck.h.mul_bigint(blinding.into_bigint());
    Ok(acc.into_affine())
}

pub fn batch_pedersen_commit_blinded<R: Rng>(
    matrix: &[Vec<Fr>],
    ck: &CommitKey,
    rng: &mut R,
) -> Result<(Vec<G1Affine>, Vec<Fr>), CryptoError> {
    if matrix.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    if matrix.iter().any(|row| row.len() != ck.g.len()) {
        return Err(CryptoError::InvalidInputLength(
            "all rows must match commit key length",
        ));
    }

    let mut commitments = Vec::with_capacity(matrix.len());
    let mut blindings = Vec::with_capacity(matrix.len());
    for row in matrix {
        let bl = Fr::rand(rng);
        let c = pedersen_commit_blinded(row, bl, ck)?;
        commitments.push(c);
        blindings.push(bl);
    }
    Ok((commitments, blindings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_commit_roundtrip() {
        let mut rng = ark_std::test_rng();
        let ck = setup_commit_key(4, &mut rng);
        let m = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let r = Fr::from(9u64);
        let c1 = pedersen_commit_blinded(&m, r, &ck).unwrap();
        let c2 = pedersen_commit_blinded(&m, r, &ck).unwrap();
        assert_eq!(c1, c2);
    }
}
