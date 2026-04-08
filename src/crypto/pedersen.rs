use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{scalar_mul::variable_base::ChunkedPippenger, CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, UniformRand};
use rand::Rng;
use rayon::prelude::*;

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

    let mut msm = ChunkedPippenger::<G1Projective>::with_size(data.len() + 1);
    for (m, g) in data.iter().zip(ck.g.iter()) {
        msm.add(g, m.into_bigint());
    }
    msm.add(&ck.h, blinding.into_bigint());
    Ok(msm.finalize().into_affine())
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

    let blindings = (0..matrix.len()).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
    let commitments = matrix
        .par_iter()
        .zip(blindings.par_iter())
        .map(|(row, bl)| pedersen_commit_blinded(row, *bl, ck))
        .collect::<Result<Vec<_>, _>>()?;

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
