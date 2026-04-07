use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use rand::Rng;

use crate::crypto::hash::{hash_elements, hash_point};
use crate::crypto::pedersen::{pedersen_commit_blinded, CommitKey};
use crate::crypto::CryptoError;

#[derive(Clone, Debug)]
pub struct CPLinkProof {
    pub r1: G1Affine,
    pub r2: G1Affine,
    pub z: Vec<Fr>,
    pub t1: Fr,
    pub t2: Fr,
}

fn compute_cp_link_challenge(c1: &G1Affine, c2: &G1Affine, r1: &G1Affine, r2: &G1Affine) -> Fr {
    hash_elements(&[
        hash_point(c1),
        hash_point(c2),
        hash_point(r1),
        hash_point(r2),
    ])
}

fn weighted_sum(vectors: &[Vec<Fr>], r: Fr) -> Result<Vec<Fr>, CryptoError> {
    if vectors.is_empty() {
        return Ok(Vec::new());
    }
    let k = vectors[0].len();
    if vectors.iter().any(|v| v.len() != k) {
        return Err(CryptoError::InvalidInputLength(
            "proof vector lengths mismatch",
        ));
    }
    let mut out = vec![Fr::zero(); k];
    let mut weight = Fr::one();
    for vec_i in vectors {
        for (acc, z) in out.iter_mut().zip(vec_i.iter()) {
            *acc += *z * weight;
        }
        weight *= r;
    }
    Ok(out)
}

pub fn prove_cp_link<R: Rng>(
    x: &[Fr],
    r1: Fr,
    r2: Fr,
    ck1: &CommitKey,
    ck2: &CommitKey,
    rng: &mut R,
) -> Result<CPLinkProof, CryptoError> {
    if x.len() != ck1.g.len() || x.len() != ck2.g.len() {
        return Err(CryptoError::InvalidInputLength(
            "witness vector and commit keys must match",
        ));
    }

    let y = (0..x.len()).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
    let s1 = Fr::rand(rng);
    let s2 = Fr::rand(rng);

    let r1_point = pedersen_commit_blinded(&y, s1, ck1)?;
    let r2_point = pedersen_commit_blinded(&y, s2, ck2)?;

    let c1 = pedersen_commit_blinded(x, r1, ck1)?;
    let c2 = pedersen_commit_blinded(x, r2, ck2)?;
    let challenge = compute_cp_link_challenge(&c1, &c2, &r1_point, &r2_point);

    let z = y
        .iter()
        .zip(x.iter())
        .map(|(yi, xi)| *yi + challenge * xi)
        .collect::<Vec<_>>();
    let t1 = s1 + challenge * r1;
    let t2 = s2 + challenge * r2;

    Ok(CPLinkProof {
        r1: r1_point,
        r2: r2_point,
        z,
        t1,
        t2,
    })
}

pub fn verify_cp_link(
    c1: &G1Affine,
    c2: &G1Affine,
    proof: &CPLinkProof,
    ck1: &CommitKey,
    ck2: &CommitKey,
) -> Result<bool, CryptoError> {
    if proof.z.len() != ck1.g.len() || proof.z.len() != ck2.g.len() {
        return Err(CryptoError::InvalidInputLength(
            "proof vector and commit keys must match",
        ));
    }

    let challenge = compute_cp_link_challenge(c1, c2, &proof.r1, &proof.r2);

    let lhs1 = pedersen_commit_blinded(&proof.z, proof.t1, ck1)?;
    let rhs1 = (proof.r1.into_group() + c1.mul_bigint(challenge.into_bigint())).into_affine();

    let lhs2 = pedersen_commit_blinded(&proof.z, proof.t2, ck2)?;
    let rhs2 = (proof.r2.into_group() + c2.mul_bigint(challenge.into_bigint())).into_affine();

    Ok(lhs1 == rhs1 && lhs2 == rhs2)
}

pub fn verify_cp_links_batched(
    c1s: &[G1Affine],
    c2s: &[G1Affine],
    proofs: &[CPLinkProof],
    ck1: &CommitKey,
    ck2s: &[CommitKey],
) -> Result<bool, CryptoError> {
    let l = proofs.len();
    if l == 0 {
        return Ok(true);
    }
    if c1s.len() != l || c2s.len() != l || ck2s.len() != l {
        return Err(CryptoError::InvalidInputLength(
            "batch input lengths must match",
        ));
    }

    let challenges = (0..l)
        .map(|i| compute_cp_link_challenge(&c1s[i], &c2s[i], &proofs[i].r1, &proofs[i].r2))
        .collect::<Vec<_>>();

    let mut r = challenges[0];
    for c in challenges.iter().skip(1) {
        r = hash_elements(&[r, *c]);
    }

    let zs = proofs.iter().map(|p| p.z.clone()).collect::<Vec<_>>();
    let z_batched = weighted_sum(&zs, r)?;

    let mut t1_batched = Fr::zero();
    let mut weight = Fr::one();
    for p in proofs {
        t1_batched += p.t1 * weight;
        weight *= r;
    }

    let lhs1 = pedersen_commit_blinded(&z_batched, t1_batched, ck1)?;
    let mut rhs1 = G1Projective::zero();
    let mut w = Fr::one();
    for i in 0..l {
        rhs1 += proofs[i].r1.mul_bigint(w.into_bigint());
        rhs1 += c1s[i].mul_bigint((w * challenges[i]).into_bigint());
        w *= r;
    }
    if lhs1 != rhs1.into_affine() {
        return Ok(false);
    }

    for i in 0..l {
        let ok = verify_cp_link(&c1s[i], &c2s[i], &proofs[i], ck1, &ck2s[i])?;
        if !ok {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pedersen::setup_commit_key;

    #[test]
    fn test_cp_link_single() {
        let mut rng = ark_std::test_rng();
        let ck1 = setup_commit_key(4, &mut rng);
        let ck2 = setup_commit_key(4, &mut rng);
        let x = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let r1 = Fr::from(11u64);
        let r2 = Fr::from(19u64);

        let c1 = pedersen_commit_blinded(&x, r1, &ck1).unwrap();
        let c2 = pedersen_commit_blinded(&x, r2, &ck2).unwrap();
        let proof = prove_cp_link(&x, r1, r2, &ck1, &ck2, &mut rng).unwrap();
        assert!(verify_cp_link(&c1, &c2, &proof, &ck1, &ck2).unwrap());
    }

    #[test]
    fn test_cp_link_batch() {
        let mut rng = ark_std::test_rng();
        let ck1 = setup_commit_key(2, &mut rng);
        let mut c1s = Vec::new();
        let mut c2s = Vec::new();
        let mut proofs = Vec::new();
        let mut ck2s = Vec::new();

        for i in 0..4u64 {
            let ck2 = setup_commit_key(2, &mut rng);
            let x = vec![Fr::from(i + 1), Fr::from(i + 3)];
            let r1 = Fr::from(10 + i);
            let r2 = Fr::from(20 + i);
            let c1 = pedersen_commit_blinded(&x, r1, &ck1).unwrap();
            let c2 = pedersen_commit_blinded(&x, r2, &ck2).unwrap();
            let proof = prove_cp_link(&x, r1, r2, &ck1, &ck2, &mut rng).unwrap();
            c1s.push(c1);
            c2s.push(c2);
            proofs.push(proof);
            ck2s.push(ck2);
        }

        assert!(verify_cp_links_batched(&c1s, &c2s, &proofs, &ck1, &ck2s).unwrap());
    }
}
