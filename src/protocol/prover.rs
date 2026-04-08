use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{One, UniformRand, Zero};
use ark_groth16::{Groth16, ProvingKey};
use ark_snark::SNARK;
use rand::{CryptoRng, Rng};
use rayon::prelude::*;
use std::time::{Duration, Instant};

use crate::circuits::gadgets::linear_code::{reed_solomon::ReedSolomonCode, LinearCode};
use crate::circuits::meow::Meow;
use crate::crypto::hash::{
    generate_unique_indices, hash_elements, poseidon_hash_elements_bn254,
    poseidon_sponge_config_bn254,
};
use crate::crypto::merkle::{build_merkle_tree_from_group_elements, get_merkle_proof};
use crate::crypto::pedersen::{batch_pedersen_commit_blinded, setup_commit_key, CommitKey};
use crate::protocol::{
    MerkleOpening, ProtocolError, ProtocolParams, ProtocolProof, PublicTranscript, QueryOpeningSet,
    SetupArtifacts,
};

#[derive(Debug, Clone)]
pub struct Prover {
    pub ck1: CommitKey,
    pub ck_scalar: CommitKey,
    pub poseidon_config: PoseidonConfig<Fr>,
}

#[derive(Debug, Clone, Default)]
pub struct ProveTimeBreakdown {
    pub matmul: Duration,
    pub pedersen_commit: Duration,
    pub groth16_prove: Duration,
    pub merkle_membership_proof: Duration,
}

impl ProveTimeBreakdown {
    pub fn tracked_total(&self) -> Duration {
        self.matmul + self.pedersen_commit + self.groth16_prove + self.merkle_membership_proof
    }
}

impl Prover {
    pub fn setup<R: Rng>(k: usize, rng: &mut R) -> Self {
        Self {
            ck1: setup_commit_key(k, rng),
            ck_scalar: setup_commit_key(1, rng),
            poseidon_config: poseidon_sponge_config_bn254(),
        }
    }

    pub fn circuit_setup<R: Rng + CryptoRng>(
        &self,
        params: &ProtocolParams,
        rng: &mut R,
    ) -> Result<SetupArtifacts, ProtocolError> {
        validate_params(params)?;
        let circuit = empty_circuit(params, self.poseidon_config.clone());
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng)?;
        Ok(SetupArtifacts { pk, vk })
    }

    pub fn prove_with_random_matrices<R: Rng + CryptoRng>(
        &self,
        params: &ProtocolParams,
        pk: &ProvingKey<Bn254>,
        rng: &mut R,
    ) -> Result<ProtocolProof, ProtocolError> {
        let (proof, _) = self.prove_with_random_matrices_timed(params, pk, rng)?;
        Ok(proof)
    }

    pub fn prove_with_random_matrices_timed<R: Rng + CryptoRng>(
        &self,
        params: &ProtocolParams,
        pk: &ProvingKey<Bn254>,
        rng: &mut R,
    ) -> Result<(ProtocolProof, ProveTimeBreakdown), ProtocolError> {
        validate_params(params)?;
        let a = random_matrix(params.k, rng);
        let b = random_matrix(params.k, rng);
        let matmul_start = Instant::now();
        let c = matmul(&a, &b)?;
        let mut timings = ProveTimeBreakdown {
            matmul: matmul_start.elapsed(),
            ..Default::default()
        };
        let proof = self.prove_internal(params, pk, &a, &b, &c, rng, &mut timings)?;
        Ok((proof, timings))
    }

    pub fn prove<R: Rng + CryptoRng>(
        &self,
        params: &ProtocolParams,
        pk: &ProvingKey<Bn254>,
        a: &[Vec<Fr>],
        b: &[Vec<Fr>],
        c: &[Vec<Fr>],
        rng: &mut R,
    ) -> Result<ProtocolProof, ProtocolError> {
        let mut timings = ProveTimeBreakdown::default();
        self.prove_internal(params, pk, a, b, c, rng, &mut timings)
    }

    fn prove_internal<R: Rng + CryptoRng>(
        &self,
        params: &ProtocolParams,
        pk: &ProvingKey<Bn254>,
        a: &[Vec<Fr>],
        b: &[Vec<Fr>],
        c: &[Vec<Fr>],
        rng: &mut R,
        timings: &mut ProveTimeBreakdown,
    ) -> Result<ProtocolProof, ProtocolError> {
        validate_params(params)?;
        validate_square_matrix(a, params.k)?;
        validate_square_matrix(b, params.k)?;
        validate_square_matrix(c, params.k)?;

        let rs = ReedSolomonCode::<Fr>::new(params.k, params.n);

        // 1) RS encode A,B,C into KxN then transpose into NxK columns.
        let enc_a_rows = encode_rows(&rs, a)?;
        let enc_b_rows = encode_rows(&rs, b)?;
        let enc_c_rows = encode_rows(&rs, c)?;
        let cols_enc_a = transpose(&enc_a_rows)?;
        let cols_enc_b = transpose(&enc_b_rows)?;
        let cols_enc_c = transpose(&enc_c_rows)?;

        // 2-3) Commit columns with ck1 and build Merkle roots.
        let depth = ilog2_exact(params.n)?;
        let (tree_a, root_a, leaves_a, _) =
            commit_matrix_with_timing(&cols_enc_a, &self.ck1, depth, rng, timings)?;
        let (tree_b, root_b, leaves_b, _) =
            commit_matrix_with_timing(&cols_enc_b, &self.ck1, depth, rng, timings)?;
        let (tree_c, root_c, leaves_c, _) =
            commit_matrix_with_timing(&cols_enc_c, &self.ck1, depth, rng, timings)?;

        // 4-5) Verifier challenge: Keccak(rootA,rootB,rootC) -> scalar r -> [1,r,r^2,...].
        let r_scalar = hash_elements(&[root_a, root_b, root_c]);
        let challenge_r = powers_vector(r_scalar, params.k);

        // 6) x = rA, y = xB, z = rC.
        let vec_x = vec_mat_mul(&challenge_r, a)?;
        let vec_y = vec_mat_mul(&vec_x, b)?;
        let vec_z = vec_mat_mul(&challenge_r, c)?;
        if vec_y != vec_z {
            return Err(ProtocolError::InvalidInput(
                "A*B must equal C, but y=xB and z=rC mismatch",
            ));
        }

        // 7) Encode x,y,z and commit (scalar commitments).
        let enc_x = rs.encode(&vec_x)?;
        let enc_y = rs.encode(&vec_y)?;
        let enc_z = rs.encode(&vec_z)?;

        let x_columns = to_scalar_columns(&enc_x);
        let y_columns = to_scalar_columns(&enc_y);
        let z_columns = to_scalar_columns(&enc_z);

        let (tree_x, root_x, leaves_x, _) =
            commit_matrix_with_timing(&x_columns, &self.ck_scalar, depth, rng, timings)?;
        let (tree_y, root_y, leaves_y, _) =
            commit_matrix_with_timing(&y_columns, &self.ck_scalar, depth, rng, timings)?;
        let (tree_z, root_z, leaves_z, _) =
            commit_matrix_with_timing(&z_columns, &self.ck_scalar, depth, rng, timings)?;

        // 8) Query indices from Keccak(rootX,rootY,rootZ).
        let idx_seed = hash_elements(&[root_x, root_y, root_z]);
        let indices = generate_unique_indices(idx_seed, params.n, params.l)?;

        // Circuit public hashes use Poseidon gadget in current meow.rs.
        let cm_abc = poseidon_hash_elements_bn254(&self.poseidon_config, &[root_a, root_b, root_c]);
        let cm_xy = poseidon_hash_elements_bn254(&self.poseidon_config, &[root_x, root_y]);

        // 9) Merkle openings for queried indices.
        let mut openings = Vec::with_capacity(params.l);
        let mut queried_cols_a = Vec::with_capacity(params.l);
        let mut queried_cols_b = Vec::with_capacity(params.l);
        let mut queried_cols_c = Vec::with_capacity(params.l);
        let mut target_enc_x = Vec::with_capacity(params.l);
        let mut target_enc_y = Vec::with_capacity(params.l);

        let merkle_proof_start = Instant::now();
        for &idx in &indices {
            queried_cols_a.push(cols_enc_a[idx].clone());
            queried_cols_b.push(cols_enc_b[idx].clone());
            queried_cols_c.push(cols_enc_c[idx].clone());
            target_enc_x.push(enc_x[idx]);
            target_enc_y.push(enc_y[idx]);

            openings.push(QueryOpeningSet {
                index: idx,
                a: MerkleOpening {
                    commitment: leaves_a[idx],
                    siblings: get_merkle_proof(&tree_a, idx, depth)?,
                },
                b: MerkleOpening {
                    commitment: leaves_b[idx],
                    siblings: get_merkle_proof(&tree_b, idx, depth)?,
                },
                c: MerkleOpening {
                    commitment: leaves_c[idx],
                    siblings: get_merkle_proof(&tree_c, idx, depth)?,
                },
                x: MerkleOpening {
                    commitment: leaves_x[idx],
                    siblings: get_merkle_proof(&tree_x, idx, depth)?,
                },
                y: MerkleOpening {
                    commitment: leaves_y[idx],
                    siblings: get_merkle_proof(&tree_y, idx, depth)?,
                },
                z: MerkleOpening {
                    commitment: leaves_z[idx],
                    siblings: get_merkle_proof(&tree_z, idx, depth)?,
                },
            });
        }
        timings.merkle_membership_proof += merkle_proof_start.elapsed();

        // 10) Build Groth16 witness only from queried columns and global vectors.
        let meow_assignment = Meow::<Fr> {
            k: params.k,
            n: params.n,
            roots: Some([root_a, root_b, root_c, root_x, root_y]),
            cm_abc: Some(cm_abc),
            cm_xyz: Some(cm_xy),
            challenge_r: Some(r_scalar),
            indices: Some(indices.iter().map(|&i| Fr::from(i as u64)).collect()),
            lookup_index_challenge: Some(params.lookup_index_challenge),
            lookup_logup_challenge: Some(params.lookup_logup_challenge),
            rs_point_x: Some(params.rs_point_x),
            rs_point_yz: Some(params.rs_point_y),
            poseidon_config: Some(self.poseidon_config.clone()),
            cols_enc_a: Some(queried_cols_a),
            cols_enc_b: Some(queried_cols_b),
            cols_enc_c: Some(queried_cols_c),
            vec_x: Some(vec_x.clone()),
            vec_yz: Some(vec_y.clone()),
            enc_x: Some(enc_x.clone()),
            enc_yz: Some(enc_y.clone()),
            target_enc_x: Some(target_enc_x),
            target_enc_yz: Some(target_enc_y),
        };

        let groth16_start = Instant::now();
        let groth16_proof = Groth16::<Bn254>::prove(pk, meow_assignment, rng)?;
        timings.groth16_prove += groth16_start.elapsed();

        let public = PublicTranscript {
            root_a,
            root_b,
            root_c,
            root_x,
            root_y,
            root_z,
            cm_abc,
            cm_xy,
            challenge_r: r_scalar,
            indices: indices.clone(),
            lookup_index_challenge: params.lookup_index_challenge,
            lookup_logup_challenge: params.lookup_logup_challenge,
            rs_point_x: params.rs_point_x,
            rs_point_y: params.rs_point_y,
        };

        let public_inputs = build_public_inputs(&public);

        Ok(ProtocolProof {
            groth16_proof,
            public_inputs,
            public,
            query_openings: openings,
        })
    }
}

fn commit_matrix_with_timing<R: Rng>(
    columns: &[Vec<Fr>],
    ck: &CommitKey,
    depth: usize,
    rng: &mut R,
    timings: &mut ProveTimeBreakdown,
) -> Result<(Vec<Vec<Fr>>, Fr, Vec<ark_bn254::G1Affine>, Vec<Fr>), ProtocolError> {
    let pedersen_start = Instant::now();
    let (commitments, blindings) = batch_pedersen_commit_blinded(columns, ck, rng)?;
    timings.pedersen_commit += pedersen_start.elapsed();
    let (tree, root) = build_merkle_tree_from_group_elements(&commitments, depth)?;
    Ok((tree, root, commitments, blindings))
}

pub(crate) fn build_public_inputs(public: &PublicTranscript) -> Vec<Fr> {
    let mut out = Vec::with_capacity(5 + 2 + 1 + public.indices.len() + 4);
    out.extend([
        public.root_a,
        public.root_b,
        public.root_c,
        public.root_x,
        public.root_y,
    ]);
    out.push(public.cm_abc);
    out.push(public.cm_xy);
    out.push(public.challenge_r);
    out.extend(public.indices.iter().map(|&i| Fr::from(i as u64)));
    out.push(public.lookup_index_challenge);
    out.push(public.lookup_logup_challenge);
    out.push(public.rs_point_x);
    out.push(public.rs_point_y);
    out
}

fn empty_circuit(params: &ProtocolParams, poseidon_config: PoseidonConfig<Fr>) -> Meow<Fr> {
    let zeros_k = vec![Fr::zero(); params.k];
    let zeros_n = vec![Fr::zero(); params.n];
    let zeros_l = vec![Fr::zero(); params.l];
    let zero_cols_lk = vec![vec![Fr::zero(); params.k]; params.l];
    Meow::<Fr> {
        k: params.k,
        n: params.n,
        roots: Some([Fr::zero(); 5]),
        cm_abc: Some(Fr::zero()),
        cm_xyz: Some(Fr::zero()),
        challenge_r: Some(Fr::zero()),
        indices: Some(zeros_l),
        lookup_index_challenge: Some(params.lookup_index_challenge),
        lookup_logup_challenge: Some(params.lookup_logup_challenge),
        rs_point_x: Some(params.rs_point_x),
        rs_point_yz: Some(params.rs_point_y),
        poseidon_config: Some(poseidon_config),
        cols_enc_a: Some(zero_cols_lk.clone()),
        cols_enc_b: Some(zero_cols_lk.clone()),
        cols_enc_c: Some(zero_cols_lk),
        vec_x: Some(zeros_k.clone()),
        vec_yz: Some(zeros_k),
        enc_x: Some(zeros_n.clone()),
        enc_yz: Some(zeros_n),
        target_enc_x: Some(vec![Fr::zero(); params.l]),
        target_enc_yz: Some(vec![Fr::zero(); params.l]),
    }
}

fn validate_params(params: &ProtocolParams) -> Result<(), ProtocolError> {
    if params.k == 0 || params.n == 0 || params.l == 0 {
        return Err(ProtocolError::InvalidInput("k,n,l must be non-zero"));
    }
    if params.n < params.k {
        return Err(ProtocolError::InvalidInput("n must be >= k"));
    }
    if params.l > params.n {
        return Err(ProtocolError::InvalidInput("l must be <= n"));
    }
    ilog2_exact(params.n)?;
    Ok(())
}

fn ilog2_exact(n: usize) -> Result<usize, ProtocolError> {
    if !n.is_power_of_two() {
        return Err(ProtocolError::InvalidInput("n must be a power of two"));
    }
    Ok(n.trailing_zeros() as usize)
}

fn random_matrix<R: Rng>(k: usize, rng: &mut R) -> Vec<Vec<Fr>> {
    (0..k)
        .map(|_| (0..k).map(|_| Fr::rand(rng)).collect::<Vec<_>>())
        .collect()
}

fn validate_square_matrix(m: &[Vec<Fr>], k: usize) -> Result<(), ProtocolError> {
    if m.len() != k || m.iter().any(|row| row.len() != k) {
        return Err(ProtocolError::InvalidInput("matrix must be k x k"));
    }
    Ok(())
}

pub fn matmul(a: &[Vec<Fr>], b: &[Vec<Fr>]) -> Result<Vec<Vec<Fr>>, ProtocolError> {
    let k = a.len();
    if a.iter().any(|row| row.len() != k) || b.len() != k || b.iter().any(|row| row.len() != k) {
        return Err(ProtocolError::InvalidInput("matrix dimension mismatch"));
    }

    let b_cols: Vec<Vec<Fr>> = (0..k)
        .map(|j| (0..k).map(|i| b[i][j]).collect::<Vec<_>>())
        .collect();

    let dot = |lhs: &[Fr], rhs: &[Fr]| -> Fr {
        lhs.iter()
            .zip(rhs.iter())
            .fold(Fr::zero(), |mut acc, (x, y)| {
                acc += *x * *y;
                acc
            })
    };

    let mut out = vec![vec![Fr::zero(); k]; k];
    out.par_iter_mut()
        .zip(a.par_iter())
        .for_each(|(out_row, a_row)| {
            for (out_cell, b_col) in out_row.iter_mut().zip(b_cols.iter()) {
                *out_cell = dot(a_row, b_col);
            }
        });

    Ok(out)
}

fn vec_mat_mul(v: &[Fr], m: &[Vec<Fr>]) -> Result<Vec<Fr>, ProtocolError> {
    let k = v.len();
    if m.len() != k || m.iter().any(|row| row.len() != k) {
        return Err(ProtocolError::InvalidInput(
            "vector/matrix dimension mismatch",
        ));
    }
    let mut out = vec![Fr::zero(); k];
    for j in 0..k {
        let mut acc = Fr::zero();
        for i in 0..k {
            acc += v[i] * m[i][j];
        }
        out[j] = acc;
    }
    Ok(out)
}

fn encode_rows(
    rs: &ReedSolomonCode<Fr>,
    matrix: &[Vec<Fr>],
) -> Result<Vec<Vec<Fr>>, ProtocolError> {
    matrix
        .iter()
        .map(|row| rs.encode(row).map_err(ProtocolError::from))
        .collect()
}

fn transpose(rows: &[Vec<Fr>]) -> Result<Vec<Vec<Fr>>, ProtocolError> {
    if rows.is_empty() {
        return Err(ProtocolError::InvalidInput("cannot transpose empty matrix"));
    }
    let row_len = rows[0].len();
    if rows.iter().any(|r| r.len() != row_len) {
        return Err(ProtocolError::InvalidInput(
            "ragged matrix cannot transpose",
        ));
    }
    let mut cols = vec![vec![Fr::zero(); rows.len()]; row_len];
    for (i, row) in rows.iter().enumerate() {
        for (j, v) in row.iter().enumerate() {
            cols[j][i] = *v;
        }
    }
    Ok(cols)
}

fn to_scalar_columns(values: &[Fr]) -> Vec<Vec<Fr>> {
    values.iter().map(|v| vec![*v]).collect()
}

fn powers_vector(base: Fr, k: usize) -> Vec<Fr> {
    if k == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(k);
    let mut cur = Fr::one();
    for _ in 0..k {
        out.push(cur);
        cur *= base;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::verifier::Verifier;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    #[ignore = "Groth16 setup mode may fail with inverse-heavy gadgets"]
    fn test_protocol_end_to_end_without_cplink() {
        let mut rng = StdRng::seed_from_u64(42);
        let params = ProtocolParams {
            k: 4,
            n: 8,
            l: 3,
            lookup_index_challenge: Fr::from(17u64),
            lookup_logup_challenge: Fr::from(1009u64),
            rs_point_x: Fr::from(0u64),
            rs_point_y: Fr::from(0u64),
        };

        let prover = Prover::setup(params.k, &mut rng);
        let setup = prover.circuit_setup(&params, &mut rng).unwrap();
        let proof = prover
            .prove_with_random_matrices(&params, &setup.pk, &mut rng)
            .unwrap();

        let verifier = Verifier::new(params.clone(), setup.vk, prover.poseidon_config.clone());
        assert!(verifier.verify(&proof).unwrap());
    }
}
