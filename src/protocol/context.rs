use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::Zero;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use rand::{CryptoRng, Rng};

use crate::circuits::meow::{Meow, MeowPublic, MeowWitness};
use crate::crypto::hash::poseidon_sponge_config_bn254;
use crate::crypto::pedersen::{setup_commit_key, CommitKey};
use crate::protocol::{ProtocolError, ProtocolParams, SetupArtifacts};

#[derive(Debug, Clone)]
pub struct ProtocolContext {
    pub ck1: CommitKey,
    pub ck_scalar: CommitKey,
    pub poseidon_config: PoseidonConfig<Fr>,
}

impl ProtocolContext {
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
}

fn empty_circuit(params: &ProtocolParams, poseidon_config: PoseidonConfig<Fr>) -> Meow<Fr> {
    let zeros_k = vec![Fr::zero(); params.k];
    let zeros_n = vec![Fr::zero(); params.n];
    let zeros_l = vec![Fr::zero(); params.l];
    let zero_cols_lk = vec![vec![Fr::zero(); params.k]; params.l];
    Meow::<Fr> {
        k: params.k,
        n: params.n,
        public: MeowPublic {
            roots: Some([Fr::zero(); 5]),
            cm_abc: Some(Fr::zero()),
            cm_xyz: Some(Fr::zero()),
            challenge_r: Some(Fr::zero()),
            indices: Some(zeros_l),
            lookup_index_challenge: Some(Fr::zero()),
            lookup_logup_challenge: Some(Fr::zero()),
            rs_point_x: Some(Fr::zero()),
            rs_point_yz: Some(Fr::zero()),
            poseidon_config: Some(poseidon_config),
        },
        witness: MeowWitness {
            cols_enc_a: Some(zero_cols_lk.clone()),
            cols_enc_b: Some(zero_cols_lk.clone()),
            cols_enc_c: Some(zero_cols_lk),
            vec_x: Some(zeros_k.clone()),
            vec_yz: Some(zeros_k),
            enc_x: Some(zeros_n.clone()),
            enc_yz: Some(zeros_n),
            target_enc_x: Some(vec![Fr::zero(); params.l]),
            target_enc_yz: Some(vec![Fr::zero(); params.l]),
        },
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
    if !params.n.is_power_of_two() {
        return Err(ProtocolError::InvalidInput("n must be a power of two"));
    }
    Ok(())
}
