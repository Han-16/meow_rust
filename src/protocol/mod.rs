pub mod prover;
pub mod verifier;

use ark_bn254::{Bn254, Fr, G1Affine};
use ark_groth16::Proof;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_relations::r1cs::SynthesisError;

use crate::crypto::CryptoError;

#[derive(Debug, Clone)]
pub struct ProtocolParams {
    pub k: usize,
    pub n: usize,
    pub l: usize,
    pub lookup_index_challenge: Fr,
    pub lookup_logup_challenge: Fr,
    pub rs_point_x: Fr,
    pub rs_point_y: Fr,
}

#[derive(Debug, Clone)]
pub struct MerkleOpening {
    pub commitment: G1Affine,
    pub siblings: Vec<Fr>,
}

#[derive(Debug, Clone)]
pub struct QueryOpeningSet {
    pub index: usize,
    pub a: MerkleOpening,
    pub b: MerkleOpening,
    pub c: MerkleOpening,
    pub x: MerkleOpening,
    pub y: MerkleOpening,
    pub z: MerkleOpening,
}

#[derive(Debug, Clone)]
pub struct PublicTranscript {
    pub root_a: Fr,
    pub root_b: Fr,
    pub root_c: Fr,
    pub root_x: Fr,
    pub root_y: Fr,
    pub root_z: Fr,
    pub cm_abc: Fr,
    pub cm_xy: Fr,
    pub challenge_r: Fr,
    pub indices: Vec<usize>,
    pub lookup_index_challenge: Fr,
    pub lookup_logup_challenge: Fr,
    pub rs_point_x: Fr,
    pub rs_point_y: Fr,
}

#[derive(Debug, Clone)]
pub struct ProtocolProof {
    pub groth16_proof: Proof<Bn254>,
    pub public_inputs: Vec<Fr>,
    pub public: PublicTranscript,
    pub query_openings: Vec<QueryOpeningSet>,
}

#[derive(Debug)]
pub struct SetupArtifacts {
    pub pk: ProvingKey<Bn254>,
    pub vk: VerifyingKey<Bn254>,
}

#[derive(Debug)]
pub enum ProtocolError {
    Crypto(CryptoError),
    Synthesis(SynthesisError),
    LinearCode(crate::circuits::gadgets::linear_code::Error),
    InvalidInput(&'static str),
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Synthesis(e) => write!(f, "{e}"),
            Self::LinearCode(e) => write!(f, "{e}"),
            Self::InvalidInput(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<CryptoError> for ProtocolError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<SynthesisError> for ProtocolError {
    fn from(value: SynthesisError) -> Self {
        Self::Synthesis(value)
    }
}

impl From<crate::circuits::gadgets::linear_code::Error> for ProtocolError {
    fn from(value: crate::circuits::gadgets::linear_code::Error) -> Self {
        Self::LinearCode(value)
    }
}
