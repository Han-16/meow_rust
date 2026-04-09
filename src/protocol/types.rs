use ark_bn254::{Bn254, Fr, G1Affine};
use ark_groth16::Proof;
use ark_groth16::{ProvingKey, VerifyingKey};

#[derive(Debug, Clone)]
pub struct ProtocolParams {
    pub k: usize,
    pub n: usize,
    pub l: usize,
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
