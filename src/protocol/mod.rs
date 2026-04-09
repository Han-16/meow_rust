pub mod prover;
pub mod verifier;

use ark_bn254::{Bn254, Fr, G1Affine};
use ark_groth16::Proof;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_relations::r1cs::SynthesisError;

use crate::circuits::gadgets::linear_code::reed_solomon::ReedSolomonCode;
use crate::crypto::CryptoError;
use crate::crypto::hash::hash_elements;

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

const FS_TAG_CHALLENGE_R: u64 = 1;
const FS_TAG_QUERY_INDICES: u64 = 2;
const FS_TAG_LOOKUP_INDEX: u64 = 3;
const FS_TAG_LOOKUP_LOGUP: u64 = 4;
const FS_TAG_RS_POINT_X: u64 = 5;
const FS_TAG_RS_POINT_Y: u64 = 6;

fn fs_hash(tag: u64, elements: &[Fr]) -> Fr {
    let mut inputs = Vec::with_capacity(elements.len() + 1);
    inputs.push(Fr::from(tag));
    inputs.extend_from_slice(elements);
    hash_elements(&inputs)
}

pub(crate) fn derive_challenge_r(root_a: Fr, root_b: Fr, root_c: Fr) -> Fr {
    fs_hash(FS_TAG_CHALLENGE_R, &[root_a, root_b, root_c])
}

pub(crate) fn derive_query_index_seed(root_x: Fr, root_y: Fr, root_z: Fr) -> Fr {
    fs_hash(FS_TAG_QUERY_INDICES, &[root_x, root_y, root_z])
}

fn fs_base_transcript(public: &PublicTranscript) -> [Fr; 9] {
    [
        public.root_a,
        public.root_b,
        public.root_c,
        public.root_x,
        public.root_y,
        public.root_z,
        public.cm_abc,
        public.cm_xy,
        public.challenge_r,
    ]
}

fn fs_lookup_transcript(public: &PublicTranscript) -> Vec<Fr> {
    let mut transcript = fs_base_transcript(public).to_vec();
    transcript.extend(public.indices.iter().map(|&idx| Fr::from(idx as u64)));
    transcript
}

fn derive_out_of_domain_point(tag: u64, public: &PublicTranscript, n: usize) -> Fr {
    let rs = ReedSolomonCode::<Fr>::new(1, n);
    let omega = rs.omega();
    let mut point = fs_hash(tag, &fs_base_transcript(public));
    loop {
        let mut omega_i = Fr::from(1u64);
        let mut in_domain = false;
        for _ in 0..n {
            if point == omega_i {
                in_domain = true;
                break;
            }
            omega_i *= omega;
        }
        if !in_domain {
            return point;
        }
        point = fs_hash(tag, &[point]);
    }
}

pub(crate) fn derive_fiat_shamir_challenges(
    public: &PublicTranscript,
    n: usize,
) -> (Fr, Fr, Fr, Fr) {
    let lookup_transcript = fs_lookup_transcript(public);
    let lookup_index_challenge = fs_hash(FS_TAG_LOOKUP_INDEX, &lookup_transcript);
    let lookup_logup_challenge =
        fs_hash(
            FS_TAG_LOOKUP_LOGUP,
            &[lookup_transcript.as_slice(), &[lookup_index_challenge]].concat(),
        );
    let rs_point_x = derive_out_of_domain_point(FS_TAG_RS_POINT_X, public, n);
    let rs_point_y = derive_out_of_domain_point(FS_TAG_RS_POINT_Y, public, n);
    (
        lookup_index_challenge,
        lookup_logup_challenge,
        rs_point_x,
        rs_point_y,
    )
}
