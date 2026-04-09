use ark_bn254::Fr;

use crate::circuits::gadgets::linear_code::reed_solomon::ReedSolomonCode;
use crate::crypto::hash::hash_elements;
use crate::protocol::PublicTranscript;

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
    let lookup_logup_challenge = fs_hash(
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
