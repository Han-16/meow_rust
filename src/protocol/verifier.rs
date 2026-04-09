use ark_bn254::Bn254;
use ark_groth16::{Groth16, VerifyingKey};
use ark_snark::SNARK;
use std::time::{Duration, Instant};

use crate::crypto::hash::{generate_unique_indices, poseidon_hash_elements_bn254};
use crate::crypto::merkle::verify_membership;
use crate::protocol::prover::build_public_inputs;
use crate::protocol::{
    derive_challenge_r, derive_fiat_shamir_challenges, derive_query_index_seed, ProtocolError,
    ProtocolContext, ProtocolParams, ProtocolProof,
};

#[derive(Debug, Clone, Default)]
pub struct VerifyTimeBreakdown {
    pub groth16_verify: Duration,
    pub merkle_membership_verify: Duration,
}

impl VerifyTimeBreakdown {
    pub fn tracked_total(&self) -> Duration {
        self.groth16_verify + self.merkle_membership_verify
    }
}

#[derive(Debug, Clone)]
pub struct Verifier {
    params: ProtocolParams,
    vk: VerifyingKey<Bn254>,
    pub context: ProtocolContext,
}

impl Verifier {
    pub fn new(params: ProtocolParams, vk: VerifyingKey<Bn254>, context: ProtocolContext) -> Self {
        Self {
            params,
            vk,
            context,
        }
    }

    pub fn verify(&self, proof: &ProtocolProof) -> Result<bool, ProtocolError> {
        let (ok, _) = self.verify_with_timing(proof)?;
        Ok(ok)
    }

    pub fn verify_with_timing(
        &self,
        proof: &ProtocolProof,
    ) -> Result<(bool, VerifyTimeBreakdown), ProtocolError> {
        let mut timings = VerifyTimeBreakdown::default();

        if proof.public.indices.len() != self.params.l || proof.query_openings.len() != self.params.l {
            return Err(ProtocolError::InvalidInput(
                "public transcript length mismatch",
            ));
        }

        // 4-5) Recompute random scalar from Merkle roots and check scalar challenge.
        let r_scalar = derive_challenge_r(
            proof.public.root_a,
            proof.public.root_b,
            proof.public.root_c,
        );
        if r_scalar != proof.public.challenge_r {
            return Ok((false, timings));
        }

        // 8) Recompute query set from cm_x, cm_y, cm_z.
        let idx_seed = derive_query_index_seed(
            proof.public.root_x,
            proof.public.root_y,
            proof.public.root_z,
        );
        let expected_indices = generate_unique_indices(idx_seed, self.params.n, self.params.l)?;
        if expected_indices != proof.public.indices {
            return Ok((false, timings));
        }

        let (
            expected_lookup_index_challenge,
            expected_lookup_logup_challenge,
            expected_rs_point_x,
            expected_rs_point_y,
        ) = derive_fiat_shamir_challenges(&proof.public, self.params.n);
        if expected_lookup_index_challenge != proof.public.lookup_index_challenge
            || expected_lookup_logup_challenge != proof.public.lookup_logup_challenge
            || expected_rs_point_x != proof.public.rs_point_x
            || expected_rs_point_y != proof.public.rs_point_y
        {
            return Ok((false, timings));
        }

        // Circuit hash publics are Poseidon in current meow.rs.
        let expected_cm_abc = poseidon_hash_elements_bn254(
            &self.context.poseidon_config,
            &[
                proof.public.root_a,
                proof.public.root_b,
                proof.public.root_c,
            ],
        );
        if expected_cm_abc != proof.public.cm_abc {
            return Ok((false, timings));
        }
        let expected_cm_xy = poseidon_hash_elements_bn254(
            &self.context.poseidon_config,
            &[proof.public.root_x, proof.public.root_y],
        );
        if expected_cm_xy != proof.public.cm_xy {
            return Ok((false, timings));
        }

        // 11-a) Groth16 proof verification.
        let expected_public_inputs = build_public_inputs(&proof.public);
        if expected_public_inputs != proof.public_inputs {
            return Ok((false, timings));
        }
        let groth16_start = Instant::now();
        let groth16_ok =
            Groth16::<Bn254>::verify(&self.vk, &proof.public_inputs, &proof.groth16_proof)?;
        timings.groth16_verify += groth16_start.elapsed();
        if !groth16_ok {
            return Ok((false, timings));
        }

        // 11-b) Merkle membership checks for A,B,C,X,Y,Z.
        let merkle_verify_start = Instant::now();
        for (i, opening_set) in proof.query_openings.iter().enumerate() {
            let idx = opening_set.index;
            if idx != proof.public.indices[i] {
                return Ok((false, timings));
            }
            if !verify_membership(
                proof.public.root_a,
                &opening_set.a.commitment,
                &opening_set.a.siblings,
                idx,
            ) {
                return Ok((false, timings));
            }
            if !verify_membership(
                proof.public.root_b,
                &opening_set.b.commitment,
                &opening_set.b.siblings,
                idx,
            ) {
                return Ok((false, timings));
            }
            if !verify_membership(
                proof.public.root_c,
                &opening_set.c.commitment,
                &opening_set.c.siblings,
                idx,
            ) {
                return Ok((false, timings));
            }
            if !verify_membership(
                proof.public.root_x,
                &opening_set.x.commitment,
                &opening_set.x.siblings,
                idx,
            ) {
                return Ok((false, timings));
            }
            if !verify_membership(
                proof.public.root_y,
                &opening_set.y.commitment,
                &opening_set.y.siblings,
                idx,
            ) {
                return Ok((false, timings));
            }
            if !verify_membership(
                proof.public.root_z,
                &opening_set.z.commitment,
                &opening_set.z.siblings,
                idx,
            ) {
                return Ok((false, timings));
            }
        }
        timings.merkle_membership_verify += merkle_verify_start.elapsed();

        Ok((true, timings))
    }
}
