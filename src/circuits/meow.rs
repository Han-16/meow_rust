use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
    Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, Result as R1CSResult, SynthesisError,
};

use crate::circuits::gadgets::{
    linear_code::constraints::ProbabilisticEncodingTestGadget,
    linear_code::reed_solomon::constraints::ReedSolomonGadget,
    linear_code::reed_solomon::ReedSolomonCode,
    lookup::logup::constraints::enforce_lookup_vector_indexing,
};

#[derive(Debug, Clone)]
pub struct MeowPublic<F: PrimeField> {
    // Public inputs carried by the Groth16 proof.
    // Merkle roots for the committed encodings [A, B, C, X, Y].
    pub roots: Option<[F; 5]>,
    // Poseidon commitment over roots[A, B, C].
    pub cm_abc: Option<F>,
    // Poseidon commitment over roots[X, Y].
    pub cm_xyz: Option<F>,
    // Scalar challenge r from which [1, r, r^2, ...] is rebuilt in-circuit.
    pub challenge_r: Option<F>,
    // Queried RS positions as field elements, length L.
    pub indices: Option<Vec<F>>,
    // Row-compression challenge for lookup rows such as [index, value].
    pub lookup_index_challenge: Option<F>,
    // LogUp challenge used in the rational lookup identity.
    pub lookup_logup_challenge: Option<F>,
    // Out-of-domain evaluation point for the RS check on x.
    pub rs_point_x: Option<F>,
    // Out-of-domain evaluation point for the RS check on yz.
    pub rs_point_yz: Option<F>,
    pub poseidon_config: Option<PoseidonConfig<F>>,
}

#[derive(Debug, Clone)]
pub struct MeowWitness<F: PrimeField> {
    // Witnesses used to satisfy the queried checks.
    // Queried encoded columns from A, B, C at the selected indices, each [L][K].
    pub cols_enc_a: Option<Vec<Vec<F>>>,
    pub cols_enc_b: Option<Vec<Vec<F>>>,
    pub cols_enc_c: Option<Vec<Vec<F>>>,
    // Folded vectors x = rA and yz, each length K.
    pub vec_x: Option<Vec<F>>,
    pub vec_yz: Option<Vec<F>>,
    // Full RS encodings of x and yz, each length N.
    pub enc_x: Option<Vec<F>>,
    pub enc_yz: Option<Vec<F>>,
    // Claimed values of enc_x / enc_yz at the queried indices, each length L.
    pub target_enc_x: Option<Vec<F>>,
    pub target_enc_yz: Option<Vec<F>>,
}

#[derive(Debug, Clone)]
pub struct Meow<F: PrimeField> {
    // Circuit dimensions: original matrix width k and RS codeword length n.
    pub k: usize,
    pub n: usize,
    pub public: MeowPublic<F>,
    pub witness: MeowWitness<F>,
}

fn fold<F: PrimeField>(lhs: &[FpVar<F>], rhs: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
    if lhs.len() != rhs.len() {
        return Err(SynthesisError::AssignmentMissing);
    }
    Ok(lhs
        .iter()
        .zip(rhs.iter())
        .fold(FpVar::<F>::zero(), |acc, (l, r)| acc + (l * r)))
}

fn poseidon_hash<F: PrimeField + Absorb>(
    cs: ConstraintSystemRef<F>,
    params: &PoseidonConfig<F>,
    inputs: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::<F>::new(cs, params);
    sponge.absorb(&inputs.to_vec())?;
    let out = sponge.squeeze_field_elements(1)?;
    out.into_iter()
        .next()
        .ok_or(SynthesisError::AssignmentMissing)
}

impl<F: PrimeField + Absorb> ConstraintSynthesizer<F> for Meow<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> R1CSResult<()> {
        let Meow {
            k,
            n,
            public:
                MeowPublic {
                    roots,
                    cm_abc,
                    cm_xyz,
                    challenge_r,
                    indices,
                    lookup_index_challenge,
                    lookup_logup_challenge,
                    rs_point_x,
                    rs_point_yz,
                    poseidon_config,
                },
            witness:
                MeowWitness {
                    cols_enc_a,
                    cols_enc_b,
                    cols_enc_c,
                    vec_x,
                    vec_yz,
                    enc_x,
                    enc_yz,
                    target_enc_x,
                    target_enc_yz,
                },
        } = self;

        // Public transcript values exposed to the verifier.
        let roots = Vec::<FpVar<F>>::new_input(cs.clone(), || {
            roots
                .map(|arr| arr.to_vec())
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        if roots.len() != 5 {
            return Err(SynthesisError::AssignmentMissing);
        }
        let cm_abc = FpVar::<F>::new_input(cs.clone(), || {
            cm_abc.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let cm_xyz = FpVar::<F>::new_input(cs.clone(), || {
            cm_xyz.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let challenge_r = FpVar::<F>::new_input(cs.clone(), || {
            challenge_r.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let indices = Vec::<FpVar<F>>::new_input(cs.clone(), || {
            indices.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let lookup_index_challenge = FpVar::<F>::new_input(cs.clone(), || {
            lookup_index_challenge.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let lookup_logup_challenge = FpVar::<F>::new_input(cs.clone(), || {
            lookup_logup_challenge.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let rs_point_x = FpVar::<F>::new_input(cs.clone(), || {
            rs_point_x.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let rs_point_yz = FpVar::<F>::new_input(cs.clone(), || {
            rs_point_yz.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Witness values used to open the queried positions and folded checks.
        let cols_enc_a_vals = cols_enc_a.ok_or(SynthesisError::AssignmentMissing)?;
        let cols_enc_b_vals = cols_enc_b.ok_or(SynthesisError::AssignmentMissing)?;
        let cols_enc_c_vals = cols_enc_c.ok_or(SynthesisError::AssignmentMissing)?;
        let cols_enc_a = cols_enc_a_vals
            .iter()
            .map(|row| Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(row.clone())))
            .collect::<Result<Vec<_>, _>>()?;
        let cols_enc_b = cols_enc_b_vals
            .iter()
            .map(|row| Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(row.clone())))
            .collect::<Result<Vec<_>, _>>()?;
        let cols_enc_c = cols_enc_c_vals
            .iter()
            .map(|row| Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(row.clone())))
            .collect::<Result<Vec<_>, _>>()?;
        let vec_x = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            vec_x.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let vec_yz = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            vec_yz.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let enc_x = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            enc_x.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let enc_yz = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            enc_yz.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let target_enc_x = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            target_enc_x.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let target_enc_yz = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            target_enc_yz.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let l = indices.len();

        // Build [1, r, r^2, ...] inside the circuit from scalar r.
        let mut challenge_r_pows = Vec::with_capacity(k);
        let mut cur = FpVar::<F>::one();
        for _ in 0..k {
            challenge_r_pows.push(cur.clone());
            cur *= &challenge_r;
        }

        // 1) Bind queried indices to the claimed encoded values.
        enforce_lookup_vector_indexing(
            cs.clone(),
            &enc_x,
            &indices,
            &target_enc_x,
            &lookup_index_challenge,
            &lookup_logup_challenge,
        )?;
        enforce_lookup_vector_indexing(
            cs.clone(),
            &enc_yz,
            &indices,
            &target_enc_yz,
            &lookup_index_challenge,
            &lookup_logup_challenge,
        )?;

        // 1-b) Check that queried columns fold to the looked-up targets.
        for i in 0..l {
            let fold_a = fold(&challenge_r_pows, &cols_enc_a[i])?;
            let fold_b = fold(&vec_x, &cols_enc_b[i])?;
            let fold_c = fold(&challenge_r_pows, &cols_enc_c[i])?;

            fold_a.enforce_equal(&target_enc_x[i])?;
            fold_b.enforce_equal(&target_enc_yz[i])?;
            fold_c.enforce_equal(&target_enc_yz[i])?;
        }

        // 2) Recompute public hash commitments from the supplied roots.
        let poseidon_cfg = poseidon_config.ok_or(SynthesisError::AssignmentMissing)?;
        let calc_cm_abc = poseidon_hash(cs.clone(), &poseidon_cfg, &roots[0..3])?;
        calc_cm_abc.enforce_equal(&cm_abc)?;
        let calc_cm_xyz = poseidon_hash(cs.clone(), &poseidon_cfg, &roots[3..5])?;
        calc_cm_xyz.enforce_equal(&cm_xyz)?;

        // 3) Probabilistically check that x and yz match their RS encodings.
        let rs_code = ReedSolomonCode::<F>::new(k, n);
        let rs_gadget = ReedSolomonGadget::<F, FpVar<F>>::new_constant(cs, rs_code)?;
        rs_gadget.is_valid(&vec_x, &enc_x, &rs_point_x)?;
        rs_gadget.is_valid(&vec_yz, &enc_yz, &rs_point_yz)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    use crate::circuits::gadgets::linear_code::{reed_solomon::ReedSolomonCode, LinearCode};
    use crate::crypto::hash::{poseidon_hash_elements_bn254, poseidon_sponge_config_bn254};

    #[test]
    fn test_meow_circuit_is_satisfied() {
        let k = 8usize;
        let n = 16usize;
        let l = 8usize;

        let poseidon_cfg = poseidon_sponge_config_bn254();
        let roots = [
            Fr::from(11u64),
            Fr::from(22u64),
            Fr::from(33u64),
            Fr::from(44u64),
            Fr::from(55u64),
        ];
        let cm_abc = poseidon_hash_elements_bn254(&poseidon_cfg, &roots[0..3]);
        let cm_xyz = poseidon_hash_elements_bn254(&poseidon_cfg, &roots[3..5]);

        let challenge_r = Fr::from(0u64);

        let rs = ReedSolomonCode::<Fr>::new(k, n);
        let mut vec_x = vec![Fr::from(0u64); k];
        vec_x[0] = Fr::from(1u64);
        let mut vec_yz = vec![Fr::from(0u64); k];
        vec_yz[0] = Fr::from(7u64);
        let enc_x = rs.encode(&vec_x).expect("rs encode(x) should succeed");
        let enc_yz = rs.encode(&vec_yz).expect("rs encode(yz) should succeed");

        let indices_usize = (0..l).collect::<Vec<_>>();
        let indices = indices_usize
            .iter()
            .map(|&i| Fr::from(i as u64))
            .collect::<Vec<_>>();
        let target_enc_x = indices_usize.iter().map(|&i| enc_x[i]).collect::<Vec<_>>();
        let target_enc_yz = indices_usize.iter().map(|&i| enc_yz[i]).collect::<Vec<_>>();

        let mut cols_enc_a = vec![vec![Fr::from(0u64); k]; l];
        let mut cols_enc_b = vec![vec![Fr::from(0u64); k]; l];
        let mut cols_enc_c = vec![vec![Fr::from(0u64); k]; l];
        for i in 0..l {
            cols_enc_a[i][0] = target_enc_x[i];
            cols_enc_b[i][0] = target_enc_yz[i];
            cols_enc_c[i][0] = target_enc_yz[i];
        }

        let circuit = Meow::<Fr> {
            k,
            n,
            public: MeowPublic {
                roots: Some(roots),
                cm_abc: Some(cm_abc),
                cm_xyz: Some(cm_xyz),
                challenge_r: Some(challenge_r),
                indices: Some(indices),
                lookup_index_challenge: Some(Fr::from(1u64)),
                lookup_logup_challenge: Some(Fr::from((n as u64) + 1000)),
                rs_point_x: Some(Fr::from((n as u64) + 2001)),
                rs_point_yz: Some(Fr::from((n as u64) + 3001)),
                poseidon_config: Some(poseidon_cfg),
            },
            witness: MeowWitness {
                cols_enc_a: Some(cols_enc_a),
                cols_enc_b: Some(cols_enc_b),
                cols_enc_c: Some(cols_enc_c),
                vec_x: Some(vec_x),
                vec_yz: Some(vec_yz),
                enc_x: Some(enc_x),
                enc_yz: Some(enc_yz),
                target_enc_x: Some(target_enc_x),
                target_enc_yz: Some(target_enc_yz),
            },
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation should succeed");
        assert!(
            cs.is_satisfied().expect("satisfiability check should run"),
            "meow circuit must be satisfied with valid witness"
        );
    }
}
