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
pub struct Meow<F: PrimeField> {
    // Dimensions.
    pub k: usize,
    pub n: usize,

    // Public inputs.
    pub roots: Option<[F; 5]>, // [A, B, C, X, YZ] merkle roots
    pub cm_abc: Option<F>,
    pub cm_xyz: Option<F>,
    pub challenge_r: Option<Vec<F>>, // len = K
    pub indices: Option<Vec<F>>,     // len = L
    pub lookup_index_challenge: Option<F>,
    pub lookup_logup_challenge: Option<F>,
    pub rs_point_x: Option<F>,
    pub rs_point_yz: Option<F>,
    pub poseidon_config: Option<PoseidonConfig<F>>,

    // Witnesses.
    pub cols_enc_a: Option<Vec<Vec<F>>>, // [L][K]
    pub cols_enc_b: Option<Vec<Vec<F>>>, // [L][K]
    pub cols_enc_c: Option<Vec<Vec<F>>>, // [L][K]
    pub vec_x: Option<Vec<F>>,           // [K]
    pub vec_yz: Option<Vec<F>>,          // [K]
    pub enc_x: Option<Vec<F>>,           // [N]
    pub enc_yz: Option<Vec<F>>,          // [N]
    pub target_enc_x: Option<Vec<F>>,    // [L]
    pub target_enc_yz: Option<Vec<F>>,   // [L]
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
        let Self {
            k,
            n,
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
            cols_enc_a,
            cols_enc_b,
            cols_enc_c,
            vec_x,
            vec_yz,
            enc_x,
            enc_yz,
            target_enc_x,
            target_enc_yz,
        } = self;

        // Public inputs.
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
        let challenge_r = Vec::<FpVar<F>>::new_input(cs.clone(), || {
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

        // Witnesses.
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

        // 1) Lookup constraints (t.Lookup(indices[i]) == target[i]) for X and YZ.
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

        // 1-b) Fold checks.
        for i in 0..l {
            let fold_a = fold(&challenge_r, &cols_enc_a[i])?;
            let fold_b = fold(&vec_x, &cols_enc_b[i])?;
            let fold_c = fold(&challenge_r, &cols_enc_c[i])?;

            fold_a.enforce_equal(&target_enc_x[i])?;
            fold_b.enforce_equal(&target_enc_yz[i])?;
            fold_c.enforce_equal(&target_enc_yz[i])?;
        }

        // 2) Poseidon checks: CmABC = H(RootA,RootB,RootC), CmXYZ = H(RootX,RootYZ)
        let poseidon_cfg = poseidon_config.ok_or(SynthesisError::AssignmentMissing)?;
        let calc_cm_abc = poseidon_hash(cs.clone(), &poseidon_cfg, &roots[0..3])?;
        calc_cm_abc.enforce_equal(&cm_abc)?;
        let calc_cm_xyz = poseidon_hash(cs.clone(), &poseidon_cfg, &roots[3..5])?;
        calc_cm_xyz.enforce_equal(&cm_xyz)?;

        // 3) Reed-Solomon encoding checks (same as VerifyRSEncoding probabilistic test).
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
    use ark_crypto_primitives::sponge::{
        poseidon::{traits::find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge},
        CryptographicSponge,
    };
    use ark_ff::PrimeField;
    use ark_relations::r1cs::{ConstraintSystem, SynthesisError};

    use crate::circuits::gadgets::linear_code::{reed_solomon::ReedSolomonCode, LinearCode};
    use std::{collections::HashMap, fs};

    fn parse_env_file(path: &str) -> Result<HashMap<String, String>, SynthesisError> {
        let text = fs::read_to_string(path).map_err(|_| SynthesisError::AssignmentMissing)?;
        let mut out = HashMap::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let (k, v) = trimmed
                .split_once('=')
                .ok_or(SynthesisError::AssignmentMissing)?;
            out.insert(k.trim().to_string(), v.trim().to_string());
        }
        Ok(out)
    }

    fn parse_circuit_sizes_from_env() -> Result<(usize, usize, usize), SynthesisError> {
        let env = parse_env_file(".env")?;
        let log_k: usize = env
            .get("LOG_K")
            .ok_or(SynthesisError::AssignmentMissing)?
            .parse()
            .map_err(|_| SynthesisError::AssignmentMissing)?;
        let l: usize = env
            .get("L")
            .ok_or(SynthesisError::AssignmentMissing)?
            .parse()
            .map_err(|_| SynthesisError::AssignmentMissing)?;
        let rho: f64 = env
            .get("RHO")
            .ok_or(SynthesisError::AssignmentMissing)?
            .parse()
            .map_err(|_| SynthesisError::AssignmentMissing)?;
        if !(rho > 0.0) {
            return Err(SynthesisError::AssignmentMissing);
        }

        let k = 1usize << log_k;
        let n_float = (k as f64) / rho;
        let n = n_float.round() as usize;
        if n == 0 || l > n {
            return Err(SynthesisError::AssignmentMissing);
        }
        Ok((k, n, l))
    }

    fn parse_circuit_range_from_env() -> Result<(usize, usize, usize, f64), SynthesisError> {
        let env = parse_env_file(".env")?;
        let log_k_min: usize = env
            .get("LOG_K_MIN")
            .ok_or(SynthesisError::AssignmentMissing)?
            .parse()
            .map_err(|_| SynthesisError::AssignmentMissing)?;
        let log_k_max: usize = env
            .get("LOG_K_MAX")
            .ok_or(SynthesisError::AssignmentMissing)?
            .parse()
            .map_err(|_| SynthesisError::AssignmentMissing)?;
        let l: usize = env
            .get("L")
            .ok_or(SynthesisError::AssignmentMissing)?
            .parse()
            .map_err(|_| SynthesisError::AssignmentMissing)?;
        let rho: f64 = env
            .get("RHO")
            .ok_or(SynthesisError::AssignmentMissing)?
            .parse()
            .map_err(|_| SynthesisError::AssignmentMissing)?;
        if !(rho > 0.0) || log_k_min > log_k_max {
            return Err(SynthesisError::AssignmentMissing);
        }
        Ok((log_k_min, log_k_max, l, rho))
    }

    fn poseidon_bn254_cfg() -> PoseidonConfig<Fr> {
        let rate = 2usize;
        let full_rounds = 8usize;
        let partial_rounds = 56usize;
        let alpha = 5u64;
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            Fr::MODULUS_BIT_SIZE as u64,
            rate,
            full_rounds as u64,
            partial_rounds as u64,
            0,
        );
        PoseidonConfig {
            full_rounds,
            partial_rounds,
            alpha,
            ark,
            mds,
            rate,
            capacity: 1,
        }
    }

    fn poseidon_hash_native(cfg: &PoseidonConfig<Fr>, inputs: &[Fr]) -> Result<Fr, SynthesisError> {
        let mut sponge = PoseidonSponge::<Fr>::new(cfg);
        sponge.absorb(&inputs.to_vec());
        Ok(sponge.squeeze_field_elements::<Fr>(1)[0])
    }

    fn build_satisfiable_meow_circuit(
        k: usize,
        n: usize,
        l: usize,
        poseidon_cfg: PoseidonConfig<Fr>,
    ) -> Result<Meow<Fr>, SynthesisError> {
        let roots = [
            Fr::from(11u64),
            Fr::from(22u64),
            Fr::from(33u64),
            Fr::from(44u64),
            Fr::from(55u64),
        ];
        let cm_abc = poseidon_hash_native(&poseidon_cfg, &roots[0..3])?;
        let cm_xyz = poseidon_hash_native(&poseidon_cfg, &roots[3..5])?;

        let lookup_alpha = Fr::from(1u64);
        let lookup_beta = Fr::from((n as u64) + 1000);

        let mut challenge_r = vec![Fr::from(0u64); k];
        challenge_r[0] = Fr::from(1u64);

        let rs = ReedSolomonCode::<Fr>::new(k, n);
        let mut vec_x = vec![Fr::from(0u64); k];
        vec_x[0] = Fr::from(1u64);
        let mut vec_yz = vec![Fr::from(0u64); k];
        vec_yz[0] = Fr::from(7u64);
        let enc_x = rs
            .encode(&vec_x)
            .map_err(|_| SynthesisError::AssignmentMissing)?;
        let enc_yz = rs
            .encode(&vec_yz)
            .map_err(|_| SynthesisError::AssignmentMissing)?;

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

        Ok(Meow::<Fr> {
            k,
            n,
            roots: Some(roots),
            cm_abc: Some(cm_abc),
            cm_xyz: Some(cm_xyz),
            challenge_r: Some(challenge_r),
            indices: Some(indices),
            lookup_index_challenge: Some(lookup_alpha),
            lookup_logup_challenge: Some(lookup_beta),
            rs_point_x: Some(Fr::from((n as u64) + 2001)),
            rs_point_yz: Some(Fr::from((n as u64) + 3001)),
            poseidon_config: Some(poseidon_cfg),
            cols_enc_a: Some(cols_enc_a),
            cols_enc_b: Some(cols_enc_b),
            cols_enc_c: Some(cols_enc_c),
            vec_x: Some(vec_x),
            vec_yz: Some(vec_yz),
            enc_x: Some(enc_x),
            enc_yz: Some(enc_yz),
            target_enc_x: Some(target_enc_x),
            target_enc_yz: Some(target_enc_yz),
        })
    }

    #[test]
    fn test_meow_constraint_count_from_env() -> Result<(), SynthesisError> {
        let (k, n, l) = parse_circuit_sizes_from_env()?;
        let circuit = build_satisfiable_meow_circuit(k, n, l, poseidon_bn254_cfg())?;

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone())?;
        let is_sat = cs.is_satisfied()?;
        if !is_sat {
            eprintln!("unsatisfied: {:?}", cs.which_is_unsatisfied()?);
        }
        assert!(is_sat);
        let num_constraints = cs.num_constraints();
        assert!(num_constraints > 0);
        eprintln!(
            "meow constraints (from .env): K={}, N={}, L={} => {}",
            k, n, l, num_constraints
        );
        Ok(())
    }

    #[test]
    fn test_meow_constraint_count_range_from_env() -> Result<(), SynthesisError> {
        let (log_k_min, log_k_max, l, rho) = parse_circuit_range_from_env()?;
        for log_k in log_k_min..=log_k_max {
            let k = 1usize << log_k;
            let n = ((k as f64) / rho).round() as usize;
            if n == 0 || l > n {
                return Err(SynthesisError::AssignmentMissing);
            }

            let circuit = build_satisfiable_meow_circuit(k, n, l, poseidon_bn254_cfg())?;
            let cs = ConstraintSystem::<Fr>::new_ref();
            circuit.generate_constraints(cs.clone())?;
            assert!(cs.is_satisfied()?);
            eprintln!(
                "meow constraints (range/.env): LOG_K={}, K={}, N={}, L={} => {}",
                log_k,
                k,
                n,
                l,
                cs.num_constraints()
            );
        }
        Ok(())
    }
}
