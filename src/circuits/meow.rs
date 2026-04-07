use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, Result as R1CSResult, SynthesisError,
};
use ark_std::{
    fmt::Debug,
    rand::{CryptoRng, RngCore},
};

use ndarray::Array2;

use crate::circuits::gadgets::{
    linear_code::constraints::ProbabilisticEncodingTestGadget,
    linear_code::reed_solomon::constraints::ReedSolomonGadget,
    linear_code::reed_solomon::ReedSolomonCode, linear_code::LinearCode,
    lookup::logup::constraints::enforce_lookup_vector_indexing,
};

#[derive(Debug, Clone)]
pub struct Meow<F: PrimeField> {
    // Public challenge used in lookup row packing.
    pub r: Option<F>,

    // Base matrices (flattened row-major, size k*k).
    pub a: Option<Vec<F>>,
    pub b: Option<Vec<F>>,
    pub c: Option<Vec<F>>,

    // Reed-Solomon encodings of A/B/C rows (flattened, size k*n each).
    pub encoded_a: Option<Vec<F>>,
    pub encoded_b: Option<Vec<F>>,
    pub encoded_c: Option<Vec<F>>,

    // Folded vectors for Freivalds-style checks.
    pub r_a: Option<Vec<F>>,  // r_a= a * r (folded by inner product with r).
    pub r_ab: Option<Vec<F>>, // r_ab = (r_a) * b (folded product of r_a and b).
    pub r_c: Option<Vec<F>>,  // r_c = (r_a) * c (folded product of r_a and c).

    // Public evaluation point for RS probabilistic encoding tests and LogUp.
    pub evaluation_point: Option<F>,

    // Encoded folded vectors (lookup tables, size n).
    pub encoded_r_a: Option<Vec<F>>,
    pub encoded_r_ab: Option<Vec<F>>,
    pub encoded_r_c: Option<Vec<F>>,

    // Queried values opened from encoded_r_* at `queries`.
    pub target_encoded_r_a: Option<Vec<F>>,
    pub target_encoded_r_ab: Option<Vec<F>>,
    pub target_encoded_r_c: Option<Vec<F>>,

    num_queries: usize,
    pub queries: Option<Vec<usize>>,

    rs_code: ReedSolomonCode<F>,
}

impl<F: PrimeField> Meow<F> {
    pub fn rand<R: RngCore + CryptoRng>(n: usize, k: usize, l: usize, rng: &mut R) -> Self {
        let r = F::rand(rng);

        let raw_a = (0..k * k).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let raw_b = (0..k * k).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let a = Array2::from_shape_vec((k, k), raw_a.clone()).unwrap();
        let b = Array2::from_shape_vec((k, k), raw_b.clone()).unwrap();
        let c = a * b;
        let (raw_c, offset) = c.into_raw_vec_and_offset();
        debug_assert_eq!(offset, Some(0));
        let rs_code = ReedSolomonCode::<F>::new(k, n);
        Self {
            r: Some(r),
            a: Some(raw_a),
            b: Some(raw_b),
            c: Some(raw_c),
            encoded_a: None,
            encoded_b: None,
            encoded_c: None,
            r_a: None,
            r_ab: None,
            r_c: None,
            evaluation_point: None,
            encoded_r_a: None,
            encoded_r_ab: None,
            encoded_r_c: None,
            target_encoded_r_a: None,
            target_encoded_r_ab: None,
            target_encoded_r_c: None,
            num_queries: l,
            queries: None,
            rs_code,
        }
    }

    pub fn default(n: usize, k: usize, l: usize) -> Self {
        let rs_code = ReedSolomonCode::new(k, n);
        Self {
            r: Some(F::zero()),
            a: Some(vec![F::zero(); k * k]),
            b: Some(vec![F::zero(); k * k]),
            c: Some(vec![F::zero(); k * k]),
            encoded_a: Some(vec![F::zero(); k * n]),
            encoded_b: Some(vec![F::zero(); k * n]),
            encoded_c: Some(vec![F::zero(); k * n]),
            r_a: Some(vec![F::zero(); k]),
            r_ab: Some(vec![F::zero(); k]),
            r_c: Some(vec![F::zero(); k]),
            evaluation_point: Some(F::zero()),
            encoded_r_a: Some(vec![F::zero(); n]),
            encoded_r_ab: Some(vec![F::zero(); n]),
            encoded_r_c: Some(vec![F::zero(); n]),
            target_encoded_r_a: Some(vec![F::zero(); l]),
            target_encoded_r_ab: Some(vec![F::zero(); l]),
            target_encoded_r_c: Some(vec![F::zero(); l]),
            num_queries: l,
            queries: Some(vec![0; l]),
            rs_code,
        }
    }

    fn derive_targets(values: &[F], queries: &[usize]) -> Result<Vec<F>, SynthesisError> {
        // Convenience witness builder: derive opened values from (table, indices).
        let mut out = Vec::with_capacity(queries.len());
        for &q in queries {
            let v = values.get(q).ok_or(SynthesisError::AssignmentMissing)?;
            out.push(*v);
        }
        Ok(out)
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Meow<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> R1CSResult<()> {
        let Meow {
            r,
            a,
            b,
            c,
            encoded_a,
            encoded_b,
            encoded_c,
            r_a: _,
            r_ab: _,
            r_c: _,
            evaluation_point,
            encoded_r_a,
            encoded_r_ab,
            encoded_r_c,
            target_encoded_r_a,
            target_encoded_r_ab,
            target_encoded_r_c,
            num_queries,
            queries,
            rs_code,
        } = self;

        // Keep copies for target-derivation closures without re-borrow issues.
        let encoded_r_a_for_target = encoded_r_a.clone();
        let encoded_r_ab_for_target = encoded_r_ab.clone();
        let encoded_r_c_for_target = encoded_r_c.clone();
        let queries_for_target = queries.clone();

        // Public inputs.
        let r = FpVar::new_input(cs.clone(), || r.ok_or(SynthesisError::AssignmentMissing))?;

        let beta = FpVar::new_input(cs.clone(), || {
            evaluation_point.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Witness vectors and tables.
        let a = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            a.clone().ok_or(SynthesisError::AssignmentMissing)
        })?;
        let b = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            b.clone().ok_or(SynthesisError::AssignmentMissing)
        })?;
        let c = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            c.clone().ok_or(SynthesisError::AssignmentMissing)
        })?;
        let encoded_a = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            encoded_a.clone().ok_or(SynthesisError::AssignmentMissing)
        })?;
        let encoded_b = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            encoded_b.clone().ok_or(SynthesisError::AssignmentMissing)
        })?;
        let encoded_c = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            encoded_c.clone().ok_or(SynthesisError::AssignmentMissing)
        })?;

        let encoded_r_a = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            encoded_r_a.clone().ok_or(SynthesisError::AssignmentMissing)
        })?;
        let encoded_r_ab = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            encoded_r_ab
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let encoded_r_c = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            encoded_r_c.clone().ok_or(SynthesisError::AssignmentMissing)
        })?;

        let query_indices = Vec::<FpVar<F>>::new_input(cs.clone(), || {
            let qs = queries.clone().ok_or(SynthesisError::AssignmentMissing)?;
            if qs.len() != num_queries {
                return Err(SynthesisError::AssignmentMissing);
            }
            Ok(qs
                .into_iter()
                .map(|q| F::from(q as u64))
                .collect::<Vec<_>>())
        })?;

        let target_encoded_r_a = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            // Allow explicit target witness, or derive from table+queries.
            if let Some(v) = target_encoded_r_a.clone() {
                return Ok(v);
            }
            let table = encoded_r_a_for_target
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)?;
            let qs = queries_for_target
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)?;
            Self::derive_targets(&table, &qs)
        })?;
        let target_encoded_r_ab = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            if let Some(v) = target_encoded_r_ab.clone() {
                return Ok(v);
            }
            let table = encoded_r_ab_for_target
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)?;
            let qs = queries_for_target
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)?;
            Self::derive_targets(&table, &qs)
        })?;
        let target_encoded_r_c = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            if let Some(v) = target_encoded_r_c.clone() {
                return Ok(v);
            }
            let table = encoded_r_c_for_target
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)?;
            let qs = queries_for_target
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)?;
            Self::derive_targets(&table, &qs)
        })?;

        let k = rs_code.message_length();
        let n = rs_code.codeword_length();

        // Enforce each row of encoded_{a,b,c} is a valid RS encoding of {a,b,c}.
        let rs_gadget = ReedSolomonGadget::<F, FpVar<F>>::new_witness(cs.clone(), || Ok(rs_code))?;
        for i in 0..k {
            let msg_a = &a[i * k..(i + 1) * k];
            let msg_b = &b[i * k..(i + 1) * k];
            let msg_c = &c[i * k..(i + 1) * k];
            let enc_a_row = &encoded_a[i * n..(i + 1) * n];
            let enc_b_row = &encoded_b[i * n..(i + 1) * n];
            let enc_c_row = &encoded_c[i * n..(i + 1) * n];

            rs_gadget.is_valid(msg_a, enc_a_row, &beta)?;
            rs_gadget.is_valid(msg_b, enc_b_row, &beta)?;
            rs_gadget.is_valid(msg_c, enc_c_row, &beta)?;
        }

        // LogUp-based vector indexing checks:
        // target_encoded_r_* must be openings of encoded_r_* at query_indices.
        enforce_lookup_vector_indexing(
            cs.clone(),
            &encoded_r_a,
            &query_indices,
            &target_encoded_r_a,
            &r,
            &beta,
        )?;
        enforce_lookup_vector_indexing(
            cs.clone(),
            &encoded_r_ab,
            &query_indices,
            &target_encoded_r_ab,
            &r,
            &beta,
        )?;

        enforce_lookup_vector_indexing(
            cs,
            &encoded_r_c,
            &query_indices,
            &target_encoded_r_c,
            &r,
            &beta,
        )?;
        for (ab_i, c_i) in target_encoded_r_ab.iter().zip(target_encoded_r_c.iter()) {
            // In meow relation, rAB and rC openings must match per queried index.
            ab_i.enforce_equal(c_i)?;
        }

        Ok(())
    }
}
