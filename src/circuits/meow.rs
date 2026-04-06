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
    linear_code::reed_solomon::ReedSolomonCode,
    lookup::logup::constraints::enforce_lookup_vector_indexing,
};

#[derive(Debug, Clone)]
pub struct Meow<F: PrimeField> {
    // Public Input
    pub r: Option<F>,

    // Committed Witness
    pub a: Option<Vec<F>>,
    pub b: Option<Vec<F>>,
    pub c: Option<Vec<F>>,

    pub encoded_a: Option<Vec<F>>,
    pub encoded_b: Option<Vec<F>>,
    pub encoded_c: Option<Vec<F>>,

    pub r_a: Option<Vec<F>>,
    pub r_ab: Option<Vec<F>>,
    pub r_c: Option<Vec<F>>,

    pub evaluation_point: Option<F>,
    pub encoded_r_a: Option<Vec<F>>,
    pub encoded_r_ab: Option<Vec<F>>,
    pub encoded_r_c: Option<Vec<F>>,

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
        let raw_c = c.into_raw_vec();
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
        let r_val = self.r;
        let evaluation_point_val = self.evaluation_point;
        let encoded_r_a_val = self.encoded_r_a;
        let encoded_r_ab_val = self.encoded_r_ab;
        let encoded_r_c_val = self.encoded_r_c;
        let target_encoded_r_a_val = self.target_encoded_r_a;
        let target_encoded_r_ab_val = self.target_encoded_r_ab;
        let target_encoded_r_c_val = self.target_encoded_r_c;
        let queries_val = self.queries;
        let num_queries = self.num_queries;

        // Public random challenge used to pack (index, value) pairs.
        let r = FpVar::new_input(cs.clone(), || {
            r_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Public lookup challenge (beta in LogUp relation).
        let beta = FpVar::new_input(cs.clone(), || {
            evaluation_point_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let encoded_r_a = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            encoded_r_a_val
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let encoded_r_ab = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            encoded_r_ab_val
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let encoded_r_c = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            encoded_r_c_val
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let query_indices = Vec::<FpVar<F>>::new_input(cs.clone(), || {
            let qs = queries_val
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)?;
            if qs.len() != num_queries {
                return Err(SynthesisError::AssignmentMissing);
            }
            Ok(qs
                .into_iter()
                .map(|q| F::from(q as u64))
                .collect::<Vec<_>>())
        })?;

        // Queried values can be provided directly or derived from the witness table
        // to simplify witness construction.
        let target_encoded_r_a = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            if let Some(v) = target_encoded_r_a_val.clone() {
                return Ok(v);
            }
            let table = encoded_r_a_val
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)?;
            let qs = queries_val
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)?;
            Self::derive_targets(&table, &qs)
        })?;
        let target_encoded_r_ab = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            if let Some(v) = target_encoded_r_ab_val.clone() {
                return Ok(v);
            }
            let table = encoded_r_ab_val
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)?;
            let qs = queries_val
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)?;
            Self::derive_targets(&table, &qs)
        })?;
        let target_encoded_r_c = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            if let Some(v) = target_encoded_r_c_val.clone() {
                return Ok(v);
            }
            let table = encoded_r_c_val
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)?;
            let qs = queries_val
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)?;
            Self::derive_targets(&table, &qs)
        })?;

        // Go meow.go의 t.Lookup(indices[i])에 해당:
        // EncX/EncYZ 인덱싱을 lookup argument로 강제한다.
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

        // C also opens at the same indices; keep it aligned with AB side.
        enforce_lookup_vector_indexing(
            cs,
            &encoded_r_c,
            &query_indices,
            &target_encoded_r_c,
            &r,
            &beta,
        )?;
        for (ab_i, c_i) in target_encoded_r_ab.iter().zip(target_encoded_r_c.iter()) {
            ab_i.enforce_equal(c_i)?;
        }

        Ok(())
    }
}
