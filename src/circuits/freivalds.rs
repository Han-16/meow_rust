use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, Result as R1CSResult, SynthesisError,
};
use ark_std::{fmt::Debug, rand::Rng};

use ndarray::{Array1, Array2};

#[derive(Debug, Clone)]
pub struct Freivalds<F: PrimeField> {
    // Public Input
    pub r: Option<F>,

    // Committed Witness
    pub a: Option<Vec<F>>,
    pub b: Option<Vec<F>>,
    pub c: Option<Vec<F>>,

    n: usize,
    k: usize,
    m: usize,
}

impl<F: PrimeField> Freivalds<F> {
    pub fn rand<R: Rng + ?Sized>(n: usize, k: usize, m: usize, rng: &mut R) -> Self {
        let r = F::rand(rng);

        let raw_a = (0..n * k).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let raw_b = (0..k * m).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let a = Array2::from_shape_vec((n, k), raw_a.clone()).unwrap();
        let b = Array2::from_shape_vec((k, m), raw_b.clone()).unwrap();
        let c = a * b;
        let (raw_c, offset) = c.into_raw_vec_and_offset();
        debug_assert_eq!(offset, Some(0));

        Self {
            r: Some(r),
            a: Some(raw_a),
            b: Some(raw_b),
            c: Some(raw_c),
            n,
            k,
            m,
        }
    }

    pub fn default(n: usize, k: usize, m: usize) -> Self {
        Self {
            r: Some(F::zero()),
            a: Some(vec![F::zero(); n * k]),
            b: Some(vec![F::zero(); k * m]),
            c: Some(vec![F::zero(); n * m]),
            n,
            k,
            m,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Freivalds<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> R1CSResult<()> {
        let r = FpVar::new_input(cs.clone(), || {
            self.r.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let a = {
            let raw_a = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
                self.a.ok_or(SynthesisError::AssignmentMissing)
            })?;
            Array2::from_shape_vec((self.n, self.k), raw_a).unwrap()
        };
        let b = {
            let raw_b = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
                self.b.ok_or(SynthesisError::AssignmentMissing)
            })?;
            Array2::from_shape_vec((self.k, self.m), raw_b).unwrap()
        };
        let c = {
            let raw_c = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
                self.c.ok_or(SynthesisError::AssignmentMissing)
            })?;
            Array2::from_shape_vec((self.n, self.m), raw_c).unwrap()
        };

        let mut power_of_r = Vec::with_capacity(self.n);
        for _ in 0..self.n {
            power_of_r.push(power_of_r.last().map(|r_i| r_i * &r).unwrap_or(r.clone()));
        }
        let power_of_r = Array1::from_shape_vec(self.n, power_of_r).unwrap();

        let r_a = &power_of_r * &a;
        let r_ab = r_a * &b;
        let r_c = power_of_r * &c;

        for (r_ab_i, r_c_i) in r_ab.iter().zip(&r_c) {
            r_ab_i.enforce_equal(r_c_i)?;
        }

        Ok(())
    }
}
