use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::FieldVar, prelude::AllocationMode};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{borrow::Borrow, marker::PhantomData};

use crate::circuits::gadgets::linear_code::{
    constraints::{LinearCodeGadget, ProbabilisticEncodingTestGadget},
    reed_solomon::ReedSolomonCode,
    LinearCode,
};

pub struct ReedSolomonGadget<F: PrimeField, FV: FieldVar<F, F>> {
    pub message_length: usize,
    pub codeword_length: usize,
    pub omega: FV,
    _alphabet: PhantomData<F>,
}

impl<F: PrimeField, FV: FieldVar<F, F>> AllocVar<ReedSolomonCode<F>, F>
    for ReedSolomonGadget<F, FV>
{
    fn new_variable<T: Borrow<ReedSolomonCode<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let rs_code = f().map(|code| code.borrow().clone());
        let omega = FV::new_variable(cs, || rs_code.map(|code| code.omega()), mode)?;
        Ok(Self {
            message_length: rs_code.map(|code| code.message_length())?,
            codeword_length: rs_code.map(|code| code.codeword_length())?,
            omega,
            _alphabet: PhantomData,
        })
    }
}

impl<F: PrimeField, FV: FieldVar<F, F>> LinearCodeGadget<F> for ReedSolomonGadget<F, FV> {
    type AlphabetVar = FV;
}

impl<F: PrimeField, FV: FieldVar<F, F>> ProbabilisticEncodingTestGadget<F>
    for ReedSolomonGadget<F, FV>
{
    type PointVar = FV;

    fn evaluate_message(&self, message: &[FV], point: &FV) -> FV {
        let mut acc = FV::zero();
        let mut pow = FV::one();
        for m in message {
            acc += m.clone() * pow.clone();
            pow *= point.clone();
        }
        acc
    }

    fn evaluate_codeword(&self, codeword: &[FV], point: &FV) -> FV {
        let n = F::from(self.codeword_length as u64);
        let n_inv = n
            .inverse()
            .expect("codeword length must be invertible in field");
        let cofactor = (point
            .pow_by_constant(&[self.codeword_length as u64])
            .unwrap()
            - FV::one())
            * FV::constant(n_inv);
        let (result, _) = codeword
            .iter()
            .fold((FV::zero(), FV::one()), |(eval, omega_i), c| {
                let numerator = c.clone() * omega_i.clone();
                let denominator_inv = (point.clone() - omega_i.clone()).inverse().unwrap();
                (
                    eval + numerator * denominator_inv,
                    omega_i.clone() * self.omega.clone(),
                )
            });
        result * cofactor
    }
}
