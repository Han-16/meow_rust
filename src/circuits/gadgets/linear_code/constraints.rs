use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::FieldVar, R1CSVar};
use ark_relations::r1cs::SynthesisError;
use ark_std::fmt::Debug;

pub trait LinearCodeGadget<F: PrimeField> {
    type AlphabetVar: FieldVar<F, F> + R1CSVar<F> + EqGadget<F>;
}

pub trait ProbabilisticEncodingTestGadget<F: PrimeField>: LinearCodeGadget<F> {
    type PointVar: Sized + Clone + Debug;

    fn evaluate_message(
        &self,
        message: &[Self::AlphabetVar],
        point: &Self::PointVar,
    ) -> Self::AlphabetVar;

    fn evaluate_codeword(
        &self,
        codeword: &[Self::AlphabetVar],
        point: &Self::PointVar,
    ) -> Self::AlphabetVar;

    fn is_valid(
        &self,
        message: &[Self::AlphabetVar],
        codeword: &[Self::AlphabetVar],
        point: &Self::PointVar,
    ) -> Result<(), SynthesisError> {
        self.evaluate_message(message, point)
            .enforce_equal(&self.evaluate_codeword(codeword, point))
    }
}
