use ark_ff::Field;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::FieldVar,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{borrow::Borrow, marker::PhantomData};

#[derive(Clone)]
pub struct ColumnVar<F: Field, FV: FieldVar<F, F::BasePrimeField>> {
    pub vals: Vec<FV>,
    _field: PhantomData<F>,
}

// impl<F, FV> AllocVar<Column<F>, F::BasePrimeField> for ColumnVar<F, FV>
// where
//     F: Field,
//     FV: FieldVar<F, F::BasePrimeField>,
// {
//     fn new_variable<T: Borrow<Column<F>>>(
//         cs: impl Into<Namespace<F::BasePrimeField>>,
//         f: impl FnOnce() -> Result<T, SynthesisError>,
//         mode: AllocationMode,
//     ) -> Result<Self, SynthesisError> {
//         let vals = Vec::<FV>::new_variable(cs, || f().map(|col| col.borrow().vals), mode)?;
//         Ok(Self {
//             vals,
//             _field: PhantomData,
//         })
//     }
// }

/// A trait for lookup argument protocols.
///
/// A lookup argument allows a prover to demonstrate that a set of values (inputs)
/// are contained within a pre-defined table, without necessarily revealing the
/// relationship between specific inputs and table indices.
pub trait LookupArgumentGadget<F: Field> {
    type Var: FieldVar<F, F::BasePrimeField>;

    /// Registers the table and input variables within the constraint system.
    /// This step handles the allocation of necessary auxiliary witness variables.
    fn register(
        &mut self,
        cs: impl Into<Namespace<F::BasePrimeField>>,
        table: &[Self::Var],
        inputs: &[Self::Var],
    ) -> Result<(), SynthesisError>;

    /// Enforces the constraints required by the lookup argument protocol.
    fn prove(&self) -> Result<(), SynthesisError>;
}
