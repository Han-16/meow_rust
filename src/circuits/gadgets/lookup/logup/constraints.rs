use ark_ff::{Field, PrimeField};

use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar, R1CSVar};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::cfg_iter;
use std::collections::HashMap;

use super::{Config, LookupArgumentGadget};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// The LogUp lookup argument implementation.
///
/// LogUp proves inclusion in a table by checking the rational identity:
/// $$ \sum_i \frac{1}{\beta + a_i} = \sum_j \frac{m_j}{\beta + t_j} $$
/// where $\{a_i\}$ are the lookup entries, $\{t_j\}$ is the table,
/// and $\{m_j\}$ are the multiplicities of each table entry in the inputs.
pub struct LogUpArgument<F: Field, FV: FieldVar<F, F::BasePrimeField>> {
    /// The random challenge $\beta$ used for the rational identity.
    pub beta: Option<FV>,
    /// The lookup table variables.
    pub table_vars: Option<Vec<FV>>,
    /// The entries being looked up.
    pub entry_vars: Option<Vec<FV>>,
    /// Witness variables representing the multiplicity of each table entry.
    pub multiplicity_vars: Option<Vec<FV>>,
    /// Protocol configuration.
    pub config: Config<F>,
}

impl<F: PrimeField, FV: FieldVar<F, F>> LogUpArgument<F, FV> {
    /// Initializes a new LogUp argument with the given configuration.
    pub fn new(config: Config<F>) -> Self {
        Self {
            beta: None,
            table_vars: None,
            entry_vars: None,
            multiplicity_vars: None,
            config,
        }
    }
}

impl<F: Field, FV: FieldVar<F, F::BasePrimeField>> LookupArgumentGadget<F>
    for LogUpArgument<F, FV>
{
    type Var = FV;

    fn register(
        &mut self,
        cs: impl Into<Namespace<F::BasePrimeField>>,
        table_vars: &[FV],
        entry_vars: &[FV],
    ) -> Result<(), SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        if table_vars.len() != self.config.table_size || entry_vars.len() != self.config.entry_size
        {
            return Err(SynthesisError::AssignmentMissing);
        }

        // Extract concrete values for witness generation.
        // `FV` may not implement `Sync`, so extracting witness values from vars
        // must stay sequential even when the `parallel` feature is enabled.
        let table_vals: Result<Vec<F>, _> = table_vars.iter().map(|v| v.value()).collect();
        let entry_vals: Result<Vec<F>, _> = entry_vars.iter().map(|v| v.value()).collect();

        // Compute multiplicities if concrete values are available.
        // The table is assumed to contain unique elements.
        let multiplicities: Vec<F> = match (table_vals, entry_vals) {
            (Ok(t_vals), Ok(e_vals)) => {
                let table_index: HashMap<F, usize> = cfg_iter!(t_vals)
                    .enumerate()
                    .map(|(i, &v)| (v, i))
                    .collect();

                let mut counts = vec![0u64; self.config.table_size];
                for v in e_vals {
                    if let Some(&idx) = table_index.get(&v) {
                        counts[idx] += 1;
                    }
                }

                counts.into_iter().map(F::from).collect()
            }
            _ => vec![F::zero(); self.config.table_size],
        };

        // Allocate multiplicities as witness variables.
        let multiplicity_vars = Vec::<FV>::new_witness(cs, || Ok(multiplicities))?;

        self.multiplicity_vars = Some(multiplicity_vars);
        self.table_vars = Some(table_vars.to_vec());
        self.entry_vars = Some(entry_vars.to_vec());

        Ok(())
    }

    fn prove(&self) -> Result<(), SynthesisError> {
        match (
            &self.table_vars,
            &self.entry_vars,
            &self.multiplicity_vars,
            &self.beta,
        ) {
            (Some(table_vars), Some(entry_vars), Some(multiplicity_vars), Some(beta)) => {
                // Compute LHS: sum( 1 / (beta + a_i) )
                let mut lhs = FV::zero();
                for e in entry_vars {
                    let denom = e.clone() + beta;
                    lhs += denom.inverse()?;
                }

                // Compute RHS: sum( m_j / (beta + t_j) )
                let mut rhs = FV::zero();
                for (t, m) in table_vars.iter().zip(multiplicity_vars.iter()) {
                    let denom = t.clone() + beta;
                    rhs += &(denom.inverse()? * m);
                }

                lhs.enforce_equal(&rhs)
            }
            _ => Err(SynthesisError::AssignmentMissing),
        }
    }
}

pub fn enforce_lookup_vector_indexing<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    table_values: &[FpVar<F>],
    query_indices: &[FpVar<F>],
    query_values: &[FpVar<F>],
    index_challenge: &FpVar<F>,
    logup_challenge: &FpVar<F>,
) -> Result<(), SynthesisError> {
    if query_indices.len() != query_values.len() {
        return Err(SynthesisError::AssignmentMissing);
    }

    // table row: [index, table_value], query row: [query_index, query_value]
    let table_rows = table_values
        .iter()
        .enumerate()
        .map(|(i, v)| vec![FpVar::Constant(F::from(i as u64)), v.clone()])
        .collect::<Vec<_>>();
    let query_rows = query_indices
        .iter()
        .zip(query_values.iter())
        .map(|(i, v)| vec![i.clone(), v.clone()])
        .collect::<Vec<_>>();

    enforce_lookup_rows(cs, &table_rows, &query_rows, index_challenge, logup_challenge)?;

    Ok(())
}

fn validate_row_shapes<F: PrimeField>(
    table_rows: &[Vec<FpVar<F>>],
    query_rows: &[Vec<FpVar<F>>],
) -> Result<usize, SynthesisError> {
    if table_rows.is_empty() || query_rows.is_empty() {
        return Err(SynthesisError::AssignmentMissing);
    }
    let row_len = table_rows[0].len();
    if row_len == 0 {
        return Err(SynthesisError::AssignmentMissing);
    }
    if table_rows.iter().any(|r| r.len() != row_len) || query_rows.iter().any(|r| r.len() != row_len)
    {
        return Err(SynthesisError::AssignmentMissing);
    }
    Ok(row_len)
}

pub fn build_row_coeffs_from_alpha<F: PrimeField>(
    alpha: &FpVar<F>,
    width: usize,
) -> Vec<FpVar<F>> {
    let mut coeffs = Vec::with_capacity(width);
    let mut cur = FpVar::<F>::one();
    for _ in 0..width {
        coeffs.push(cur.clone());
        cur *= alpha;
    }
    coeffs
}

pub fn enforce_lookup_rows_with_coeffs<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    table_rows: &[Vec<FpVar<F>>],
    query_rows: &[Vec<FpVar<F>>],
    row_coeffs: &[FpVar<F>],
    logup_challenge: &FpVar<F>,
) -> Result<(), SynthesisError> {
    let row_len = validate_row_shapes(table_rows, query_rows)?;
    if row_coeffs.len() != row_len {
        return Err(SynthesisError::AssignmentMissing);
    }

    enforce_logup_rows(cs, table_rows, query_rows, logup_challenge, row_coeffs)
}

pub fn enforce_lookup_rows<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    table_rows: &[Vec<FpVar<F>>],
    query_rows: &[Vec<FpVar<F>>],
    alpha: &FpVar<F>,
    logup_challenge: &FpVar<F>,
) -> Result<(), SynthesisError> {
    let row_len = validate_row_shapes(table_rows, query_rows)?;
    let row_coeffs = build_row_coeffs_from_alpha(alpha, row_len);
    enforce_lookup_rows_with_coeffs(cs, table_rows, query_rows, &row_coeffs, logup_challenge)
}

fn row_linear_combination<F: PrimeField>(
    row: &[FpVar<F>],
    coeffs: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    if row.len() != coeffs.len() {
        return Err(SynthesisError::AssignmentMissing);
    }
    Ok(row
        .iter()
        .zip(coeffs.iter())
        .fold(FpVar::<F>::zero(), |acc, (v, c)| acc + (v * c)))
}

fn compute_counts<F: PrimeField>(
    table: &[Vec<F>],
    queries: &[Vec<F>],
) -> Result<Vec<F>, SynthesisError> {
    if table.is_empty() {
        return Err(SynthesisError::AssignmentMissing);
    }
    let row_len = table[0].len();
    if row_len == 0 {
        return Err(SynthesisError::AssignmentMissing);
    }
    if table.iter().any(|r| r.len() != row_len) || queries.iter().any(|r| r.len() != row_len) {
        return Err(SynthesisError::AssignmentMissing);
    }

    let mut table_index = HashMap::<Vec<F>, usize>::new();
    for (i, row) in table.iter().enumerate() {
        if table_index.insert(row.clone(), i).is_some() {
            return Err(SynthesisError::Unsatisfiable);
        }
    }

    let mut counts = vec![0u64; table.len()];
    for q in queries {
        let idx = table_index.get(q).ok_or(SynthesisError::Unsatisfiable)?;
        counts[*idx] += 1;
    }
    Ok(counts.into_iter().map(F::from).collect())
}

/// Enforce gnark log-derivative lookup on row tables:
/// sum_j exps[j] / (beta - <r, table[j]>) == sum_i 1 / (beta - <r, query[i]>)
///
/// - `table_rows` and `query_rows` are matrix rows.
/// - `row_coeffs` are random linear-combination coefficients.
/// - `exps` are allocated as witness and derived from concrete row values
///   using the same semantics as gnark `countHint`.
pub fn enforce_logup_rows<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    table_rows: &[Vec<FpVar<F>>],
    query_rows: &[Vec<FpVar<F>>],
    challenge: &FpVar<F>,
    row_coeffs: &[FpVar<F>],
) -> Result<(), SynthesisError> {
    // exps := count(table_row_j, queries) ; allocated as witness (gnark hint equivalent)
    let exps = Vec::<FpVar<F>>::new_witness(cs, || {
        let t_vals: Result<Vec<Vec<F>>, _> = table_rows
            .iter()
            .map(|row| row.iter().map(|v| v.value()).collect())
            .collect();
        let q_vals: Result<Vec<Vec<F>>, _> = query_rows
            .iter()
            .map(|row| row.iter().map(|v| v.value()).collect())
            .collect();
        match (t_vals, q_vals) {
            (Ok(tv), Ok(qv)) => compute_counts(&tv, &qv),
            // Setup mode may not provide concrete witness values yet.
            _ => Ok(vec![F::zero(); table_rows.len()]),
        }
    })?;

    let mut lp = FpVar::<F>::zero();
    for (row, exp) in table_rows.iter().zip(exps.iter()) {
        let row_comb = row_linear_combination(row, row_coeffs)?;
        let inv = (challenge - row_comb).inverse()?;
        lp += exp * inv;
    }

    let mut rp = FpVar::<F>::zero();
    for row in query_rows {
        let row_comb = row_linear_combination(row, row_coeffs)?;
        let inv = (challenge - row_comb).inverse()?;
        rp += inv;
    }

    lp.enforce_equal(&rp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::r1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Result as R1CSResult,
        SynthesisError,
    };

    fn vec_fr(xs: &[u64]) -> Vec<Fr> {
        xs.iter().map(|&x| Fr::from(x)).collect()
    }

    fn assert_circuit_satisfied<C: ConstraintSynthesizer<Fr>>(
        circuit: C,
    ) -> Result<usize, SynthesisError> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone())?;
        assert!(cs.is_satisfied()?);
        Ok(cs.num_constraints())
    }

    #[derive(Clone)]
    struct SimpleLookupCircuit {
        table: Vec<Fr>,
        entries: Vec<Fr>,
        beta: Fr,
    }

    impl ConstraintSynthesizer<Fr> for SimpleLookupCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R1CSResult<()> {
            let table_vars = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(self.table.clone()))?;
            let entry_vars =
                Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(self.entries.clone()))?;
            let beta_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.beta))?;

            let mut lookup = LogUpArgument::<Fr, FpVar<Fr>>::new(Config::new(
                table_vars.len(),
                entry_vars.len(),
            ));
            lookup.beta = Some(beta_var);
            lookup.register(cs, &table_vars, &entry_vars)?;
            lookup.prove()
        }
    }

    #[derive(Clone)]
    struct VectorIndexLookupCircuit {
        table: Vec<Fr>,
        query_indices: Vec<usize>,
        query_values: Vec<Fr>,
        alpha: Fr,
        beta: Fr,
    }

    impl ConstraintSynthesizer<Fr> for VectorIndexLookupCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R1CSResult<()> {
            let table_vars = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(self.table.clone()))?;
            let query_index_vars = Vec::<FpVar<Fr>>::new_input(cs.clone(), || {
                Ok(self
                    .query_indices
                    .clone()
                    .into_iter()
                    .map(|i| Fr::from(i as u64))
                    .collect::<Vec<_>>())
            })?;
            let query_value_vars =
                Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(self.query_values.clone()))?;
            let alpha_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.alpha))?;
            let beta_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.beta))?;

            enforce_lookup_vector_indexing(
                cs,
                &table_vars,
                &query_index_vars,
                &query_value_vars,
                &alpha_var,
                &beta_var,
            )
        }
    }

    #[derive(Clone)]
    struct MultiColumnLookupCircuit {
        table_rows: Vec<Vec<Fr>>,
        query_rows: Vec<Vec<Fr>>,
        alpha: Fr,
        beta: Fr,
    }

    impl ConstraintSynthesizer<Fr> for MultiColumnLookupCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R1CSResult<()> {
            let table_vars = self
                .table_rows
                .iter()
                .map(|row| Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(row.clone())))
                .collect::<Result<Vec<_>, _>>()?;
            let query_vars = self
                .query_rows
                .iter()
                .map(|row| Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(row.clone())))
                .collect::<Result<Vec<_>, _>>()?;
            let alpha_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.alpha))?;
            let beta_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.beta))?;

            enforce_lookup_rows(cs, &table_vars, &query_vars, &alpha_var, &beta_var)
        }
    }

    #[derive(Clone)]
    struct QueryNotInTableCircuit {
        beta: Fr,
        alpha: Fr,
    }

    impl ConstraintSynthesizer<Fr> for QueryNotInTableCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R1CSResult<()> {
            let table_rows = vec![
                vec![
                    FpVar::Constant(Fr::from(0u64)),
                    FpVar::Constant(Fr::from(10u64)),
                ],
                vec![
                    FpVar::Constant(Fr::from(1u64)),
                    FpVar::Constant(Fr::from(20u64)),
                ],
            ];
            let query_rows = vec![vec![
                FpVar::new_input(cs.clone(), || Ok(Fr::from(1u64)))?,
                FpVar::new_witness(cs.clone(), || Ok(Fr::from(999u64)))?,
            ]];

            let beta = FpVar::new_input(cs.clone(), || Ok(self.beta))?;
            let alpha = FpVar::new_input(cs, || Ok(self.alpha))?;
            let coeffs = build_row_coeffs_from_alpha(&alpha, 2);
            enforce_logup_rows(
                query_rows[0][0].cs(),
                &table_rows,
                &query_rows,
                &beta,
                &coeffs,
            )
        }
    }

    #[derive(Clone)]
    struct DuplicateTableRowsCircuit {
        beta: Fr,
        alpha: Fr,
    }

    impl ConstraintSynthesizer<Fr> for DuplicateTableRowsCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R1CSResult<()> {
            let table_rows = vec![
                vec![
                    FpVar::Constant(Fr::from(0u64)),
                    FpVar::Constant(Fr::from(10u64)),
                ],
                vec![
                    FpVar::Constant(Fr::from(0u64)),
                    FpVar::Constant(Fr::from(10u64)),
                ],
            ];
            let query_rows = vec![vec![
                FpVar::new_input(cs.clone(), || Ok(Fr::from(0u64)))?,
                FpVar::new_witness(cs.clone(), || Ok(Fr::from(10u64)))?,
            ]];

            let beta = FpVar::new_input(cs.clone(), || Ok(self.beta))?;
            let alpha = FpVar::new_input(cs, || Ok(self.alpha))?;
            let coeffs = build_row_coeffs_from_alpha(&alpha, 2);
            enforce_logup_rows(
                query_rows[0][0].cs(),
                &table_rows,
                &query_rows,
                &beta,
                &coeffs,
            )
        }
    }

    #[derive(Clone)]
    struct LookupScaleCircuit {
        table: Vec<Fr>,
        query_indices: Vec<usize>,
        query_values: Vec<Fr>,
        alpha: Fr,
        beta: Fr,
    }

    impl ConstraintSynthesizer<Fr> for LookupScaleCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R1CSResult<()> {
            let table_vars = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(self.table.clone()))?;
            let query_index_vars = Vec::<FpVar<Fr>>::new_input(cs.clone(), || {
                Ok(self
                    .query_indices
                    .iter()
                    .map(|&i| Fr::from(i as u64))
                    .collect::<Vec<_>>())
            })?;
            let query_value_vars =
                Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(self.query_values.clone()))?;
            let alpha = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.alpha))?;
            let beta = FpVar::<Fr>::new_input(cs, || Ok(self.beta))?;

            enforce_lookup_vector_indexing(
                alpha.cs(),
                &table_vars,
                &query_index_vars,
                &query_value_vars,
                &alpha,
                &beta,
            )
        }
    }

    #[test]
    fn test_simple_logup_lookup_circuit() -> Result<(), SynthesisError> {
        let circuit = SimpleLookupCircuit {
            table: vec_fr(&[3, 7, 11, 19]),
            entries: vec_fr(&[7, 19, 7]),
            beta: Fr::from(13u64),
        };

        let num_constraints = assert_circuit_satisfied(circuit)?;
        assert!(num_constraints > 0);
        eprintln!("simple_logup_lookup constraints = {}", num_constraints);
        Ok(())
    }

    #[test]
    fn test_vector_index_lookup_circuit() -> Result<(), SynthesisError> {
        let table = vec_fr(&[10, 20, 30, 40, 50]);
        let query_indices = vec![0usize, 3usize, 1usize, 4usize, 3usize];
        let query_values = query_indices.iter().map(|&i| table[i]).collect::<Vec<_>>();

        let circuit = VectorIndexLookupCircuit {
            table,
            query_indices,
            query_values,
            alpha: Fr::from(17u64),
            beta: Fr::from(29u64),
        };

        let num_constraints = assert_circuit_satisfied(circuit)?;
        assert!(num_constraints > 0);
        eprintln!("vector_index_lookup constraints = {}", num_constraints);
        Ok(())
    }

    #[test]
    fn test_vector_index_lookup_circuit_rejects_wrong_value() {
        let table = vec_fr(&[10, 20, 30, 40, 50]);
        let query_indices = vec![0usize, 3usize, 1usize, 4usize, 3usize];
        let mut query_values = query_indices.iter().map(|&i| table[i]).collect::<Vec<_>>();
        query_values[1] = Fr::from(41u64);

        let circuit = VectorIndexLookupCircuit {
            table,
            query_indices,
            query_values,
            alpha: Fr::from(17u64),
            beta: Fr::from(29u64),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        let res = circuit.generate_constraints(cs);
        assert!(res.is_err());
    }

    #[test]
    fn test_multicolumn_lookup_circuit() -> Result<(), SynthesisError> {
        let table_rows = vec![
            vec_fr(&[0, 10, 100]),
            vec_fr(&[1, 20, 200]),
            vec_fr(&[2, 30, 300]),
            vec_fr(&[3, 40, 400]),
        ];
        let query_rows = vec![table_rows[3].clone(), table_rows[1].clone(), table_rows[3].clone()];

        let circuit = MultiColumnLookupCircuit {
            table_rows,
            query_rows,
            alpha: Fr::from(7u64),
            beta: Fr::from(101u64),
        };

        let num_constraints = assert_circuit_satisfied(circuit)?;
        assert!(num_constraints > 0);
        eprintln!("multicolumn_lookup constraints = {}", num_constraints);
        Ok(())
    }

    #[test]
    fn test_enforce_logup_rows_rejects_query_not_in_table() {
        let circuit = QueryNotInTableCircuit {
            beta: Fr::from(13u64),
            alpha: Fr::from(17u64),
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        let res = circuit.generate_constraints(cs);
        assert!(res.is_err());
    }

    #[test]
    fn test_enforce_logup_rows_rejects_duplicate_table_rows() {
        let circuit = DuplicateTableRowsCircuit {
            beta: Fr::from(13u64),
            alpha: Fr::from(17u64),
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        let res = circuit.generate_constraints(cs);
        assert!(res.is_err());
    }

    #[test]
    fn test_lookup_len_1024_with_128_indices_constraint_count() -> Result<(), SynthesisError> {
        let table = (0..1024)
            .map(|i| Fr::from((10000 + i) as u64))
            .collect::<Vec<_>>();
        let query_indices = (0..128).map(|j| (j * 7 + 13) % 1024).collect::<Vec<_>>();
        let query_values = query_indices.iter().map(|&i| table[i]).collect::<Vec<_>>();

        let circuit = LookupScaleCircuit {
            table,
            query_indices,
            query_values,
            alpha: Fr::from(17u64),
            beta: Fr::from(29u64),
        };

        let num_constraints = assert_circuit_satisfied(circuit)?;
        eprintln!(
            "lookup_len_1024_with_128_indices constraints = {}",
            num_constraints
        );
        Ok(())
    }
}
