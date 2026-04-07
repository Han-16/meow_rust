use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, Result as R1CSResult, SynthesisError,
};
use ark_std::{fmt::Debug, rand::Rng};

use ndarray::Array2;

#[derive(Debug, Clone)]
pub struct Freivalds<F: PrimeField> {
    // Public Input
    pub r: Option<F>,

    // Committed Witness
    pub a: Option<Vec<F>>,
    pub b: Option<Vec<F>>,
    pub c: Option<Vec<F>>,

    k: usize,
}

impl<F: PrimeField> Freivalds<F> {
    pub fn rand<R: Rng + ?Sized>(k: usize, rng: &mut R) -> Self {
        let r = F::rand(rng);

        let raw_a = (0..k * k).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let raw_b = (0..k * k).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let mut raw_c = vec![F::zero(); k * k];
        for i in 0..k {
            for j in 0..k {
                let mut acc = F::zero();
                for t in 0..k {
                    acc += raw_a[i * k + t] * raw_b[t * k + j];
                }
                raw_c[i * k + j] = acc;
            }
        }

        Self {
            r: Some(r),
            a: Some(raw_a),
            b: Some(raw_b),
            c: Some(raw_c),
            k,
        }
    }

    pub fn default(k: usize) -> Self {
        Self {
            r: Some(F::zero()),
            a: Some(vec![F::zero(); k * k]),
            b: Some(vec![F::zero(); k * k]),
            c: Some(vec![F::zero(); k * k]),
            k,
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
            Array2::from_shape_vec((self.k, self.k), raw_a).unwrap()
        };
        let b = {
            let raw_b = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
                self.b.ok_or(SynthesisError::AssignmentMissing)
            })?;
            Array2::from_shape_vec((self.k, self.k), raw_b).unwrap()
        };
        let c = {
            let raw_c = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
                self.c.ok_or(SynthesisError::AssignmentMissing)
            })?;
            Array2::from_shape_vec((self.k, self.k), raw_c).unwrap()
        };

        // R[0]=1, R[i]=R[i-1]*r
        let mut power_of_r = Vec::with_capacity(self.k);
        for i in 0..self.k {
            if i == 0 {
                power_of_r.push(FpVar::one());
            } else {
                power_of_r.push(power_of_r[i - 1].clone() * &r);
            }
        }

        // x = R * A   (len = k)
        let mut x = Vec::with_capacity(self.k);
        for j in 0..self.k {
            let mut acc = FpVar::<F>::zero();
            for i in 0..self.k {
                acc += power_of_r[i].clone() * a[[i, j]].clone();
            }
            x.push(acc);
        }

        // y = x * B, z = R * C   (both len = k)
        for j in 0..self.k {
            let mut y = FpVar::<F>::zero();
            let mut z = FpVar::<F>::zero();
            for i in 0..self.k {
                y += x[i].clone() * b[[i, j]].clone();
            }
            for i in 0..self.k {
                z += power_of_r[i].clone() * c[[i, j]].clone();
            }
            y.enforce_equal(&z)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::{ConstraintSystem, SynthesisError};
    use rand::{rngs::StdRng, SeedableRng};
    use std::{path::Path, thread};

    use crate::utils::{benchmark_io::append_csv_row, env::read_bench_env_params};

    const STACK_SIZE: usize = 64 * 1024 * 1024;

    fn count_constraints_for_k(k: usize, seed: u64) -> Result<usize, SynthesisError> {
        let handle = thread::Builder::new()
            .stack_size(STACK_SIZE)
            .spawn(move || -> Result<usize, SynthesisError> {
                let mut rng = StdRng::seed_from_u64(seed);
                let circuit = Freivalds::<Fr>::rand(k, &mut rng);

                let cs = ConstraintSystem::<Fr>::new_ref();
                circuit.generate_constraints(cs.clone())?;
                if !cs.is_satisfied()? {
                    return Err(SynthesisError::Unsatisfiable);
                }
                Ok(cs.num_constraints())
            })
            .map_err(|_| SynthesisError::AssignmentMissing)?;

        handle
            .join()
            .map_err(|_| SynthesisError::AssignmentMissing)?
    }

    #[test]
    fn test_freivalds_constraint_count_from_env() -> Result<(), SynthesisError> {
        let params =
            read_bench_env_params(".env").map_err(|_| SynthesisError::AssignmentMissing)?;
        let log_k = params.log_k;
        let k = 1usize << log_k;

        let constraints = count_constraints_for_k(k, 0xFEE1_0001)?;
        assert!(constraints > 0);
        eprintln!(
            "freivalds constraints (from .env): LOG_K={}, K=N=M={} => {}",
            log_k, k, constraints
        );
        Ok(())
    }

    #[test]
    fn test_freivalds_constraint_count_range_from_env() -> Result<(), SynthesisError> {
        let params =
            read_bench_env_params(".env").map_err(|_| SynthesisError::AssignmentMissing)?;
        let log_k_min = params.log_k_min;
        let log_k_max = params.log_k_max;

        let csv_path = Path::new("benchmark").join("freivalds_constraints.csv");
        for log_k in log_k_min..=log_k_max {
            let k = 1usize << log_k;
            let constraints =
                count_constraints_for_k(k, 0xFEE1_0001u64.wrapping_add(log_k as u64))?;

            let row = [
                log_k.to_string(),
                k.to_string(),
                k.to_string(),
                k.to_string(),
                constraints.to_string(),
            ];
            append_csv_row(&csv_path, &["log_k", "n", "k", "m", "constraints"], &row)
                .map_err(|_| SynthesisError::AssignmentMissing)?;

            eprintln!(
                "freivalds constraints (range/.env): LOG_K={}, K=N=M={} => {}",
                log_k, k, constraints
            );
        }
        eprintln!("wrote benchmark csv: {}", csv_path.display());
        Ok(())
    }
}
