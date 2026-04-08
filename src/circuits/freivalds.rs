use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, Result as R1CSResult, SynthesisError,
};
use ark_std::{fmt::Debug, rand::Rng};

#[derive(Debug, Clone)]
pub struct Freivalds<F: PrimeField> {
    // Public Input
    pub r: Option<F>,

    // Committed Witness
    pub a: Option<Vec<Vec<F>>>,
    pub b: Option<Vec<Vec<F>>>,
    pub c: Option<Vec<Vec<F>>>,

    pub k: usize,
}

impl<F: PrimeField> Freivalds<F> {
    pub fn rand<R: Rng + ?Sized>(k: usize, rng: &mut R) -> Self {
        let r = F::rand(rng);

        let a = (0..k)
            .map(|_| (0..k).map(|_| F::rand(rng)).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let b = (0..k)
            .map(|_| (0..k).map(|_| F::rand(rng)).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let mut c = vec![vec![F::zero(); k]; k];
        for i in 0..k {
            for j in 0..k {
                let mut acc = F::zero();
                for t in 0..k {
                    acc += a[i][t] * b[t][j];
                }
                c[i][j] = acc;
            }
        }

        Self {
            r: Some(r),
            a: Some(a),
            b: Some(b),
            c: Some(c),
            k,
        }
    }

    pub fn default(k: usize) -> Self {
        Self {
            r: Some(F::zero()),
            a: Some(vec![vec![F::zero(); k]; k]),
            b: Some(vec![vec![F::zero(); k]; k]),
            c: Some(vec![vec![F::zero(); k]; k]),
            k,
        }
    }

    pub fn from_witness(r: F, a: Vec<Vec<F>>, b: Vec<Vec<F>>, c: Vec<Vec<F>>, k: usize) -> Self {
        Self {
            r: Some(r),
            a: Some(a),
            b: Some(b),
            c: Some(c),
            k,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Freivalds<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> R1CSResult<()> {
        let Self { r, a, b, c, k } = self;

        let r = FpVar::new_input(cs.clone(), || r.ok_or(SynthesisError::AssignmentMissing))?;

        let a_vals = a.ok_or(SynthesisError::AssignmentMissing)?;
        let b_vals = b.ok_or(SynthesisError::AssignmentMissing)?;
        let c_vals = c.ok_or(SynthesisError::AssignmentMissing)?;

        let a = a_vals
            .iter()
            .map(|row| Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(row.clone())))
            .collect::<Result<Vec<_>, _>>()?;
        let b = b_vals
            .iter()
            .map(|row| Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(row.clone())))
            .collect::<Result<Vec<_>, _>>()?;
        let c = c_vals
            .iter()
            .map(|row| Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(row.clone())))
            .collect::<Result<Vec<_>, _>>()?;

        // R[0]=1, R[i]=R[i-1]*r
        let mut power_of_r = Vec::with_capacity(k);
        for i in 0..k {
            if i == 0 {
                power_of_r.push(FpVar::one());
            } else {
                power_of_r.push(power_of_r[i - 1].clone() * &r);
            }
        }

        // x = R * A   (len = k)
        let mut x = Vec::with_capacity(k);
        for j in 0..k {
            let mut acc = FpVar::<F>::zero();
            for i in 0..k {
                acc += power_of_r[i].clone() * a[i][j].clone();
            }
            x.push(acc);
        }

        // y = x * B, z = R * C   (both len = k)
        for j in 0..k {
            let mut y = FpVar::<F>::zero();
            let mut z = FpVar::<F>::zero();
            for i in 0..k {
                y += x[i].clone() * b[i][j].clone();
            }
            for i in 0..k {
                z += power_of_r[i].clone() * c[i][j].clone();
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
    use ark_relations::r1cs::ConstraintSystem;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_freivalds_circuit_is_satisfied() {
        let mut rng = StdRng::seed_from_u64(0xFEE1_0001);
        let circuit = Freivalds::<Fr>::rand(8, &mut rng);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation should succeed");
        assert!(
            cs.is_satisfied().expect("satisfiability check should run"),
            "freivalds circuit must be satisfied with valid witness"
        );
    }
}
