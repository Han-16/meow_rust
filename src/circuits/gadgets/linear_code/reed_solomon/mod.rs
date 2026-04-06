//!Reed Solomon Code
pub mod constraints;

use super::SetupParameters;

use ark_ff::FftField;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};

use super::{Error, LinearCode, ProbailisticEncodingTest};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Debug, Clone, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct ReedSolomonCode<F: FftField> {
    message_length: usize,
    codeword_length: usize,
    evaluation_domain: Radix2EvaluationDomain<F>,
}

impl<F: FftField> ReedSolomonCode<F> {
    pub fn new(message_length: usize, codeword_length: usize) -> Self {
        Self {
            message_length,
            codeword_length,
            evaluation_domain: Radix2EvaluationDomain::<F>::new(codeword_length).unwrap(),
        }
    }

    /// Returns the generator element of the evaluation domain.
    pub fn omega(&self) -> F {
        self.evaluation_domain.group_gen
    }
}

impl<F: FftField> LinearCode for ReedSolomonCode<F> {
    type Alphabet = F;
    type SetupParameters = SetupParameters;

    fn setup<R: RngCore + CryptoRng>(sp: &Self::SetupParameters, _: &mut R) -> Result<Self, Error> {
        Ok(ReedSolomonCode {
            message_length: sp.message_length,
            codeword_length: sp.codeword_length,
            evaluation_domain: Radix2EvaluationDomain::<F>::new(sp.codeword_length).ok_or(
                Error::InvalidConfig(format!("RS code's N doesn't satisfy domain size")),
            )?,
        })
    }

    fn encode(&self, message: &[Self::Alphabet]) -> Result<Vec<Self::Alphabet>, Error> {
        if message.len() != self.message_length {
            return Err(Error::InvalidMessageLength);
        }
        let codeword = self.evaluation_domain.fft(message);
        Ok(codeword)
    }

    fn message_length(&self) -> usize {
        self.message_length
    }

    fn codeword_length(&self) -> usize {
        self.codeword_length
    }

    fn distance(&self) -> usize {
        self.codeword_length - self.message_length
    }
}

impl<F: FftField> ProbailisticEncodingTest for ReedSolomonCode<F> {
    type Point = F;

    fn evaluate_message(&self, message: &[Self::Alphabet], point: &Self::Point) -> Self::Alphabet {
        let poly = DensePolynomial::<F>::from_coefficients_slice(message);
        poly.evaluate(point)
    }

    fn evaluate_codeword(
        &self,
        codeword: &[Self::Alphabet],
        point: &Self::Point,
    ) -> Self::Alphabet {
        let omega = self.omega();
        let cofactor = (point.pow([self.codeword_length() as u64]) - F::one())
            / F::from(self.codeword_length() as u64);
        let result = {
            #[cfg(feature = "parallel")]
            {
                codeword
                    .par_iter()
                    .enumerate()
                    .map(|(i, c)| {
                        let omega_i = omega.pow([i as u64]);
                        let numerator = *c * omega_i;
                        let denominator = *point - omega_i;
                        numerator / denominator
                    })
                    .sum::<F>()
            }
            #[cfg(not(feature = "parallel"))]
            {
                let (result, _) =
                    codeword
                        .iter()
                        .fold((F::zero(), F::one()), |(eval, omega_i), c| {
                            let numerator = *c * omega_i;
                            let denominator = *point - omega_i;
                            (eval + numerator / denominator, omega_i * omega)
                        });
                result
            }
        };
        result * cofactor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ff::UniformRand;
    use ark_std::{
        end_timer,
        rand::{rngs::StdRng, SeedableRng},
        start_timer, test_rng,
    };

    type F = ark_bn254::Fr;
    type R = StdRng;

    #[test]
    fn reed_solomon_code() {
        let mut rng = R::seed_from_u64(test_rng().next_u64());

        const LOG_RATE: usize = 3;
        const K: usize = 1 << 10;
        const N: usize = K << LOG_RATE;

        let sp = SetupParameters {
            message_length: K,
            codeword_length: N,
        };
        let rs_code = ReedSolomonCode::<F>::setup(&sp, &mut rng).unwrap();

        let msg = vec![F::rand(&mut rng); K];

        let encode_timer = start_timer!(|| "Encode Reed Solomon Code");
        let _ = rs_code.encode(&msg).unwrap();
        end_timer!(encode_timer);
    }

    #[test]
    fn test_probabilistic_evaluation() {
        let mut rng = R::seed_from_u64(test_rng().next_u64());

        const LOG_RATE: usize = 3;
        const K: usize = 1 << 10;
        const N: usize = K << LOG_RATE;

        let sp = SetupParameters {
            message_length: K,
            codeword_length: N,
        };
        let rs_code = ReedSolomonCode::<F>::setup(&sp, &mut rng).unwrap();

        let message = vec![F::rand(&mut rng); K];
        let codeword = rs_code.encode(&message).unwrap();
        let point = F::rand(&mut rng);

        let eval_message = rs_code.evaluate_message(&message, &point);
        let eval_codeword = rs_code.evaluate_codeword(&codeword, &point);
        assert_eq!(eval_message, eval_codeword);
    }
}
