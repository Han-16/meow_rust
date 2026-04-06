//! This module contains the error correction codes.
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    cfg_into_iter,
    One, Zero,
    fmt::Debug,
    rand::{CryptoRng, RngCore},
};

pub mod constraints;

pub mod reed_solomon;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// The basic setup parameters for the error correction code.
#[derive(Debug, Clone, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetupParameters {
    pub message_length: usize,
    pub codeword_length: usize,
}

/// This trait defines the error correction code.
pub trait LinearCode: Clone + Copy + Send + Sync {
    type Alphabet: Field;
    type SetupParameters: Clone + Copy + CanonicalSerialize + CanonicalDeserialize + Send + Sync;

    /// Setup the error correction code.
    fn setup<R: RngCore + CryptoRng>(
        sp: &Self::SetupParameters,
        rng: &mut R,
    ) -> Result<Self, Error>;

    /// Encode the message.
    fn encode(&self, message: &[Self::Alphabet]) -> Result<Vec<Self::Alphabet>, Error>;

    /// Returns the length of the message.
    fn message_length(&self) -> usize;

    /// Returns the length of the codeword.
    fn codeword_length(&self) -> usize;

    /// Returns the hamming distance of the code.
    fn distance(&self) -> usize;

    /// Returns the code rate.
    fn code_rate(&self) -> f64 {
        self.message_length() as f64 / self.codeword_length() as f64
    }

    /// Returns the relative distance of the code.
    fn relative_distance(&self) -> f64 {
        self.distance() as f64 / self.codeword_length() as f64
    }

    /// Returns the generator matrix of the code.
    fn generator_matrix(&self) -> Vec<Vec<Self::Alphabet>> {
        cfg_into_iter!(0..self.message_length())
            .map(|i| {
                let mut msg = vec![Self::Alphabet::zero(); self.codeword_length()];
                msg[i] = Self::Alphabet::one();
                self.encode(&msg).unwrap()
            })
            .collect()
    }
}

pub trait ProbailisticEncodingTest: LinearCode {
    type Point: Sized + Clone + Debug + Sync;

    fn evaluate_message(&self, message: &[Self::Alphabet], point: &Self::Point) -> Self::Alphabet;

    fn evaluate_codeword(&self, codeword: &[Self::Alphabet], point: &Self::Point)
    -> Self::Alphabet;

    fn is_valid(
        &self,
        message: &[Self::Alphabet],
        codeword: &[Self::Alphabet],
        point: &Self::Point,
    ) -> bool {
        self.evaluate_message(message, point) == self.evaluate_codeword(codeword, point)
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidConfig(String),
    InvalidMessageLength,
    InvalidCodewordLength,
    InvalidGenerator,
    SerializationError(ark_serialize::SerializationError),
}

impl ark_std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(s) => write!(f, "Invalid configuration: {}", s),
            Self::InvalidMessageLength => write!(f, "Invalid message length"),
            Self::InvalidCodewordLength => write!(f, "Invalid codeword length"),
            Self::InvalidGenerator => write!(f, "Invalid generator"),
            Self::SerializationError(e) => write!(f, "{e}"),
        }
    }
}

impl ark_std::error::Error for Error {}

impl From<ark_serialize::SerializationError> for Error {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerializationError(e)
    }
}
