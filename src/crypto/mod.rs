pub mod cp_link;
pub mod hash;
pub mod merkle;
pub mod pedersen;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidInputLength(&'static str),
    InvalidDepth,
    EmptyInput,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidInputLength(ctx) => write!(f, "invalid input length: {ctx}"),
            Self::InvalidDepth => write!(f, "invalid merkle depth"),
            Self::EmptyInput => write!(f, "empty input"),
        }
    }
}

impl std::error::Error for CryptoError {}
