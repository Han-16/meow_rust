use ark_relations::r1cs::SynthesisError;

use crate::crypto::CryptoError;

#[derive(Debug)]
pub enum ProtocolError {
    Crypto(CryptoError),
    Synthesis(SynthesisError),
    LinearCode(crate::circuits::gadgets::linear_code::Error),
    InvalidInput(&'static str),
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Synthesis(e) => write!(f, "{e}"),
            Self::LinearCode(e) => write!(f, "{e}"),
            Self::InvalidInput(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<CryptoError> for ProtocolError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<SynthesisError> for ProtocolError {
    fn from(value: SynthesisError) -> Self {
        Self::Synthesis(value)
    }
}

impl From<crate::circuits::gadgets::linear_code::Error> for ProtocolError {
    fn from(value: crate::circuits::gadgets::linear_code::Error) -> Self {
        Self::LinearCode(value)
    }
}
