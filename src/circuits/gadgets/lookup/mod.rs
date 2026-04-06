use ark_ff::Field;
use ark_std::marker::PhantomData;

pub mod logup;

pub mod constraints;
pub use constraints::*;

/// Configuration for a lookup argument.
pub struct Config<F: Field> {
    /// Total number of entries in the lookup table.
    pub table_size: usize,
    /// Number of elements being looked up.
    pub entry_size: usize,
    pub _field: PhantomData<F>,
}

impl<F: Field> Config<F> {
    /// Creates a new configuration for a lookup argument.
    pub fn new(table_size: usize, entry_size: usize) -> Self {
        Self {
            table_size,
            entry_size,
            _field: PhantomData,
        }
    }
}

pub type Table<F> = Vec<F>;
pub type Entry<F> = Vec<F>;
pub type Matrix<F> = Vec<Vec<F>>;

pub trait LookupArgument<F: Field> {
    /// Appends a table to the lookup argument.
    fn append_table(&mut self, table: Table<F>) -> &mut Self;
    /// Appends an entry to the lookup argument.
    fn append_entry(&mut self, entry: Entry<F>) -> &mut Self;
    /// Returns a slice of the tables in the lookup argument.
    fn tables(&self) -> &[Table<F>];
    /// Returns a slice of the entries in the lookup argument.
    fn entries(&self) -> &[Entry<F>];
    /// Prepares the lookup argument for use in a circuit.
    fn prepare(&mut self) -> Result<(), Error>;
}

#[derive(Debug)]
pub enum Error {
    EntryNotFound(String),
    SerializationError(ark_serialize::SerializationError),
}

impl ark_std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::EntryNotFound(s) => write!(f, "Entry not found: {s}"),
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
