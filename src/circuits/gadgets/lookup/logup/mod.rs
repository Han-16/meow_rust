pub mod constraints;

use super::*;

use ark_std::rand::{CryptoRng, RngCore};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub struct LogUp<F: Field> {
    tables: Vec<Table<F>>,
    entries: Vec<Entry<F>>,
    counts: Vec<usize>,
}

impl<F: Field> LogUp<F> {
    pub fn new(num_table: usize, table_size: usize, entry_size: usize) -> LogUp<F> {
        LogUp {
            tables: vec![vec![F::zero(); table_size]; num_table],
            entries: vec![vec![F::zero(); entry_size]; num_table],
            counts: vec![0; table_size],
        }
    }

    pub fn rand<R: RngCore + CryptoRng>(
        num_table: usize,
        table_size: usize,
        entry_size: usize,
        rng: &mut R,
    ) -> LogUp<F> {
        let table = (0..table_size).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let entry = (0..entry_size).map(|_| F::rand(rng)).collect::<Vec<_>>();
        LogUp {
            tables: vec![table; num_table],
            entries: vec![entry; num_table],
            counts: vec![0; table_size],
        }
    }
}

impl<F: Field> LookupArgument<F> for LogUp<F> {
    fn append_table(&mut self, table: Table<F>) -> &mut Self {
        self.tables.push(table);
        self
    }

    fn append_entry(&mut self, entry: Entry<F>) -> &mut Self {
        self.entries.push(entry);
        self
    }

    fn tables(&self) -> &[Table<F>] {
        &self.tables
    }

    fn entries(&self) -> &[Entry<F>] {
        &self.entries
    }

    /// Prepares the lookup argument for use in a circuit.
    /// We assume that the table is already sorted.
    fn prepare(&mut self) -> Result<(), Error> {
        let table = self
            .tables
            .first()
            .ok_or_else(|| Error::EntryNotFound("no table".to_string()))?;
        let mut entry = self.entries.first().cloned().unwrap_or_default();
        self.counts.fill(0);
        entry.sort();

        #[cfg(not(feature = "parallel"))]
        {
            let mut table_idx = 0usize;
            let mut entry_idx = 0usize;
            while entry_idx < entry.len() {
                let target = entry[entry_idx];
                while table_idx < table.len() && table[table_idx] < target {
                    table_idx += 1;
                }
                if table_idx == table.len() || table[table_idx] != target {
                    return Err(Error::EntryNotFound(target.to_string()));
                }
                let mut cnt = 0usize;
                while entry_idx + cnt < entry.len() && entry[entry_idx + cnt] == target {
                    cnt += 1;
                }
                self.counts[table_idx] = cnt;
                entry_idx += cnt;
            }
        }
        #[cfg(feature = "parallel")]
        {
            todo!("parallelization is not yet supported");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare() {
        const N: usize = 1 << 16; // table size
        const M: usize = 1 << 10; // entry size
        let mut logup = LogUp::<ark_bn254::Fr>::new(1, N, M);
        assert!(logup.prepare().is_ok());
    }
}
