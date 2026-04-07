use csv::WriterBuilder;
use std::{fs, io, path::Path};

pub fn append_csv_row(csv_path: &Path, header: &[&str], row: &[String]) -> Result<(), io::Error> {
    if let Some(parent) = csv_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file_is_empty = if csv_path.exists() {
        fs::metadata(csv_path).map(|m| m.len() == 0).unwrap_or(true)
    } else {
        true
    };

    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(csv_path)?;

    let mut wtr = WriterBuilder::new().has_headers(false).from_writer(file);
    if file_is_empty {
        wtr.write_record(header)
            .map_err(|e| io::Error::other(e.to_string()))?;
    }
    wtr.write_record(row)
        .map_err(|e| io::Error::other(e.to_string()))?;
    wtr.flush().map_err(|e| io::Error::other(e.to_string()))?;
    Ok(())
}
