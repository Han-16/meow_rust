use std::{collections::HashMap, fs, io};

pub fn read_env_map(path: &str) -> io::Result<HashMap<String, String>> {
    let text = fs::read_to_string(path)?;
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once('=').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid .env line: missing '='")
        })?;
        out.insert(k.trim().to_string(), v.trim().to_string());
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
pub struct BenchEnvParams {
    pub log_k: usize,
    pub log_k_min: usize,
    pub log_k_max: usize,
    pub l: usize,
    pub rho: f64,
}

pub fn read_bench_env_params(path: &str) -> io::Result<BenchEnvParams> {
    let env = read_env_map(path)?;

    let parse_usize = |key: &str| -> io::Result<usize> {
        env.get(key)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("missing key: {key}"))
            })?
            .parse()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid usize: {key}"))
            })
    };
    let parse_f64 = |key: &str| -> io::Result<f64> {
        env.get(key)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("missing key: {key}"))
            })?
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("invalid f64: {key}")))
    };

    let params = BenchEnvParams {
        log_k: parse_usize("LOG_K")?,
        log_k_min: parse_usize("LOG_K_MIN")?,
        log_k_max: parse_usize("LOG_K_MAX")?,
        l: parse_usize("L")?,
        rho: parse_f64("RHO")?,
    };

    if !(params.rho > 0.0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "RHO must be > 0",
        ));
    }
    if params.log_k_min > params.log_k_max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "LOG_K_MIN must be <= LOG_K_MAX",
        ));
    }

    Ok(params)
}
