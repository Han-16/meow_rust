use std::{
    env,
    path::Path,
    time::{Duration, Instant},
};

use ark_bn254::{Bn254, Fr};
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use meow_rust::circuits::freivalds::Freivalds;
use meow_rust::protocol::prover::matmul;
use meow_rust::utils::benchmark_io::append_csv_row;
use meow_rust::utils::env::read_bench_env_params;

const BENCH_SEED: u64 = 42;
const CSV_PATH: &str = "benchmark/freivalds_protocol.csv";

#[derive(Debug, Clone)]
struct FreivaldsBenchConfig {
    log_k: usize,
    k: usize,
}

#[derive(Debug, Clone)]
struct FreivaldsBenchResult {
    matmul_time: Duration,
    constraint_count: usize,
    setup_time: Duration,
    prove_time: Duration,
    verify_time: Duration,
    verify_ok: bool,
}

fn main() {
    let configs = load_configs();
    println!("freivalds_protocol start: {} case(s)", configs.len());

    for config in configs {
        print_start(&config);
        let result = run_benchmark(&config);
        print_result(&result);
        write_csv(&config, &result).expect("failed to write benchmark/freivalds_protocol.csv");
    }
    println!("wrote benchmark csv: {}", CSV_PATH);
}

fn load_configs() -> Vec<FreivaldsBenchConfig> {
    let env = read_bench_env_params(".env").expect("failed to read LOG_K from .env");
    let (log_k_start, log_k_end) = parse_log_k_range(env.log_k, env.log_k_min, env.log_k_max);
    let mut out = Vec::new();
    for log_k in log_k_start..=log_k_end {
        out.push(FreivaldsBenchConfig {
            log_k,
            k: 1usize << log_k,
        });
    }
    out
}

fn parse_log_k_range(default_log_k: usize, env_min: usize, env_max: usize) -> (usize, usize) {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        return (default_log_k, default_log_k);
    }
    if args[0] != "--range" {
        panic!("unsupported argument: {} (use '--range' or '--range <min> <max>')", args[0]);
    }
    if args.len() == 1 {
        return (env_min, env_max);
    }
    if args.len() != 3 {
        panic!("invalid range arguments (use '--range' or '--range <min> <max>')");
    }

    let min = args[1]
        .parse::<usize>()
        .expect("invalid range min: must be usize");
    let max = args[2]
        .parse::<usize>()
        .expect("invalid range max: must be usize");
    assert!(min <= max, "range min must be <= max");
    (min, max)
}

fn print_start(config: &FreivaldsBenchConfig) {
    println!("--- freivalds case log_k={} ---", config.log_k);
    println!("params: log_k={}, k={}", config.log_k, config.k);
}

fn run_benchmark(config: &FreivaldsBenchConfig) -> FreivaldsBenchResult {
    let mut rng = StdRng::seed_from_u64(BENCH_SEED.wrapping_add(config.log_k as u64));

    let a = random_matrix(config.k, &mut rng);
    let b = random_matrix(config.k, &mut rng);

    let matmul_start = Instant::now();
    let c = matmul(&a, &b).expect("matrix multiplication failed");
    let matmul_time = matmul_start.elapsed();

    let r = Fr::rand(&mut rng);
    let witness_circuit = Freivalds::<Fr>::from_witness(r, a, b, c, config.k);
    let constraint_count = count_constraints(witness_circuit.clone());

    let setup_start = Instant::now();
    let setup_circuit = Freivalds::<Fr>::default(config.k);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng)
        .expect("freivalds setup failed");
    let setup_time = setup_start.elapsed();

    let prove_start = Instant::now();
    let proof =
        Groth16::<Bn254>::prove(&pk, witness_circuit, &mut rng).expect("freivalds prove failed");
    let prove_time = prove_start.elapsed();

    let verify_start = Instant::now();
    let verify_ok = Groth16::<Bn254>::verify(&vk, &[r], &proof).expect("freivalds verify failed");
    let verify_time = verify_start.elapsed();

    FreivaldsBenchResult {
        matmul_time,
        constraint_count,
        setup_time,
        prove_time,
        verify_time,
        verify_ok,
    }
}

fn print_result(result: &FreivaldsBenchResult) {
    println!("matmul     : {:.2}s", result.matmul_time.as_secs_f64());
    println!("constraint : {}", result.constraint_count);
    println!("setup      : {:.2}s", result.setup_time.as_secs_f64());
    println!("prove      : {:.2}s", result.prove_time.as_secs_f64());
    println!("verify     : {:.2}ms", secs_to_ms(result.verify_time.as_secs_f64()));
    println!("verify_result = {}", result.verify_ok);
}

fn write_csv(config: &FreivaldsBenchConfig, result: &FreivaldsBenchResult) -> std::io::Result<()> {
    let csv_path = Path::new(CSV_PATH);
    let header = [
        "log_k",
        "matmul_s",
        "constraint",
        "setup_s",
        "prove_s",
        "verify_ms",
        "verify_result",
    ];
    let row = [
        config.log_k.to_string(),
        format!("{:.2}", result.matmul_time.as_secs_f64()),
        result.constraint_count.to_string(),
        format!("{:.2}", result.setup_time.as_secs_f64()),
        format!("{:.2}", result.prove_time.as_secs_f64()),
        format!("{:.2}", secs_to_ms(result.verify_time.as_secs_f64())),
        result.verify_ok.to_string(),
    ];
    append_csv_row(csv_path, &header, &row)
}

fn random_matrix<R: ark_std::rand::Rng>(k: usize, rng: &mut R) -> Vec<Vec<Fr>> {
    (0..k)
        .map(|_| (0..k).map(|_| Fr::rand(rng)).collect::<Vec<_>>())
        .collect::<Vec<_>>()
}

fn count_constraints(circuit: Freivalds<Fr>) -> usize {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    circuit
        .generate_constraints(cs.clone())
        .expect("freivalds constraint generation should succeed");
    cs.num_constraints()
}

fn secs_to_ms(secs: f64) -> f64 {
    secs * 1000.0
}
