use std::{
    env,
    path::Path,
    time::{Duration, Instant},
};

use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::Zero;
use meow_rust::circuits::meow::Meow;
use meow_rust::protocol::prover::{ProveTimeBreakdown, Prover};
use meow_rust::protocol::verifier::{Verifier, VerifyTimeBreakdown};
use meow_rust::protocol::{MerkleOpening, ProtocolParams, ProtocolProof};
use meow_rust::utils::benchmark_io::append_csv_row;
use meow_rust::utils::env::read_bench_env_params;

const BENCH_SEED: u64 = 42;
const CSV_PATH: &str = "benchmark/meow_protocol.csv";

#[derive(Debug, Clone)]
struct MeowBenchConfig {
    log_k: usize,
    rho: f64,
    rho_den: usize,
    params: ProtocolParams,
}

#[derive(Debug, Clone)]
struct MeowBenchResult {
    constraint_count: usize,
    setup_time: Duration,
    prove_time: Duration,
    verify_time: Duration,
    total_time: Duration,
    prove_breakdown: ProveTimeBreakdown,
    verify_breakdown: VerifyTimeBreakdown,
    proof_sizes: ProofSizeBreakdown,
    verify_ok: bool,
}

#[derive(Debug, Clone)]
struct ProofSizeBreakdown {
    groth16_proof_bytes: usize,
    merkle_membership_total_bytes: usize,
    avg_merkle_membership_bytes: f64,
    public_inputs_bytes: usize,
    public_transcript_est_bytes: usize,
    protocol_total_est_bytes: usize,
}

fn main() {
    let configs = load_configs();
    println!("meow_protocol start: {} case(s)", configs.len());

    for config in configs {
        print_start(&config);
        let result = run_benchmark(&config);
        print_result(&result);
        write_benchmark_csv(&config, &result).expect("failed to write benchmark/meow_protocol.csv");
    }
    println!("wrote benchmark csv: {}", CSV_PATH);
}

fn load_configs() -> Vec<MeowBenchConfig> {
    let env = read_bench_env_params(".env").expect("failed to read LOG_K/L/RHO from .env");
    let l = env.l;
    let rho = env.rho;
    let (log_k_start, log_k_end) = parse_log_k_range(env.log_k, env.log_k_min, env.log_k_max);

    assert!(rho > 0.0, "RHO must be > 0");
    let rho_den = (1.0 / rho).round() as usize;
    let mut out = Vec::new();

    for log_k in log_k_start..=log_k_end {
        let k = 1usize << log_k;
        let n_f = (k as f64) / rho;
        let n = n_f.round() as usize;
        assert!(
            ((n as f64) - n_f).abs() <= 1e-9,
            "RHO must make N integer: N = K / RHO"
        );
        assert!(l <= n, "l must be <= n");

        let params = ProtocolParams {
            k,
            n,
            l,
        };

        out.push(MeowBenchConfig {
            log_k,
            rho,
            rho_den,
            params,
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
        panic!(
            "unsupported argument: {} (use '--range' or '--range <min> <max>')",
            args[0]
        );
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

fn print_start(config: &MeowBenchConfig) {
    println!("--- meow case log_k={} ---", config.log_k);
    println!(
        "params: k={}, rho={:.1} (1/{}), n={}, L={}",
        config.params.k, config.rho, config.rho_den, config.params.n, config.params.l
    );
}

fn run_benchmark(config: &MeowBenchConfig) -> MeowBenchResult {
    let mut rng = StdRng::seed_from_u64(BENCH_SEED.wrapping_add(config.log_k as u64));
    let total_start = Instant::now();

    let prover = Prover::setup(config.params.k, &mut rng);
    let constraint_count = count_meow_constraints(&config.params, prover.poseidon_config.clone());

    let setup_start = Instant::now();
    let setup = prover
        .circuit_setup(&config.params, &mut rng)
        .expect("circuit setup failed");
    let setup_time = setup_start.elapsed();

    let prove_start = Instant::now();
    let (protocol_proof, prove_breakdown) = prover
        .prove_with_random_matrices_timed(&config.params, &setup.pk, &mut rng)
        .expect("prove failed");
    let prove_time = prove_start.elapsed();

    let verify_start = Instant::now();
    let verifier = Verifier::new(
        config.params.clone(),
        setup.vk,
        prover.poseidon_config.clone(),
    );
    let (verify_ok, verify_breakdown) = verifier
        .verify_with_timing(&protocol_proof)
        .expect("verify failed");
    let verify_time = verify_start.elapsed();

    MeowBenchResult {
        constraint_count,
        setup_time,
        prove_time,
        verify_time,
        total_time: total_start.elapsed(),
        prove_breakdown,
        verify_breakdown,
        proof_sizes: compute_proof_sizes(&protocol_proof),
        verify_ok,
    }
}

fn print_result(result: &MeowBenchResult) {
    println!("setup_time  : {:.2}s", result.setup_time.as_secs_f64());
    println!("constraint  : {}", result.constraint_count);
    println!("prove_time  : {:.2}s", result.prove_time.as_secs_f64());
    println!(
        "  - matmul                  : {:.2}s",
        result.prove_breakdown.matmul.as_secs_f64()
    );
    println!(
        "  - pedersen_commit         : {:.2}s",
        result.prove_breakdown.pedersen_commit.as_secs_f64()
    );
    println!(
        "  - groth16_prove           : {:.2}s",
        result.prove_breakdown.groth16_prove.as_secs_f64()
    );
    println!(
        "  - merkle_membership_proof : {:.2}s",
        result.prove_breakdown.merkle_membership_proof.as_secs_f64()
    );
    println!(
        "  - tracked_total           : {:.2}s",
        result.prove_breakdown.tracked_total().as_secs_f64()
    );

    println!("verify_time : {:.2}ms", secs_to_ms(result.verify_time.as_secs_f64()));
    println!(
        "  - groth16_verify          : {:.2}ms",
        secs_to_ms(result.verify_breakdown.groth16_verify.as_secs_f64())
    );
    println!(
        "  - merkle_membership_verify: {:.2}ms",
        secs_to_ms(result.verify_breakdown.merkle_membership_verify.as_secs_f64())
    );
    println!(
        "  - tracked_total           : {:.2}ms",
        secs_to_ms(result.verify_breakdown.tracked_total().as_secs_f64())
    );

    println!("proof_size (compressed serialization):");
    println!(
        "  - groth16_proof           : {} bytes ({:.2} KiB)",
        result.proof_sizes.groth16_proof_bytes,
        bytes_to_kib(result.proof_sizes.groth16_proof_bytes)
    );
    println!(
        "  - merkle_membership_total : {} bytes ({:.2} KiB)",
        result.proof_sizes.merkle_membership_total_bytes,
        bytes_to_kib(result.proof_sizes.merkle_membership_total_bytes)
    );
    println!(
        "    * avg_per_membership    : {:.2} bytes",
        result.proof_sizes.avg_merkle_membership_bytes
    );
    println!(
        "  - public_inputs           : {} bytes ({:.2} KiB)",
        result.proof_sizes.public_inputs_bytes,
        bytes_to_kib(result.proof_sizes.public_inputs_bytes)
    );
    println!(
        "  - public_transcript(est.) : {} bytes ({:.2} KiB)",
        result.proof_sizes.public_transcript_est_bytes,
        bytes_to_kib(result.proof_sizes.public_transcript_est_bytes)
    );
    println!(
        "  - protocol_total(est.)    : {} bytes ({:.2} KiB)",
        result.proof_sizes.protocol_total_est_bytes,
        bytes_to_kib(result.proof_sizes.protocol_total_est_bytes)
    );
    println!("total_time  : {:.2}s", result.total_time.as_secs_f64());
    println!("verify_result = {}", result.verify_ok);
}

fn write_benchmark_csv(config: &MeowBenchConfig, result: &MeowBenchResult) -> std::io::Result<()> {
    let csv_path = Path::new(CSV_PATH);
    let header = [
        "log_k",
        "k",
        "rho",
        "n",
        "l",
        "constraint",
        "setup_time_s",
        "prove_time_s",
        "prove_matmul_s",
        "prove_pedersen_commit_s",
        "prove_groth16_prove_s",
        "prove_merkle_membership_proof_s",
        "verify_time_ms",
        "verify_groth16_verify_ms",
        "verify_merkle_membership_verify_ms",
        "total_time_s",
        "verify_result",
        "proof_groth16_bytes",
        "proof_merkle_membership_total_bytes",
        "proof_avg_merkle_membership_bytes",
        "proof_public_inputs_bytes",
        "proof_public_transcript_est_bytes",
        "proof_protocol_total_est_bytes",
    ];
    let row = [
        config.log_k.to_string(),
        config.params.k.to_string(),
        format!("{:.1}", config.rho),
        config.params.n.to_string(),
        config.params.l.to_string(),
        result.constraint_count.to_string(),
        format!("{:.2}", result.setup_time.as_secs_f64()),
        format!("{:.2}", result.prove_time.as_secs_f64()),
        format!("{:.2}", result.prove_breakdown.matmul.as_secs_f64()),
        format!(
            "{:.2}",
            result.prove_breakdown.pedersen_commit.as_secs_f64()
        ),
        format!("{:.2}", result.prove_breakdown.groth16_prove.as_secs_f64()),
        format!(
            "{:.2}",
            result.prove_breakdown.merkle_membership_proof.as_secs_f64()
        ),
        format!("{:.2}", secs_to_ms(result.verify_time.as_secs_f64())),
        format!(
            "{:.2}",
            secs_to_ms(result.verify_breakdown.groth16_verify.as_secs_f64())
        ),
        format!(
            "{:.2}",
            secs_to_ms(result.verify_breakdown.merkle_membership_verify.as_secs_f64())
        ),
        format!("{:.2}", result.total_time.as_secs_f64()),
        result.verify_ok.to_string(),
        result.proof_sizes.groth16_proof_bytes.to_string(),
        result.proof_sizes.merkle_membership_total_bytes.to_string(),
        format!("{:.2}", result.proof_sizes.avg_merkle_membership_bytes),
        result.proof_sizes.public_inputs_bytes.to_string(),
        result.proof_sizes.public_transcript_est_bytes.to_string(),
        result.proof_sizes.protocol_total_est_bytes.to_string(),
    ];
    append_csv_row(csv_path, &header, &row)
}

fn serialized_size_compressed<T: CanonicalSerialize>(value: &T) -> usize {
    let mut buf = Vec::new();
    value
        .serialize_compressed(&mut buf)
        .expect("serialization must succeed");
    buf.len()
}

fn membership_opening_size_bytes(opening: &MerkleOpening) -> usize {
    serialized_size_compressed(&opening.commitment)
        + serialized_size_compressed(&opening.siblings)
        + 8
}

fn compute_proof_sizes(proof: &ProtocolProof) -> ProofSizeBreakdown {
    let groth16_proof_bytes = serialized_size_compressed(&proof.groth16_proof);
    let public_inputs_bytes = serialized_size_compressed(&proof.public_inputs);

    let mut merkle_membership_total_bytes = 0usize;
    let mut merkle_membership_count = 0usize;
    for opening_set in &proof.query_openings {
        merkle_membership_total_bytes += membership_opening_size_bytes(&opening_set.a);
        merkle_membership_total_bytes += membership_opening_size_bytes(&opening_set.b);
        merkle_membership_total_bytes += membership_opening_size_bytes(&opening_set.c);
        merkle_membership_total_bytes += membership_opening_size_bytes(&opening_set.x);
        merkle_membership_total_bytes += membership_opening_size_bytes(&opening_set.y);
        merkle_membership_total_bytes += membership_opening_size_bytes(&opening_set.z);
        merkle_membership_count += 6;
    }

    let public_fr_fields = vec![
        proof.public.root_a,
        proof.public.root_b,
        proof.public.root_c,
        proof.public.root_x,
        proof.public.root_y,
        proof.public.root_z,
        proof.public.cm_abc,
        proof.public.cm_xy,
        proof.public.challenge_r,
        proof.public.lookup_index_challenge,
        proof.public.lookup_logup_challenge,
        proof.public.rs_point_x,
        proof.public.rs_point_y,
    ];

    let indices_u64 = proof
        .public
        .indices
        .iter()
        .map(|&i| i as u64)
        .collect::<Vec<_>>();
    let public_transcript_est_bytes =
        serialized_size_compressed(&public_fr_fields) + serialized_size_compressed(&indices_u64);

    let protocol_total_est_bytes = groth16_proof_bytes
        + merkle_membership_total_bytes
        + public_inputs_bytes
        + public_transcript_est_bytes;

    let avg_merkle_membership_bytes = if merkle_membership_count == 0 {
        0.0
    } else {
        merkle_membership_total_bytes as f64 / merkle_membership_count as f64
    };

    ProofSizeBreakdown {
        groth16_proof_bytes,
        merkle_membership_total_bytes,
        avg_merkle_membership_bytes,
        public_inputs_bytes,
        public_transcript_est_bytes,
        protocol_total_est_bytes,
    }
}

fn bytes_to_kib(bytes: usize) -> f64 {
    bytes as f64 / 1024.0
}

fn secs_to_ms(secs: f64) -> f64 {
    secs * 1000.0
}

fn count_meow_constraints(
    params: &ProtocolParams,
    poseidon_config: ark_crypto_primitives::sponge::poseidon::PoseidonConfig<Fr>,
) -> usize {
    let zeros_k = vec![Fr::zero(); params.k];
    let zeros_n = vec![Fr::zero(); params.n];
    let zeros_l = vec![Fr::zero(); params.l];
    let zero_cols_lk = vec![vec![Fr::zero(); params.k]; params.l];

    let circuit = Meow::<Fr> {
        k: params.k,
        n: params.n,
        roots: Some([Fr::zero(); 5]),
        cm_abc: Some(Fr::zero()),
        cm_xyz: Some(Fr::zero()),
        challenge_r: Some(Fr::zero()),
        indices: Some(zeros_l),
        lookup_index_challenge: Some(Fr::zero()),
        lookup_logup_challenge: Some(Fr::zero()),
        rs_point_x: Some(Fr::zero()),
        rs_point_yz: Some(Fr::zero()),
        poseidon_config: Some(poseidon_config),
        cols_enc_a: Some(zero_cols_lk.clone()),
        cols_enc_b: Some(zero_cols_lk.clone()),
        cols_enc_c: Some(zero_cols_lk),
        vec_x: Some(zeros_k.clone()),
        vec_yz: Some(zeros_k),
        enc_x: Some(zeros_n.clone()),
        enc_yz: Some(zeros_n),
        target_enc_x: Some(vec![Fr::zero(); params.l]),
        target_enc_yz: Some(vec![Fr::zero(); params.l]),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    circuit
        .generate_constraints(cs.clone())
        .expect("meow constraint generation should succeed");
    cs.num_constraints()
}
