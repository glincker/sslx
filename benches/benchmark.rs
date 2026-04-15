//! Benchmarks comparing sslx operations
//! Run with: cargo bench

use std::process::Command;
use std::time::Instant;

fn main() {
    println!("\n  sslx Benchmark Suite\n");
    println!("  {:<40} {:>10} {:>10}", "Operation", "sslx", "openssl");
    println!("  {}", "─".repeat(62));

    // Generate a test cert first
    let dir = tempfile::tempdir().expect("tempdir");
    let dir_path = dir.path().to_str().unwrap();
    let sslx = env!("CARGO_BIN_EXE_sslx");

    Command::new(sslx)
        .args(["generate", "--cn", "bench.test", "--out", dir_path])
        .output()
        .expect("generate failed");

    let cert_path = dir.path().join("cert.pem").to_str().unwrap().to_string();
    let key_path = dir.path().join("key.pem").to_str().unwrap().to_string();

    // Benchmark: inspect cert file
    bench_compare(
        "Inspect PEM certificate",
        &[sslx, "inspect", &cert_path, "--no-color"],
        &["openssl", "x509", "-in", &cert_path, "-text", "-noout"],
    );

    // Benchmark: generate self-signed cert
    let gen_dir = tempfile::tempdir().expect("tempdir");
    let gen_path = gen_dir.path().to_str().unwrap();
    bench_compare(
        "Generate self-signed cert (EC)",
        &[sslx, "generate", "--cn", "bench.gen", "--out", gen_path],
        &[
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-keyout",
            &format!("{}/ossl-key.pem", gen_path),
            "-out",
            &format!("{}/ossl-cert.pem", gen_path),
            "-days",
            "365",
            "-nodes",
            "-batch",
            "-subj",
            "/CN=bench.gen",
        ],
    );

    // Benchmark: decode JWT
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    bench_single("Decode JWT token", &[sslx, "decode", jwt, "--no-color"]);

    // Benchmark: match cert and key
    bench_single(
        "Match cert + key",
        &[sslx, "match", &cert_path, &key_path, "--no-color"],
    );

    // Benchmark: convert PEM to DER
    let conv_out = format!("{}/bench.der", dir_path);
    bench_single(
        "Convert PEM → DER",
        &[
            sslx, "convert", &cert_path, "--to", "der", "--out", &conv_out,
        ],
    );

    // Binary size
    let sslx_size = std::fs::metadata(sslx).map(|m| m.len()).unwrap_or(0);
    let openssl_path = which_openssl();
    let openssl_size = openssl_path
        .as_ref()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .unwrap_or(0);

    println!();
    println!(
        "  {:<40} {:>10} {:>10}",
        "Binary size",
        format_size(sslx_size),
        if openssl_size > 0 {
            format_size(openssl_size)
        } else {
            "N/A".to_string()
        },
    );

    // Startup time
    let startup = bench_runs(&[sslx, "--version"], 20);
    println!(
        "  {:<40} {:>10}",
        "Startup time (--version, 20 runs)",
        format!("{:.1}ms", startup)
    );

    println!();
}

fn bench_compare(label: &str, sslx_cmd: &[&str], openssl_cmd: &[&str]) {
    let sslx_time = bench_runs(sslx_cmd, 10);
    let openssl_time = bench_runs(openssl_cmd, 10);

    let speedup = if sslx_time > 0.0 && openssl_time > 0.0 {
        format!(" ({:.1}x)", openssl_time / sslx_time)
    } else {
        String::new()
    };

    println!(
        "  {:<40} {:>8.1}ms {:>8.1}ms{}",
        label, sslx_time, openssl_time, speedup
    );
}

fn bench_single(label: &str, cmd: &[&str]) {
    let time = bench_runs(cmd, 10);
    println!("  {:<40} {:>8.1}ms {:>10}", label, time, "—");
}

fn bench_runs(cmd: &[&str], runs: usize) -> f64 {
    // Warmup
    let _ = Command::new(cmd[0]).args(&cmd[1..]).output();

    let mut times = Vec::new();
    for _ in 0..runs {
        let start = Instant::now();
        let _ = Command::new(cmd[0])
            .args(&cmd[1..])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output();
        times.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    // Median
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    times[times.len() / 2]
}

fn which_openssl() -> Option<String> {
    Command::new("which")
        .arg("openssl")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1_000_000 {
        format!("{:.1}MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.0}KB", bytes as f64 / 1_000.0)
    } else {
        format!("{}B", bytes)
    }
}
