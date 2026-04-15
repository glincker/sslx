use std::process::Command;

fn sslx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sslx"))
}

#[test]
fn test_help_output() {
    let output = sslx().arg("--help").output().expect("failed to run sslx");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("The modern way to work with certificates and TLS"));
    assert!(stdout.contains("inspect"));
    assert!(stdout.contains("connect"));
    assert!(stdout.contains("verify"));
    assert!(stdout.contains("generate"));
}

#[test]
fn test_version() {
    let output = sslx()
        .arg("--version")
        .output()
        .expect("failed to run sslx");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("sslx "));
}

#[test]
fn test_generate_and_inspect() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path().to_str().unwrap();

    // Generate a cert
    let output = sslx()
        .args(["generate", "--cn", "test.sslx.dev", "--out", dir_path])
        .output()
        .expect("failed to generate cert");
    assert!(output.status.success(), "generate failed: {:?}", output);

    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    assert!(cert_path.exists(), "cert.pem not created");
    assert!(key_path.exists(), "key.pem not created");

    // Inspect the generated cert
    let output = sslx()
        .args(["inspect", cert_path.to_str().unwrap(), "--no-color"])
        .output()
        .expect("failed to inspect cert");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("test.sslx.dev"), "subject not found");
    assert!(stdout.contains("ECDSA P-256"), "key type not found");
    assert!(stdout.contains("days remaining"), "expiry not found");
    assert!(output.status.code() == Some(0), "exit code should be 0");
}

#[test]
fn test_generate_json() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path().to_str().unwrap();

    let output = sslx()
        .args(["generate", "--cn", "json.test", "--out", dir_path, "--json"])
        .output()
        .expect("failed to generate cert");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON output");
    assert_eq!(json["subject"], "CN=json.test");
    assert_eq!(json["key_type"], "ec256");
}

#[test]
fn test_inspect_json() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path().to_str().unwrap();

    // Generate first
    sslx()
        .args(["generate", "--cn", "jsoninspect.test", "--out", dir_path])
        .output()
        .expect("failed to generate");

    let cert_path = dir.path().join("cert.pem");

    // Inspect with JSON
    let output = sslx()
        .args(["inspect", cert_path.to_str().unwrap(), "--json"])
        .output()
        .expect("failed to inspect");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON");
    assert_eq!(json["certificates"][0]["subject"], "CN=jsoninspect.test");
    assert!(!json["certificates"][0]["is_expired"].as_bool().unwrap());
    assert!(json["certificates"][0]["days_remaining"].as_i64().unwrap() > 300);
}

#[test]
fn test_inspect_nonexistent_file() {
    let output = sslx()
        .args(["inspect", "/nonexistent/cert.pem"])
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to read") || stderr.contains("error"),
        "should show error for missing file"
    );
}

#[test]
fn test_generate_ed25519() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path().to_str().unwrap();

    let output = sslx()
        .args([
            "generate",
            "--cn",
            "ed.test",
            "--key-type",
            "ed25519",
            "--out",
            dir_path,
            "--no-color",
        ])
        .output()
        .expect("failed to generate Ed25519 cert");
    assert!(output.status.success());

    let cert_path = dir.path().join("cert.pem");
    let output = sslx()
        .args(["inspect", cert_path.to_str().unwrap(), "--no-color"])
        .output()
        .expect("failed to inspect");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Ed25519"), "should show Ed25519 key type");
}

#[test]
fn test_generate_invalid_key_type() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path().to_str().unwrap();

    let output = sslx()
        .args([
            "generate",
            "--cn",
            "bad.test",
            "--key-type",
            "invalid",
            "--out",
            dir_path,
        ])
        .output()
        .expect("failed to run");
    assert!(
        !output.status.success(),
        "should fail with invalid key type"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unsupported key type"),
        "should show helpful error"
    );
}

#[test]
fn test_generate_with_sans() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path().to_str().unwrap();

    let output = sslx()
        .args([
            "generate",
            "--cn",
            "multi.test",
            "--san",
            "api.multi.test,192.168.1.1",
            "--out",
            dir_path,
            "--no-color",
        ])
        .output()
        .expect("failed to generate");
    assert!(output.status.success());

    let cert_path = dir.path().join("cert.pem");
    let output = sslx()
        .args(["inspect", cert_path.to_str().unwrap(), "--no-color"])
        .output()
        .expect("failed to inspect");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("multi.test"), "CN SAN missing");
    assert!(stdout.contains("api.multi.test"), "extra SAN missing");
    assert!(stdout.contains("192.168.1.1"), "IP SAN missing");
}

#[test]
fn test_verify_self_signed() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path().to_str().unwrap();

    sslx()
        .args(["generate", "--cn", "verify.test", "--out", dir_path])
        .output()
        .expect("failed to generate");

    let cert_path = dir.path().join("cert.pem");

    // Self-signed cert verified against itself should pass
    let output = sslx()
        .args([
            "verify",
            cert_path.to_str().unwrap(),
            "--ca",
            cert_path.to_str().unwrap(),
            "--no-color",
        ])
        .output()
        .expect("failed to verify");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("valid"),
        "self-signed cert should verify against itself"
    );
}
