use std::process::{Command, Stdio};

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

#[test]
fn test_connect_live_host() {
    let output = sslx()
        .args(["connect", "google.com", "--no-color"])
        .output()
        .expect("connect failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("TLS 1."), "should show TLS version");
    assert!(stdout.contains("google.com"), "should show hostname");
    assert!(output.status.success());
}

#[test]
fn test_grade_live_host() {
    let output = sslx()
        .args(["grade", "google.com", "--no-color"])
        .output()
        .expect("grade failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Grade:"), "should show grade");
    assert!(output.status.success());
}

#[test]
fn test_expiry_multiple_hosts() {
    let output = sslx()
        .args(["expiry", "google.com", "github.com", "--no-color"])
        .output()
        .expect("expiry failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("google.com"), "should list google");
    assert!(stdout.contains("github.com"), "should list github");
    assert!(output.status.success());
}

#[test]
fn test_connect_bad_host() {
    let output = sslx()
        .args(["connect", "nonexistent.invalid.host.example"])
        .output()
        .expect("connect should run");
    assert!(!output.status.success(), "should fail for bad host");
}

#[test]
fn test_grade_json() {
    let output = sslx()
        .args(["grade", "google.com", "--json"])
        .output()
        .expect("grade failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid json");
    assert!(json["grade"].is_string(), "should have grade field");
    assert!(json["score"].is_number(), "should have score field");
}

#[test]
fn test_decode_jwt_inline() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let output = sslx()
        .args(["decode", jwt, "--no-color"])
        .output()
        .expect("decode failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("JWT"), "should detect JWT");
    assert!(stdout.contains("John"), "should show payload");
}

#[test]
fn test_match_wrong_key() {
    let dir1 = tempfile::tempdir().unwrap();
    let dir2 = tempfile::tempdir().unwrap();
    // generate two different certs
    sslx()
        .args([
            "generate",
            "--cn",
            "a.test",
            "--out",
            dir1.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    sslx()
        .args([
            "generate",
            "--cn",
            "b.test",
            "--out",
            dir2.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    // try to match cert from one with key from other
    let output = sslx()
        .args([
            "match",
            dir1.path().join("cert.pem").to_str().unwrap(),
            dir2.path().join("key.pem").to_str().unwrap(),
            "--no-color",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success(), "mismatched cert+key should fail");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("DO NOT match"),
        "should say they don't match"
    );
}

#[test]
fn test_convert_pem_to_der_and_back() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();
    sslx()
        .args(["generate", "--cn", "convert.test", "--out", d])
        .output()
        .unwrap();

    let cert_pem = dir.path().join("cert.pem");
    let cert_der = dir.path().join("cert.der");
    let cert_back = dir.path().join("cert_back.pem");

    // PEM -> DER
    sslx()
        .args([
            "convert",
            cert_pem.to_str().unwrap(),
            "--to",
            "der",
            "--out",
            cert_der.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(cert_der.exists());

    // DER -> PEM
    sslx()
        .args([
            "convert",
            cert_der.to_str().unwrap(),
            "--to",
            "pem",
            "--out",
            cert_back.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(cert_back.exists());

    // inspect the round-tripped cert
    let output = sslx()
        .args(["inspect", cert_back.to_str().unwrap(), "--no-color"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("convert.test"));
}

#[test]
fn test_inspect_stdin_pem() {
    // Generate a cert to a temp dir, then pipe its PEM contents via stdin.
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path().to_str().unwrap();

    sslx()
        .args(["generate", "--cn", "stdin.test", "--out", dir_path])
        .output()
        .expect("failed to generate cert");

    let cert_path = dir.path().join("cert.pem");
    let pem_bytes = std::fs::read(&cert_path).expect("failed to read cert.pem");

    let mut child = sslx()
        .args(["inspect", "-", "--no-color"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn sslx");

    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&pem_bytes)
        .expect("failed to write stdin");

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "inspect - should succeed");
    assert!(stdout.contains("stdin.test"), "subject should appear");
    assert!(stdout.contains("days remaining"), "expiry should appear");
}

#[test]
fn test_inspect_stdin_json() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path().to_str().unwrap();

    sslx()
        .args(["generate", "--cn", "stdin-json.test", "--out", dir_path])
        .output()
        .expect("failed to generate cert");

    let pem_bytes = std::fs::read(dir.path().join("cert.pem")).expect("failed to read cert.pem");

    let mut child = sslx()
        .args(["inspect", "-", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn sslx");

    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&pem_bytes)
        .expect("failed to write stdin");

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "inspect - --json should succeed");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert_eq!(json["certificates"][0]["subject"], "CN=stdin-json.test");
}

#[test]
fn test_decode_stdin_pem_cert() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path().to_str().unwrap();

    sslx()
        .args(["generate", "--cn", "decode-stdin.test", "--out", dir_path])
        .output()
        .expect("failed to generate cert");

    let pem_bytes = std::fs::read(dir.path().join("cert.pem")).expect("failed to read cert.pem");

    let mut child = sslx()
        .args(["decode", "-", "--no-color"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn sslx");

    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&pem_bytes)
        .expect("failed to write stdin");

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "decode - should succeed");
    assert!(
        stdout.contains("PEM Certificate"),
        "should detect PEM Certificate"
    );
    assert!(
        stdout.contains("decode-stdin.test"),
        "subject should appear"
    );
}
