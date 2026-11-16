#![cfg(feature = "test-keystore")]

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn studge() -> Command {
    Command::cargo_bin("studge").unwrap()
}

fn home() -> TempDir {
    TempDir::new().unwrap()
}

fn init_and_unlock(dir: &TempDir) -> String {
    let out = studge()
        .env("STUDGE_HOME", dir.path())
        .args(["init", "--password-stdin"])
        .write_stdin("pw123\n")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    let sk = stdout
        .lines()
        .find(|l| l.contains("Secret Key"))
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .to_string();

    studge()
        .env("STUDGE_HOME", dir.path())
        .args(["unlock", "--password-stdin"])
        .write_stdin(format!("pw123\n{}\n", sk))
        .assert()
        .success();
    sk
}

#[test]
fn init_unlock_list_get_print_lock_round_trip() {
    let dir = home();
    let _sk = init_and_unlock(&dir);

    studge()
        .env("STUDGE_HOME", dir.path())
        .args([
            "add",
            "login",
            "--title",
            "MyLogin",
            "--username",
            "user1",
            "--password-stdin",
            "--url",
            "https://example.com",
        ])
        .write_stdin("secret123\n")
        .assert()
        .success();

    studge()
        .env("STUDGE_HOME", dir.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicates::str::contains("MyLogin"));

    studge()
        .env("STUDGE_HOME", dir.path())
        .args(["get", "MyLogin", "--print"])
        .assert()
        .success()
        .stdout(predicates::str::contains("secret123"));

    studge()
        .env("STUDGE_HOME", dir.path())
        .arg("lock")
        .assert()
        .success();

    // unlock with only password line; secret key still stored
    studge()
        .env("STUDGE_HOME", dir.path())
        .args(["unlock", "--password-stdin"])
        .write_stdin("pw123\n")
        .assert()
        .success();

    studge()
        .env("STUDGE_HOME", dir.path())
        .arg("list")
        .assert()
        .success();
}

#[test]
fn master_password_never_stored_integration() {
    let dir = home();
    let pw = "Pw-Canary-7731";
    let out = studge()
        .env("STUDGE_HOME", dir.path())
        .args(["init", "--password-stdin"])
        .write_stdin(format!("{}\n", pw))
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    let sk = stdout
        .lines()
        .find(|l| l.contains("Secret Key"))
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .to_string();

    studge()
        .env("STUDGE_HOME", dir.path())
        .args(["unlock", "--password-stdin"])
        .write_stdin(format!("{}\n{}\n", pw, sk))
        .assert()
        .success();

    studge()
        .env("STUDGE_HOME", dir.path())
        .args(["add", "login", "--title", "Item1", "--password-stdin"])
        .write_stdin("itempw\n")
        .assert()
        .success();

    fn walk(dir: &std::path::Path, acc: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, acc);
                } else {
                    acc.push(p);
                }
            }
        }
    }
    let mut files = Vec::new();
    walk(dir.path(), &mut files);
    for f in files {
        if let Ok(bytes) = fs::read(&f) {
            assert!(
                !bytes.windows(pw.len()).any(|w| w == pw.as_bytes()),
                "password found in {}",
                f.display()
            );
        }
    }
}

#[test]
fn wrong_password_refused() {
    let dir = home();
    let out = studge()
        .env("STUDGE_HOME", dir.path())
        .args(["init", "--password-stdin"])
        .write_stdin("pw123\n")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    let sk = stdout
        .lines()
        .find(|l| l.contains("Secret Key"))
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .to_string();

    studge()
        .env("STUDGE_HOME", dir.path())
        .args(["unlock", "--password-stdin"])
        .write_stdin(format!("wrong\n{}\n", sk))
        .assert()
        .failure();

    assert!(!dir.path().join("session.bin").exists());
}

#[test]
fn malformed_input_no_panic() {
    let dir = home();
    init_and_unlock(&dir);
    studge()
        .env("STUDGE_HOME", dir.path())
        .args(["add", "login", "--title", "MyLogin", "--password-stdin"])
        .write_stdin("secret123\n")
        .assert()
        .success();
    // missing item
    let out = studge()
        .env("STUDGE_HOME", dir.path())
        .args(["get", "nonexistent"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"));
    // invalid field name
    let out = studge()
        .env("STUDGE_HOME", dir.path())
        .args(["get", "MyLogin", "--field", "nope"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"));
}

#[test]
fn get_without_print_does_not_leak_secret() {
    let dir = home();
    init_and_unlock(&dir);
    studge()
        .env("STUDGE_HOME", dir.path())
        .args(["add", "login", "--title", "MyLogin", "--password-stdin"])
        .write_stdin("secret123\n")
        .assert()
        .success();
    let out = studge()
        .env("STUDGE_HOME", dir.path())
        .args(["get", "MyLogin"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stdout.contains("secret123"));
    assert!(!stderr.contains("secret123"));
    // either succeeded or stderr mentions clipboard
    if !out.status.success() {
        assert!(stderr.contains("clipboard") || stderr.contains("Clipboard"));
    }
}

#[test]
fn corrupt_config_gives_error() {
    let dir = home();
    fs::write(dir.path().join("config.json"), "{bad json").unwrap();
    studge()
        .env("STUDGE_HOME", dir.path())
        .arg("status")
        .assert()
        .failure();
}

#[test]
fn empty_password_is_error() {
    let dir = home();
    studge()
        .env("STUDGE_HOME", dir.path())
        .args(["init", "--password-stdin"])
        .write_stdin("\n")
        .assert()
        .failure()
        .stderr(predicates::str::contains("empty password"));
}

#[test]
fn empty_password_unlock_is_error() {
    let dir = home();
    init_and_unlock(&dir);
    studge()
        .env("STUDGE_HOME", dir.path())
        .args(["lock"])
        .assert()
        .success();
    studge()
        .env("STUDGE_HOME", dir.path())
        .args(["unlock", "--password-stdin"])
        .write_stdin("\n")
        .assert()
        .failure()
        .stderr(predicates::str::contains("empty password"));
}
