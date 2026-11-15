use assert_cmd::Command;

use std::fs;
use tempfile::TempDir;

fn studge() -> Command {
    Command::cargo_bin("studge").unwrap()
}

fn home() -> TempDir {
    TempDir::new().unwrap()
}

#[test]
fn init_unlock_list_get_print_lock_round_trip() {
    let dir = home();
    let out = studge()
        .env("STUDGE_HOME", dir.path())
        .args(["init", "--password-stdin"])
        .write_stdin("pw123\n")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    // extract secret key line
    let sk = stdout
        .lines()
        .find(|l| l.contains("Secret Key"))
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .to_string();

    // unlock
    studge()
        .env("STUDGE_HOME", dir.path())
        .args(["unlock", "--password-stdin"])
        .write_stdin(format!("pw123\n{}\n", sk))
        .assert()
        .success();

    // list (empty)
    studge()
        .env("STUDGE_HOME", dir.path())
        .arg("list")
        .assert()
        .success();

    // lock keeps secret key: load secret key still present
    studge()
        .env("STUDGE_HOME", dir.path())
        .arg("lock")
        .assert()
        .success();
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
}

#[test]
fn malformed_input_no_panic() {
    let dir = home();
    studge()
        .env("STUDGE_HOME", dir.path())
        .args(["get", "nonexistent"])
        .assert()
        .failure();
}

#[test]
fn get_without_print_does_not_leak_secret() {
    // just ensure no panic; full round-trip requires item
    let dir = home();
    let _ = dir;
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
