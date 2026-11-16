use assert_cmd::Command;
use predicates::prelude::*;
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
    let sk = init_and_unlock(&dir);

    // add a login item
    studge()
        .env("STUDGE_HOME", dir.path())
        .args([
            "add",
            "login",
            "--title",
            "MyLogin",
            "--username",
            "user1",
            "--password",
            "secret123",
            "--url",
            "https://example.com",
        ])
        .assert()
        .success();

    // list shows it
    studge()
        .env("STUDGE_HOME", dir.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicates::str::contains("MyLogin"));

    // get --print shows password
    studge()
        .env("STUDGE_HOME", dir.path())
        .args(["get", "MyLogin", "--print"])
        .assert()
        .success()
        .stdout(predicates::str::contains("secret123"));

    // lock keeps secret key
    studge()
        .env("STUDGE_HOME", dir.path())
        .arg("lock")
        .assert()
        .success();

    // verify secret key still stored by re-unlocking with sk
    studge()
        .env("STUDGE_HOME", dir.path())
        .args(["unlock", "--password-stdin"])
        .write_stdin(format!("pw123\n{}\n", sk))
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

    // no session file
    assert!(!dir.path().join("session.bin").exists());
}

#[test]
fn malformed_input_no_panic() {
    let dir = home();
    init_and_unlock(&dir);
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
        .args(["get", "x", "--field", "nope"])
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
        .args([
            "add",
            "login",
            "--title",
            "MyLogin",
            "--password",
            "secret123",
        ])
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
        .stderr(predicate::str::contains("empty password"));
}
