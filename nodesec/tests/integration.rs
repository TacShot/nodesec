//! Integration tests for nodesec CLI

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_nodesec_audit_run() {
    let mut cmd = Command::cargo_bin("nodesec").unwrap();
    cmd.args(["audit", "run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Summary:"));
}

#[test]
fn test_nodesec_net_live_help() {
    let mut cmd = Command::cargo_bin("nodesec").unwrap();
    cmd.args(["net", "live", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("On-device real-time network monitoring"));
}

#[test]
fn test_nodesec_audit_help() {
    let mut cmd = Command::cargo_bin("nodesec").unwrap();
    cmd.args(["audit", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Security audit mode"));
}

#[test]
fn test_nodesec_help() {
    let mut cmd = Command::cargo_bin("nodesec").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Cross-platform System & Network Security Platform"));
}

#[test]
fn test_nodesec_version() {
    let mut cmd = Command::cargo_bin("nodesec").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("nodesec"));
}