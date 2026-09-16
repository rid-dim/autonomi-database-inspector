//! End-to-end checks of the binary against the live-network fixture in
//! `samples/live-store`: three public DataMaps fetched from the Autonomi
//! network with `ant chunk get`, plus the chunks of their shrunk level.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ant-inspect"))
}

fn samples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../samples/live-store")
}

const BEGBLAG: &str = "00ac7cbe1fe3e49fcd9e490eb313fabc2fe4407e67196292e961c3b34e9b1afa";
const UBUNTU_ISO: &str = "9f8ea63f705b75916548e2477c4a90022e9e9a31e01e85d99e987fc81b56130a";

#[test]
fn store_report_finds_the_three_public_datamaps() {
    let out = bin().arg(samples()).args(["--datamaps", "--classify", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["kind"], "node_root");
    assert_eq!(v["layout_is_current"], true);
    assert_eq!(v["chunk_count"], 12);
    let dms = v["datamaps"].as_array().unwrap();
    assert_eq!(dms.len(), 3);
    for d in dms {
        assert_eq!(d["child"], 1);
        assert_eq!(d["chunk_count"], 3);
        assert_eq!(d["local_present"], 3);
    }
    let dist = v["content_distribution"].as_array().unwrap();
    let datamap = dist.iter().find(|b| b["class"] == "data_map").unwrap();
    assert_eq!(datamap["count"], 3);
    let encrypted = dist.iter().find(|b| b["class"] == "high_entropy").unwrap();
    assert_eq!(encrypted["count"], 9);
}

#[test]
fn addresses_of_a_datamap_come_out_in_order() {
    let path = samples().join("chunks/0a").join(UBUNTU_ISO);
    let out = bin().arg(&path).arg("--addresses").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines,
        vec![
            "e7f1a5a60d39268a6e54d45772e7cf90c1ead6fbd278d57f6abef99ded4ad8cc",
            "f72f65c29c9345b036423031c27d041c08d5d8afba62e7fbff319c816ab7e38d",
            "7585ff8e93d54d860c574050f7c76adb4b7f4d0aadff88d86b4182b411fa1e29",
        ]
    );
}

#[test]
fn resolve_decrypts_the_parent_level_from_local_chunks() {
    // BegBlag.mp3: the public DataMap is a child (3 entries); its parent, the
    // root DataMap, has 4 data chunks totalling 15,766,382 bytes.
    let path = samples().join("chunks/fa").join(BEGBLAG);
    let out = bin().arg(&path).args(["--resolve", "--json"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["datamap"]["child"], 1);
    assert_eq!(v["datamap"]["local"]["complete"], true);
    let root = &v["resolved"][0];
    assert!(root["child"].is_null());
    assert_eq!(root["format"], "bincode");
    assert_eq!(root["stats"]["chunk_count"], 4);
    assert_eq!(root["stats"]["content_bytes"], 15_766_382);
    assert_eq!(
        root["chunks"][0]["address"],
        "e4d0508a9f0cf102a21871a931cb08be87375245a699c74f23fea00c3a0861ae"
    );
    // The data chunks themselves are not in the fixture.
    assert_eq!(root["local"]["present"], 0);

    let out = bin().arg(&path).args(["--resolve", "--addresses"]).output().unwrap();
    // Resolution itself succeeded, so the exit code is 0 even though the
    // root's chunks are missing locally.
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).lines().count(), 4);
}

#[test]
fn is_datamap_exit_codes() {
    let dm = samples().join("chunks/fa").join(BEGBLAG);
    assert_eq!(bin().arg(&dm).arg("--is-datamap").status().unwrap().code(), Some(0));
    let enc = samples().join("chunks/3b/70a0b43add6a8584198334d9bf6856c098d0b143e4523f7f644ccc0b1176063b");
    assert_eq!(bin().arg(&enc).arg("--is-datamap").status().unwrap().code(), Some(3));
    assert_eq!(bin().arg(&enc).arg("--addresses").status().unwrap().code(), Some(3));
    assert_eq!(bin().arg("/nonexistent/path").status().unwrap().code(), Some(1));
}

#[test]
fn locate_and_verify() {
    let out = bin().arg(samples()).args(["--locate", BEGBLAG]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).trim().ends_with(&format!("chunks/fa/{BEGBLAG}")));
    let missing = "0".repeat(64);
    assert_eq!(bin().arg(samples()).args(["--locate", &missing]).status().unwrap().code(), Some(3));

    let out = bin().arg(samples()).args(["--verify", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["verification"]["checked"], 12);
    assert_eq!(v["verification"]["failed"], 0);
}
