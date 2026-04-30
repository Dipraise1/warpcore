use std::fs;
use std::path::Path;

use warpcore::analyzer::analyze_path;

fn assert_snapshot(path: &str, snapshot: &str) {
    let report = analyze_path(Path::new(path)).expect("analyze path");
    let actual = serde_json::to_string_pretty(&report).expect("serialize report");
    let expected = fs::read_to_string(snapshot).expect("read snapshot");

    assert_eq!(actual.trim_end(), expected.trim_end());
}

#[test]
fn idl_single_snapshot() {
    assert_snapshot(
        "tests/fixtures/idl_single.json",
        "tests/fixtures/idl_single.snapshot.json",
    );
}

#[test]
fn idl_directory_snapshot() {
    assert_snapshot(
        "tests/fixtures/idl_directory",
        "tests/fixtures/idl_directory.snapshot.json",
    );
}
