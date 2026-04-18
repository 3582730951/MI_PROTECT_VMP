use vmp_policy::PolicyIR;

#[test]
fn rust_reads_shared_fixture() {
    let fixture = format!("{}/../../../tests/policy/examples/good.json", env!("CARGO_MANIFEST_DIR"));
    let policy = PolicyIR::load_from_file(&fixture).unwrap();
    let first = &policy.entries[0];
    assert_eq!(first.symbol_or_region, "secure::verify_score");
    assert_eq!(format!("{:?}", first.language_origin), "Cpp");
    assert_eq!(format!("{:?}", first.protection_domain), "Vm1");
    assert_eq!(format!("{:?}", first.sensitivity_level), "HighlySensitive");
    assert!(first.annotation_tags.iter().any(|tag| tag == "vm_func"));
    assert!(first.annotation_tags.iter().any(|tag| tag == "vm_string"));
}


#[test]
fn cpp_and_rust_summaries_match() {
    let fixture = format!("{}/../../../tests/policy/examples/good.json", env!("CARGO_MANIFEST_DIR"));
    let rust_policy = PolicyIR::load_from_file(&fixture).unwrap();
    let first = &rust_policy.entries[0];
    let rust_summary = serde_json::json!({
        "schema_version": rust_policy.schema_version,
        "entry_count": rust_policy.entries.len(),
        "first": {
            "symbol_or_region": first.symbol_or_region,
            "language_origin": format!("{:?}", first.language_origin).to_lowercase(),
            "protection_domain": format!("{:?}", first.protection_domain).to_lowercase(),
            "sensitivity_level": "highly_sensitive",
            "annotation_tags": first.annotation_tags,
        }
    });
    let cpp_output = std::process::Command::new("/workspace/vmp/build-linux-x64/tests/policy_cpp_summary")
        .arg(&fixture)
        .output()
        .expect("run c++ summary helper");
    assert!(cpp_output.status.success(), "{}", String::from_utf8_lossy(&cpp_output.stderr));
    let cpp_summary: serde_json::Value = serde_json::from_slice(&cpp_output.stdout).unwrap();
    assert_eq!(cpp_summary, rust_summary);
}
