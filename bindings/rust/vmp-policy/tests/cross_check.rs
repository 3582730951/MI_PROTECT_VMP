use vmp_policy::PolicyIR;

#[test]
fn rust_reads_shared_fixture() {
    let policy = PolicyIR::load_from_file("tests/policy/examples/good.json").unwrap();
    let first = &policy.entries[0];
    assert_eq!(first.symbol_or_region, "secure::verify_score");
    assert_eq!(format!("{:?}", first.language_origin), "Cpp");
    assert_eq!(format!("{:?}", first.protection_domain), "Vm1");
    assert_eq!(format!("{:?}", first.sensitivity_level), "HighlySensitive");
    assert!(first.annotation_tags.iter().any(|tag| tag == "vm_func"));
    assert!(first.annotation_tags.iter().any(|tag| tag == "vm_string"));
}
