use std::env;
use vmp_policy::PolicyIR;

fn main() {
    let path = env::args().nth(1).expect("path argument");
    let policy = PolicyIR::load_from_file(path).expect("load policy");
    let first = policy.entries.first().expect("at least one entry");
    println!(
        "{{\"schema_version\":{},\"entry_count\":{},\"first\":{{\"symbol_or_region\":{:?},\"language_origin\":{:?},\"protection_domain\":{:?},\"sensitivity_level\":{:?},\"annotation_tags\":{:?}}}}}",
        policy.schema_version,
        policy.entries.len(),
        first.symbol_or_region,
        first.language_origin,
        first.protection_domain,
        first.sensitivity_level,
        first.annotation_tags
    );
}
