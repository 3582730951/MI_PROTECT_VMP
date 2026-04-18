use serde_json::json;
use std::env;
use vmp_policy::PolicyIR;

fn main() {
    let path = env::args().nth(1).expect("path argument");
    let policy = PolicyIR::load_from_file(path).expect("load policy");
    let first = policy.entries.first().expect("at least one entry");
    let summary = json!({
        "schema_version": policy.schema_version,
        "entry_count": policy.entries.len(),
        "first": {
            "symbol_or_region": first.symbol_or_region,
            "language_origin": format!("{:?}", first.language_origin).to_lowercase(),
            "protection_domain": format!("{:?}", first.protection_domain).to_lowercase(),
            "sensitivity_level": match format!("{:?}", first.sensitivity_level).as_str() {
                "HighlySensitive" => "highly_sensitive".to_string(),
                "Sensitive" => "sensitive".to_string(),
                _ => "normal".to_string(),
            },
            "annotation_tags": first.annotation_tags,
        }
    });
    println!("{}", summary);
}
