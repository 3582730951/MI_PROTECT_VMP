fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    println!("cargo:rustc-env=OUT_DIR={out_dir}");
}
