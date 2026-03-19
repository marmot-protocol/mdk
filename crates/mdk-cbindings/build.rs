use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let crate_path = PathBuf::from(&crate_dir);
    let out_dir = crate_path.join("include");

    let config = cbindgen::Config::from_file(crate_path.join("cbindgen.toml"))
        .expect("Unable to read cbindgen.toml");

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate C bindings header")
        .write_to_file(out_dir.join("mdk.h"));
}
