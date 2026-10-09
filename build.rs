use std::{env, path::PathBuf};

fn main() {
    let lib = pkg_config::Config::new()
        .probe("modsecuirty")
        .expect("ModSecurity not found");

    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    for path in lib.include_paths {
        builder = builder.clang_arg(format!("-I{}", path.display()));
    }

    let bindings = builder.generate().expect("Failed to generate bindings");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindings.write_to_file(out.join("bindings.rs")).unwrap();
}
