use std::env;
use std::path::PathBuf;

fn bind_openssl(bindings: bindgen::Builder) -> bindgen::Builder {
    bindings
        .header_contents(
            "openssl_wrapper.hpp",
            r#"
            #include <openssl/evp.h>
            #include <openssl/bio.h>
            #include <openssl/pem.h>
            #include <openssl/err.h>
        "#,
        )
        .allowlist_function("EVP_PKEY_free")
        .allowlist_function("EVP_PKEY_CTX_new_from_pkey")
        .allowlist_function("EVP_PKEY_CTX_free")
        .allowlist_function("EVP_SIGNATURE_fetch")
        .allowlist_function("EVP_SIGNATURE_free")
        .allowlist_function("EVP_PKEY_verify_message_init")
        .allowlist_function("EVP_PKEY_verify")
        .allowlist_function("BIO_new_mem_buf")
        .allowlist_function("BIO_free")
        .allowlist_function("PEM_read_bio_PUBKEY")
        .allowlist_function("ERR_get_error")
        .allowlist_function("ERR_error_string")
        .clang_arg("-I/usr/local/include")
}

fn build_openssl() {
    println!("cargo:rerun-if-changed=victim/openssl/");
    // build openssl
    std::process::Command::new("make")
        .current_dir("victim/openssl/")
        .status()
        .expect("Failed to build openssl library");
}

fn build_victim() {
    // build victim
    std::process::Command::new("make")
        .current_dir("victim")
        .status()
        .expect("Failed to build victim");
}

fn run_bindgen(bindings: bindgen::Builder) -> bindgen::Bindings {
    bindings
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings")
}

fn write_bindings(bindings: bindgen::Bindings) {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    let mut bindings = bindgen::Builder::default();

    println!("cargo:rustc-link-search=/usr/local/lib64/");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");

    println!("cargo:rustc-env=OPENSSL_LIB_DIR=/usr/local/lib64/");
    println!("cargo:rustc-env=OPENSSL_INCLUDE_DIR=/usr/local/include/openssl/");

    bindings = bind_openssl(bindings);
    let bindings = run_bindgen(bindings);

    build_openssl();
    build_victim();

    write_bindings(bindings);
}
