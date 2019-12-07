// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = env::var("OUT_DIR").map(PathBuf::from).unwrap();

    let oqs_dir = env::var("OQS_DIR")
        .map(PathBuf::from)
        .expect("Set the environment variable OQS_DIR to the absolute path to your liboqs dir");
    let oqs_include_dir = oqs_dir.join("include");

    println!("cargo:rustc-link-lib=oqs");

    if option_env!("OQS_WITH_SODIUM") == Some("1") {
        println!("cargo:rustc-link-lib=sodium");
    }

    if option_env!("OQS_WITH_GMP") == Some("1")  {
        println!("cargo:rustc-link-lib=gmp");
    }

    println!(
        "cargo:rustc-link-search=native={}",
        oqs_dir.to_string_lossy()
    );

//    let _ = bindgen::builder()
//        .header(format!("{}/oqs/common.h", oqs_include_dir.to_string_lossy()))
//        .clang_arg(format!("-I{}", oqs_include_dir.to_string_lossy()))
//        .use_core()
//        .ctypes_prefix("::libc")
//        .whitelist_recursively(true)
//        .whitelist_type(".*")
//        .rustified_enum(".*")
//        .whitelist_function(".*")
//        .whitelist_var(".*")
////        .raw_line("use ::rand::OQS_RAND;")
//        .generate()
//        .unwrap()
//        .write_to_file(out_dir.join("common.rs"))
//        .unwrap();

    let _ = bindgen::Builder::default()
        .header(format!("{}/oqs/common.h", oqs_include_dir.to_string_lossy()))
        .clang_arg(format!("-I{}", oqs_include_dir.to_string_lossy()))
        .use_core()
        .ctypes_prefix("::libc")
        .whitelist_type("OQS_.*")
        .whitelist_function("OQS_.*")
        .whitelist_recursively(false)
        .default_enum_style(bindgen::EnumVariation::Rust { non_exhaustive: false })
        .generate()
        .unwrap()
        .write_to_file(out_dir.join("common.rs"))
        .unwrap();

    let _ = bindgen::builder()
        .header(format!("{}/oqs/rand.h", oqs_include_dir.to_string_lossy()))
        .clang_arg(format!("-I{}", oqs_include_dir.to_string_lossy()))
//        .link_static("oqs")
        .use_core()
        .ctypes_prefix("::libc")
        .whitelist_type("OQS_RAND.*")
        .whitelist_var("OQS_RAND.*")
        .whitelist_function("OQS_rand.*")
        .whitelist_recursively(false)
        .raw_line("use ::common::OQS_STATUS;")
        .generate()
        .unwrap()
        .write_to_file(out_dir.join("rand.rs"))
        .unwrap();

    let _ = bindgen::builder()
        .header(format!("{}/oqs/kem.h", oqs_include_dir.to_string_lossy()))
        .clang_arg(format!("-I{}", oqs_include_dir.to_string_lossy()))
//        .link_static("oqs")
        .use_core()
        .ctypes_prefix("::libc")
        .whitelist_recursively(false)
        .whitelist_type("OQS_KEM.*")
        .whitelist_function("OQS_KEM_.*")
        .whitelist_var("OQS_KEM.*")
        .raw_line("use ::common::OQS_STATUS;")
//        .raw_line("use ::rand::OQS_RAND;")
        .generate()
        .unwrap()
        .write_to_file(out_dir.join("kem.rs"))
        .unwrap();

//    let _ = bindgen::builder()
//        .header(format!(
//            "{}/oqs/common.h",
//            oqs_include_dir.to_string_lossy()
//        ))
//        .clang_arg(format!("-I{}", oqs_include_dir.to_string_lossy()))
////        .link_static("oqs")
//        .use_core()
//        .ctypes_prefix("::libc")
//        .whitelist_recursively(true)
//        .whitelist_var("OQS_.*")
//        .whitelist_function("OQS_.*")
//        .rustified_enum("OQS_.*")
//        .generate()
//        .unwrap()
//        .write_to_file(out_dir.join("common.rs"))
//        .unwrap();
}
