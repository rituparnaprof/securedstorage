// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 rituparnaprof
// SecuredStorage - Native Build Script

fn main() {
    #[cfg(target_os = "macos")]
    {
        cc::Build::new()
            .file("src/touchid_macos.m")
            .flag("-Wno-unused-parameter")
            .compile("touchid_macos");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
        println!("cargo:rustc-link-lib=framework=AppKit");
    }

    tauri_build::build();
}
