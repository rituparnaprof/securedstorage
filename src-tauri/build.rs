// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * SecuredStorage - PQC-Compliant Offline Password Vault
 * Copyright (C) 2026 rituparnaprof
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

fn main() {
    #[cfg(target_os = "macos")]
    {
        cc::Build::new()
            .file("src/touchid_macos.m")
            .flag("-Wno-unused-parameter")
            .compile("touchid_macos");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
    }

    tauri_build::build();
}
