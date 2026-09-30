# Third-Party Open Source Licenses & Attributions

**SecuredStorage** is free and open-source software licensed under the [GNU General Public License v3.0 (GPL-3.0-or-later)](LICENSE).

This document catalogs third-party open-source libraries, crates, and graphical assets incorporated into, bundled with, or dynamically linked by SecuredStorage, in compliance with their respective licensing conditions (including Apache-2.0 Section 4, MIT, BSD-3-Clause, and ISC attribution requirements).

---

## 1. User Interface & Iconography

### Lucide / Feather Icons
- **Project**: [Lucide Icons](https://lucide.dev) / [Feather](https://feathericons.com)
- **License**: [ISC License](https://opensource.org/licenses/ISC) / [MIT License](https://opensource.org/licenses/MIT)
- **Copyright**: (c) 2022-2026 Lucide Contributors, (c) 2013-2022 Cole Bemis
- **Usage**: Clean minimalist line SVGs rendered inline for View (`eye`), Edit (`pencil`), Delete (`trash`), and Lock Vault (`padlock`) micro-actions.

```text
Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

---

## 2. Desktop Application Framework

### Tauri Framework (`tauri`, `tauri-build`, `@tauri-apps/api`, `@tauri-apps/cli`)
- **Project**: [Tauri Apps](https://tauri.app)
- **License**: Dual-licensed under [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) OR [MIT](https://opensource.org/licenses/MIT)
- **Copyright**: (c) 2019-2026 Tauri Programme within The Commons Conservancy
- **Usage**: Secure IPC bridge, sandboxed OS webview rendering, window management, and native cross-platform application runtime.

---

## 3. Cryptography & Security Dependencies

All cryptographic crates used in SecuredStorage are developed under the audited [RustCrypto](https://github.com/RustCrypto) project and affiliated community repositories:

| Crate | Version | License | Copyright / Maintainer | Description |
| :--- | :--- | :--- | :--- | :--- |
| **`aes-gcm`** | `0.10.3` | Apache-2.0 OR MIT | (c) RustCrypto Developers | Authenticated Encryption with Associated Data (AEAD) |
| **`argon2`** | `0.5.3` | Apache-2.0 OR MIT | (c) RustCrypto Developers | Password Hashing & Memory-Hard Key Derivation (RFC 9106) |
| **`zeroize`** | `1.8` | Apache-2.0 OR MIT | (c) RustCrypto Developers | Compiler-enforced hardware memory scrubbing (`ZeroizeOnDrop`) |
| **`subtle`** | `2.6` | BSD-3-Clause | (c) 2016-2024 subtle contributors | Constant-time cryptographic comparison routines |
| **`rand`** | `0.8.5` | Apache-2.0 OR MIT | (c) The Rand Project Developers | Cryptographically secure pseudo-random number generator (CSPRNG) |

---

## 4. General Utilities & System Bindings

| Crate | Version | License | Copyright / Maintainer | Description |
| :--- | :--- | :--- | :--- | :--- |
| **`serde`** | `1.0` | Apache-2.0 OR MIT | (c) 2014-2026 Serde Developers | High-performance serialization framework |
| **`serde_json`** | `1.0` | Apache-2.0 OR MIT | (c) 2014-2026 Serde Developers | Strongly typed JSON data parsing |
| **`uuid`** | `1.10` | Apache-2.0 OR MIT | (c) 2013-2026 UUID Project Developers | Cryptographic UUIDv4 generation for credential records |
| **`dirs`** | `5.0` | Apache-2.0 OR MIT | (c) 2018-2026 Simon Ochsenreither | Canonical cross-platform OS application directories |
| **`libc`** | `0.2` | Apache-2.0 OR MIT | (c) 2014-2026 The Rust Project Developers | Raw POSIX bindings (`mlock`, `ptrace`, `setrlimit`) |
| **`windows-sys`** | `0.59` | Apache-2.0 OR MIT | (c) Microsoft Corporation | Win32 native security & display affinity bindings |
| **`cc`** | `1.0` | Apache-2.0 OR MIT | (c) 2014-2026 Alex Crichton | Native C/Objective-C compiler interface for macOS Touch ID |

---

## 5. Standard License Texts

### Apache License, Version 2.0
Licensed under the Apache License, Version 2.0 (the "License"); you may not use these files except in compliance with the License. You may obtain a copy of the License at:
`http://www.apache.org/licenses/LICENSE-2.0`

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

### The MIT License
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### BSD 3-Clause License
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
