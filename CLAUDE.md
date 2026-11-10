# CLAUDE.md

Guidance for Claude Code when working in this repository. The README covers what the crate does and how to use it.

## Layout

- `cpp/shim.h` and `cpp/shim.cpp`: a C API over OpenVPN 3 Core. `shim.cpp` includes Core's `client/ovpncli.cpp` directly, the way Core's own test client does, so the defines at its top apply to all of Core.
- `cpp/compat/tap-windows.h`: our own copy of the one header Core wants on Windows, so the GPL tap-windows6 package isn't needed.
- `src/ffi.rs`: the Rust side of `shim.h`. `src/lib.rs`: the safe `Engine` API. `src/tun_settings.rs`: parses the "key value" lines `tun_up` gets.
- `vendor/openvpn3`: Core, as a git submodule.
- `vendor/asio`: asio 1.24.0 with Core's patches from `vendor/openvpn3/deps/asio/patches` applied. Headers only, nothing to build.
- `lab/entrypoint.sh`: the OpenVPN 2.6 servers the lab test runs against.
- `ci/linux/Dockerfile`: builds and tests the crate on Linux from Windows.

## Build

`build.rs` compiles the shim with the `cc` crate. There's no CMake and no vcpkg.

- OpenSSL comes from `openssl-sys` with its `vendored` feature (OpenSSL 3.6 through `openssl-src`). LZ4 comes from `lz4-sys`. Both report their headers to `build.rs` as `DEP_OPENSSL_INCLUDE` and `DEP_LZ4_INCLUDE`.
- Two static libraries come out of it: `ovpn_shim` (C++: `shim.cpp` and Core's `data_epoch.cpp`) and `ovpn_shim_xkey` (C: Core's `xkey` provider files). They're two `cc::Build`s because gcc would compile the C files as C++ in a C++ build.
- The defines and flags follow Core's `cmake/findcoredeps.cmake`. When the submodule moves, check that file for new source files, defines or system libraries.
- Core is always built with `-O2` and `NDEBUG`, even in debug builds, because an unoptimised Core is too slow to carry a tunnel.
- `lib.rs` has `use lz4_sys as _` and `use openssl_sys as _`. Without them rustc drops the two crates, since no Rust code calls them, and the shim fails to link.
- On MSVC, `build.rs` copies OpenSSL's `ossl_static.pdb` into `target/<profile>/deps`. OpenSSL's objects point at that file, and without it the linker prints one warning per object, around 2,700 of them.
- `OPENSSL_NO_VENDOR=1` links a system OpenSSL 3 instead. Nix builds use this.

## Tests

- `cargo test` runs the unit tests and `tests/engine.rs`, which call into Core without a server.
- `cargo test --test lab -- --ignored --nocapture` runs real connections against OpenVPN 2.6 servers in Docker (testcontainers, `alpine:3.22` plus `lab/entrypoint.sh`). It covers inline keys, external RSA, EC and Ed25519 keys, user and password, static and dynamic challenges, an AES-256-CBC-only server with and without `allow_non_preferred_ciphers`, a TLS 1.3 minimum against a TLS 1.2 server, renegotiation and reconnects.
- With Docker in WSL, `DOCKER_HOST` points at its daemon and the servers are reached on the WSL machine's IP, since UDP doesn't come through Windows' localhost forwarding. `OVPN_LAB_HOST` overrides the address, `OVPN_LAB_NO_WSL` skips the WSL handling and `OVPN_LAB_CASE` runs only the cases whose name contains it.
- `.github/workflows/ci.yml` runs `cargo test` on all six targets and the lab on Linux.

## Rules

- `shim.h` and `src/ffi.rs` change together. Any mismatch in a struct or signature links fine and breaks at runtime.
- Strings crossing the C API are a pointer and a length, only valid during the call. Copy anything that has to outlive it.
- Every `extern "C"` function in `shim.cpp` wraps its body in a try/catch. No exception may unwind into Rust.
- `EngineConfig`'s `compression`, `allow_non_preferred_ciphers` and `tls_version_min` reach Core in `ovpn_shim_eval_config` as numbers, defined in `shim.h`. A new option goes through `shim.h`, `ffi.rs` and `lib.rs` together, with a default that keeps today's behavior, and gets a line in the README.
- Secrets (passwords, challenge responses, inline tls-auth and tls-crypt keys) are wiped with `OPENSSL_cleanse` in C++ and held in `Zeroizing` in Rust.
- `ovpn_shim_init_process` calls `OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG)` before anything else touches OpenSSL, so no `openssl.cnf` is ever read. Keep it first.
- Updating asio means replacing `vendor/asio` with the version Core's `deps/lib-versions` names, with Core's patches applied, and updating `vendor/asio/README.md`.

## Conventions

- Default to no comments. One short line only for a non-obvious constraint.
