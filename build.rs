use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn main() {
    for path in ["cpp/shim.h", "cpp/shim.cpp", "cpp/compat", "vendor/asio", "vendor/openvpn3"] {
        println!("cargo:rerun-if-changed={path}");
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core = core_dir(root);
    let openssl = dependency_include("OPENSSL");
    let lz4 = dependency_include("LZ4");
    let windows = env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows";
    let msvc = env::var("CARGO_CFG_TARGET_ENV").unwrap() == "msvc";

    let mut shim = cc::Build::new();
    configure(&mut shim, windows);
    shim.cpp(true)
        .std("c++17")
        .file(root.join("cpp/shim.cpp"))
        .file(core.join("openvpn/crypto/data_epoch.cpp"))
        .include(&core)
        .include(root.join("cpp"))
        .include(root.join("vendor/asio/include"))
        .include(&openssl)
        .include(&lz4)
        .define("ASIO_STANDALONE", None)
        .define("USE_ASIO", None)
        .define("HAVE_LZ4", None)
        .define("OPENVPN_EXTERNAL_TUN_FACTORY", None)
        .define("ENABLE_EXTERNAL_PKI", None);
    if windows {
        // Our own tap-windows.h, so the GPL tap-windows6 package isn't needed.
        shim.include(root.join("cpp/compat"))
            .define("_WIN32_WINNT", "0x0600")
            .define("TAP_WIN_COMPONENT_ID", "tap0901")
            .define("ASIO_DISABLE_LOCAL_SOCKETS", None);
    }
    if msvc {
        shim.flag("/EHsc").flag("/bigobj");
    }
    shim.compile("ovpn_shim");

    let mut xkey = cc::Build::new();
    configure(&mut xkey, windows);
    xkey.file(core.join("openvpn/openssl/xkey/xkey_helper.c"))
        .file(core.join("openvpn/openssl/xkey/xkey_provider.c"))
        .include(&core)
        .include(&openssl);
    xkey.compile("ovpn_shim_xkey");

    if msvc {
        copy_openssl_pdb();
    }
    link_system_libraries();
}

// OpenSSL's objects point at ossl_static.pdb, and the linker warns once per object unless it sits in the deps folder.
fn copy_openssl_pdb() {
    let Some(root) = env::var_os("DEP_OPENSSL_ROOT") else { return };
    let pdb = Path::new(&root).join("lib/ossl_static.pdb");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    if let (true, Some(profile)) = (pdb.is_file(), out.ancestors().nth(3)) {
        let _ = fs::copy(&pdb, profile.join("deps/ossl_static.pdb"));
    }
}

fn configure(build: &mut cc::Build, windows: bool) {
    // Core is always built optimised, a debug build of it is too slow to carry a tunnel.
    build.opt_level(2).debug(false).warnings(false).cargo_warnings(false).define("NDEBUG", None).define("USE_OPENSSL", None);
    if windows {
        build.define("_CRT_SECURE_NO_WARNINGS", None);
    }
}

fn core_dir(root: &Path) -> PathBuf {
    let core = root.join("vendor/openvpn3");
    if !core.join("client/ovpncli.cpp").is_file() {
        panic!("OpenVPN 3 Core is missing from vendor/openvpn3. Run: git submodule update --init");
    }
    core
}

fn dependency_include(name: &str) -> PathBuf {
    let var = format!("DEP_{name}_INCLUDE");
    PathBuf::from(env::var(&var).unwrap_or_else(|_| panic!("{var} isn't set, the {name} -sys crate didn't report its headers")))
}

fn link_system_libraries() {
    match env::var("CARGO_CFG_TARGET_OS").unwrap().as_str() {
        "windows" => {
            for lib in [
                "fwpuclnt", "iphlpapi", "wininet", "setupapi", "rpcrt4", "wtsapi32", "ws2_32", "crypt32", "advapi32", "user32",
                "bcrypt", "ole32", "shell32",
            ] {
                println!("cargo:rustc-link-lib=dylib={lib}");
            }
        }
        "macos" => {
            for framework in ["CoreFoundation", "IOKit", "CoreServices", "SystemConfiguration"] {
                println!("cargo:rustc-link-lib=framework={framework}");
            }
        }
        _ => {
            for lib in ["pthread", "dl"] {
                println!("cargo:rustc-link-lib=dylib={lib}");
            }
        }
    }
}
