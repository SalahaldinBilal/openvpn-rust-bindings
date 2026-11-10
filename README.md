# openvpn-rust-bindings

Rust bindings to [OpenVPN 3 Core](https://github.com/OpenVPN/openvpn3) with a userspace tunnel.

Core runs inside your process. It doesn't create a network adapter. The IP packets that would go through one are handed to your code instead, and you send packets back the same way. That means no admin rights and no drivers, but you bring your own network stack (smoltcp, for example) to turn those packets into connections.

## Adding it

```toml
[dependencies]
openvpn-rust-bindings = "0.1.0"
```

Core's source comes inside the crate, so there's nothing else to download.

## What you need to build it

Core, OpenSSL and LZ4 are compiled during `cargo build`, so there's nothing to install or set up besides a compiler. The first build takes around 10 minutes because OpenSSL is built from source. After that it's cached like any other crate.

- A C++17 compiler: Visual Studio 2019 or newer with the C++ tools on Windows, the Xcode Command Line Tools on macOS, gcc or clang on Linux (`build-essential` on Debian and Ubuntu).
- Perl, which OpenSSL's build is written in. Linux and macOS already have it. On Windows install [Strawberry Perl](https://strawberryperl.com). The Perl that comes with Git for Windows doesn't work for this build. If another Perl comes first on your PATH, set `OPENSSL_SRC_PERL` to Strawberry's `perl.exe`.
- [NASM](https://www.nasm.us) on Windows is optional. When it's on PATH, OpenSSL is built with its assembly code, which is faster.

To link an OpenSSL that's already installed instead of building one, set `OPENSSL_NO_VENDOR=1`. It has to be OpenSSL 3. If it isn't found through pkg-config, point `OPENSSL_DIR` at it. Nix builds need this, since they can't download OpenSSL's source.

CI builds and tests it on Windows, macOS and Linux, each on x64 and arm64.

## Using it

```rust
use std::{error::Error, sync::Arc, thread};

use openvpn_rust_bindings::{CoreEvent, Credentials, Engine, EngineConfig, EngineEvents, SignRequest, TunSettings};

struct Events;

impl EngineEvents for Events {
    fn event(&self, event: CoreEvent) {
        println!("{} {}", event.name, event.info);
    }

    fn log(&self, line: &str) {
        println!("{line}");
    }

    fn sign(&self, _request: SignRequest) -> Result<String, String> {
        Err("this profile has its key inline".to_string())
    }

    fn tun_up(&self, settings: Result<TunSettings, String>) {
        // Set up your network stack with the address, routes and DNS servers the server pushed.
        println!("{settings:?}");
    }

    fn packet(&self, _packet: &[u8]) -> bool {
        // One IP packet from the VPN. Hand it to your network stack.
        true
    }

    fn tun_down(&self) {}
}

fn main() -> Result<(), Box<dyn Error>> {
    let engine = Arc::new(Engine::new(Arc::new(Events))?);

    let evaluated = engine.eval(&EngineConfig {
        profile: std::fs::read_to_string("client.ovpn")?,
        gui_version: "my-app 1.0".to_string(),
        conn_timeout_secs: 30,
        ..Default::default()
    })?;
    if !evaluated.autologin {
        engine.provide_credentials(&Credentials {
            username: "me".to_string(),
            password: "secret".to_string().into(),
            ..Default::default()
        })?;
    }

    let session = {
        let engine = engine.clone();
        thread::spawn(move || engine.connect())
    };

    // Packets from your network stack go in with engine.send_packet(&packet).
    // When you're done, stop() ends the session and connect() returns.

    engine.stop();
    session.join().unwrap()?;
    Ok(())
}
```

Things to know:

- `connect` blocks until the session ends, so it runs on its own thread. `stop`, `pause`, `resume`, `reconnect`, `transport_stats` and `send_packet` can be called from any thread while it runs.
- Every `EngineEvents` method is called on Core's thread. Return quickly and never call back into the engine and wait on it from there.
- `eval` reads the profile without connecting. It tells you whether a username and password are needed (`autologin`), whether the key lives outside the profile (`external_pki`), any static challenge text, and the first remote.
- With `external_pki`, pass the certificate in `EngineConfig::cert_pem` (and its chain in `chain_pem`) and keep the key yourself. Core calls `sign` with the data in base64, the algorithm (like `RSA_PKCS1_PSS_PADDING` or `ECDSA`), the hash and the PSS salt length. Return the signature in base64.
- `TunSettings` holds the IPv4 and IPv6 addresses, routes, DNS servers, search domains, split DNS domains and MTU. A userspace tunnel only needs those. For callers that set up a real adapter it also has:
  - `redirect`: the server's `redirect-gateway`, for IPv4, IPv6 or both, and whether it asked for `def1`.
  - `excludes4` and `excludes6`: networks pushed as `net_gateway`, which stay outside the VPN.
  - `remote`: the server's own address. With all traffic going through the VPN it needs a route outside the tunnel, or the tunnel would carry itself.
  - A metric on each route when the server gave one, and `route_metric` from `route-metric` for the rest.
  - `block4` and `block6`: the server pushed `block-ipv4` or `block-ipv6`.
- `Engine::parse_dynamic_challenge` reads a `CRV1:` cookie from the server, for logins that ask a second question after the password.
- `EngineConfig` overrides a few things in the profile. The defaults are the safe choice, change them only for a server that needs it:
  - `compression`: `Off` by default, since compression on an encrypted tunnel can leak what's inside it (the VORACLE attack). `Downlink` accepts compressed packets from the server without compressing anything sent. `Both` compresses in both directions.
  - `allow_non_preferred_ciphers`: `false` by default, which limits the data channel to AES-GCM and ChaCha20-Poly1305. Set it for servers that only offer something older, like AES-256-CBC.
  - `tls_version_min`: `Tls12` by default. `FromProfile` uses the profile's `tls-version-min`, and `Tls13` raises it. A higher minimum in the profile always wins.
- Legacy ciphers (BF-CBC, single DES, RC2) aren't supported. The bundled OpenSSL is built without them.
- The OpenSSL in here never reads an `openssl.cnf`, so a config file someone else can write can't change how it behaves.

## License

The bindings are MPL-2.0. OpenVPN 3 Core is under AGPL-3.0 or MPL-2.0, OpenSSL under Apache-2.0, LZ4 under BSD-2-Clause, and asio under the Boost Software License 1.0.
