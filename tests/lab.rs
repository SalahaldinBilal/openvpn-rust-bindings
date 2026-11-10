// Real connections against OpenVPN 2.6 servers in Docker (lab/entrypoint.sh).
// Run with: cargo test --test lab -- --ignored --nocapture
// OVPN_LAB_HOST overrides the address the servers are reached on. With Docker in WSL it defaults to the WSL machine's IP,
// since UDP doesn't come through Windows' localhost forwarding.

use std::{
    collections::HashMap,
    env,
    net::Ipv4Addr,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use base64ct::{Base64, Encoding};
use openvpn_rust_bindings::{CoreEvent, Credentials, Engine, EngineConfig, EngineError, EngineEvents, Redirect, Route, SignRequest, TlsVersionMin, TunSettings};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, RSA_PKCS1_SHA256, RSA_PSS_SHA256, RsaKeyPair},
};
use testcontainers::{
    Container, GenericImage, ImageExt,
    core::{ExecCommand, IntoContainerPort, WaitFor},
    runners::SyncRunner,
};
use zeroize::Zeroizing;

const ENTRYPOINT: &[u8] = include_bytes!("../lab/entrypoint.sh");
const UP_TIMEOUT: Duration = Duration::from_secs(30);
const FAIL_TIMEOUT: Duration = Duration::from_secs(40);
const ECHO_ID: u16 = 0x4f56;

/// With Docker inside WSL, a `wsl.exe` held open keeps the distro from being stopped as idle mid-run.
struct WslKeepalive(Option<Child>);

impl WslKeepalive {
    fn start() -> Self {
        if !cfg!(windows) || env::var_os("OVPN_LAB_NO_WSL").is_some() {
            return Self(None);
        }
        let child = Command::new("wsl.exe")
            .args(["--exec", "sleep", "infinity"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok();
        Self(child)
    }
}

impl Drop for WslKeepalive {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct Lab {
    container: Container<GenericImage>,
    host: String,
    ports: HashMap<&'static str, u16>,
    _wsl: WslKeepalive,
}

impl Lab {
    fn start() -> Result<Self, String> {
        let wsl = WslKeepalive::start();
        // The entrypoint only starts the TCP server once every other server logged that it's up.
        let container = GenericImage::new("alpine", "3.22")
            .with_exposed_port(1194.tcp())
            .with_exposed_port(1194.udp())
            .with_exposed_port(1195.tcp())
            .with_exposed_port(1196.tcp())
            .with_exposed_port(1197.tcp())
            .with_exposed_port(1198.tcp())
            .with_exposed_port(1199.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Initialization Sequence Completed"))
            .with_copy_to("/entrypoint.sh", ENTRYPOINT.to_vec())
            .with_cmd(["sh", "-c", "apk add --no-cache openvpn openssl >/dev/null && exec sh /entrypoint.sh"])
            .with_privileged(true)
            .with_label("openvpn-rust-bindings", "lab")
            .with_startup_timeout(Duration::from_secs(180))
            .start()
            .map_err(|error| format!("The lab didn't start: {error}"))?;

        let port = |port| container.get_host_port_ipv4(port).map_err(|error| format!("No mapped port: {error}"));
        let ports = HashMap::from([
            ("@tcp@", port(1194.tcp())?),
            ("@udp@", port(1194.udp())?),
            ("@userpass@", port(1195.tcp())?),
            ("@badserver@", port(1196.tcp())?),
            ("@pkcs1@", port(1197.tcp())?),
            ("@cbc@", port(1198.tcp())?),
            ("@redirect@", port(1199.tcp())?),
        ]);
        let host = lab_host(&container)?;
        Ok(Self { container, host, ports, _wsl: wsl })
    }

    fn file(&self, name: &str) -> Result<Vec<u8>, String> {
        let mut result = self
            .container
            .exec(ExecCommand::new(["cat", &format!("/out/{name}")]))
            .map_err(|error| format!("Couldn't read {name}: {error}"))?;
        let bytes = result.stdout_to_vec().map_err(|error| format!("Couldn't read {name}: {error}"))?;
        if bytes.is_empty() {
            return Err(format!("{name} is empty"));
        }
        Ok(bytes)
    }

    fn profile(&self, name: &str) -> Result<String, String> {
        let mut profile = String::from_utf8(self.file(name)?).map_err(|_| format!("{name} isn't text"))?;
        for (placeholder, port) in &self.ports {
            profile = profile.replace(placeholder, &format!("{} {port}", self.host));
        }
        Ok(profile)
    }

    fn run(&self, command: &str) -> Result<(), String> {
        self.container
            .exec(ExecCommand::new(["sh", "-c", command]))
            .map(|_| ())
            .map_err(|error| format!("`{command}` failed: {error}"))
    }
}

fn lab_host(container: &Container<GenericImage>) -> Result<String, String> {
    if let Ok(host) = env::var("OVPN_LAB_HOST") {
        return Ok(host);
    }
    let host = container.get_host().map_err(|error| format!("No host for the lab: {error}"))?.to_string();
    let loopback = host == "localhost" || host == "127.0.0.1";
    if cfg!(windows) && loopback {
        let output = Command::new("wsl.exe")
            .args(["-e", "hostname", "-I"])
            .output()
            .map_err(|error| format!("Couldn't ask WSL for its address: {error}"))?;
        let text = String::from_utf8_lossy(&output.stdout);
        return text.split_whitespace().next().map(str::to_string).ok_or_else(|| "WSL reported no address".to_string());
    }
    Ok(if loopback { "127.0.0.1".to_string() } else { host })
}

enum Key {
    Ec(EcdsaKeyPair),
    Rsa(RsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

impl Key {
    fn ed25519(der: &[u8]) -> Result<Self, String> {
        Ed25519KeyPair::from_pkcs8_maybe_unchecked(der).map(Key::Ed25519).map_err(|error| format!("Bad Ed25519 key: {error}"))
    }

    fn ec(der: &[u8]) -> Result<Self, String> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der, &SystemRandom::new())
            .map(Key::Ec)
            .map_err(|error| format!("Bad EC key: {error}"))
    }

    fn rsa(der: &[u8]) -> Result<Self, String> {
        RsaKeyPair::from_pkcs8(der).map(Key::Rsa).map_err(|error| format!("Bad RSA key: {error}"))
    }

    fn sign(&self, request: &SignRequest) -> Result<String, String> {
        let data = Base64::decode_vec(&request.data_base64).map_err(|error| format!("Bad base64 from Core: {error}"))?;
        let rng = SystemRandom::new();
        let signature = match (self, request.algorithm.as_str(), request.hash.as_str()) {
            (Key::Ec(key), "ECDSA", "SHA256") => key.sign(&rng, &data).map_err(|_| "ECDSA signing failed")?.as_ref().to_vec(),
            (Key::Rsa(key), "RSA_PKCS1_PSS_PADDING", "SHA256") if matches!(request.salt_len.as_str(), "" | "digest") => {
                rsa_sign(key, &RSA_PSS_SHA256, &data)?
            }
            (Key::Rsa(key), "RSA_PKCS1_PADDING", "SHA256") => rsa_sign(key, &RSA_PKCS1_SHA256, &data)?,
            (Key::Ed25519(key), "ED25519", _) => key.sign(&data).as_ref().to_vec(),
            _ => {
                return Err(format!(
                    "Unsupported sign request: algorithm={} hash={} salt={}",
                    request.algorithm, request.hash, request.salt_len
                ));
            }
        };
        Ok(Base64::encode_string(&signature))
    }
}

fn rsa_sign(key: &RsaKeyPair, padding: &'static dyn ring::signature::RsaEncoding, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(padding, &SystemRandom::new(), data, &mut signature).map_err(|_| "RSA signing failed".to_string())?;
    Ok(signature)
}

enum Note {
    Up(Result<TunSettings, String>),
    Packet(Vec<u8>),
    Down,
    Event(CoreEvent),
}

struct Events {
    notes: Mutex<mpsc::Sender<Note>>,
    key: Option<Key>,
    signs: AtomicUsize,
    algorithms: Mutex<Vec<String>>,
    logs: Mutex<Vec<String>>,
}

impl Events {
    fn send(&self, note: Note) {
        let _ = self.notes.lock().unwrap().send(note);
    }
}

impl EngineEvents for Events {
    fn event(&self, event: CoreEvent) {
        self.send(Note::Event(event));
    }

    fn log(&self, line: &str) {
        if env::var_os("OVPN_LOG").is_some() {
            eprintln!("    core: {line}");
        }
        self.logs.lock().unwrap().push(line.to_string());
    }

    fn sign(&self, request: SignRequest) -> Result<String, String> {
        self.signs.fetch_add(1, Ordering::SeqCst);
        self.algorithms.lock().unwrap().push(format!("{}/{}", request.algorithm, request.hash));
        self.key.as_ref().ok_or_else(|| "No key for this session".to_string())?.sign(&request)
    }

    fn tun_up(&self, settings: Result<TunSettings, String>) {
        self.send(Note::Up(settings));
    }

    fn packet(&self, packet: &[u8]) -> bool {
        self.send(Note::Packet(packet.to_vec()));
        true
    }

    fn tun_down(&self) {
        self.send(Note::Down);
    }
}

#[derive(Default)]
struct Options {
    cert_pem: String,
    key: Option<Key>,
    credentials: Option<Credentials>,
    allow_non_preferred_ciphers: bool,
    tls_version_min: TlsVersionMin,
}

struct Session {
    engine: Arc<Engine>,
    events: Arc<Events>,
    inbox: mpsc::Receiver<Note>,
    thread: Option<JoinHandle<Result<(), EngineError>>>,
    seen: Vec<CoreEvent>,
    settings: Option<TunSettings>,
}

impl Session {
    fn start(profile: String, options: Options) -> Result<Self, String> {
        let (notes, inbox) = mpsc::channel();
        let events = Arc::new(Events {
            notes: Mutex::new(notes),
            key: options.key,
            signs: AtomicUsize::new(0),
            algorithms: Mutex::new(Vec::new()),
            logs: Mutex::new(Vec::new()),
        });
        let engine = Arc::new(Engine::new(events.clone())?);
        let config = EngineConfig {
            profile,
            cert_pem: options.cert_pem,
            gui_version: "openvpn-rust-bindings lab".to_string(),
            conn_timeout_secs: 15,
            allow_non_preferred_ciphers: options.allow_non_preferred_ciphers,
            tls_version_min: options.tls_version_min,
            ..Default::default()
        };
        let evaluated = engine.eval(&config).map_err(|error| format!("Profile refused: {error}"))?;
        if let Some(credentials) = &options.credentials {
            engine.provide_credentials(credentials).map_err(|error| format!("Credentials refused: {error}"))?;
        } else if !evaluated.autologin {
            return Err("The profile wants credentials and the case gave none".to_string());
        }
        let thread = {
            let engine = engine.clone();
            Some(thread::spawn(move || engine.connect()))
        };
        Ok(Self { engine, events, inbox, thread, seen: Vec::new(), settings: None })
    }

    fn next(&mut self, deadline: Instant) -> Option<Note> {
        let note = self.inbox.recv_timeout(deadline.saturating_duration_since(Instant::now())).ok()?;
        if let Note::Event(event) = &note {
            self.seen.push(event.clone());
        }
        Some(note)
    }

    fn wait_up(&mut self) -> Result<TunSettings, String> {
        let deadline = Instant::now() + UP_TIMEOUT;
        loop {
            match self.next(deadline) {
                Some(Note::Up(Ok(settings))) => {
                    self.settings = Some(settings.clone());
                    return Ok(settings);
                }
                Some(Note::Up(Err(error))) => return Err(format!("Bad tunnel settings: {error}")),
                Some(Note::Event(event)) if event.fatal => return Err(format!("Fatal {}: {}", event.name, event.info)),
                Some(_) => {}
                None => return Err(format!("No tunnel within {UP_TIMEOUT:?}. Events: {}", self.event_names())),
            }
        }
    }

    fn wait_down(&mut self, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.next(deadline) {
                Some(Note::Down) => return Ok(()),
                Some(_) => {}
                None => return Err(format!("The tunnel didn't go down. Events: {}", self.event_names())),
            }
        }
    }

    fn wait_fatal(&mut self) -> Result<CoreEvent, String> {
        let deadline = Instant::now() + FAIL_TIMEOUT;
        loop {
            match self.next(deadline) {
                Some(Note::Up(_)) => return Err("Connected, but should have been refused".to_string()),
                Some(Note::Event(event)) if event.fatal => return Ok(event),
                Some(_) => {}
                None => return Err(format!("Neither connected nor failed. Events: {}", self.event_names())),
            }
        }
    }

    fn ping(&mut self, count: u16) -> Result<(), String> {
        let settings = self.settings.clone().ok_or("Ping before the tunnel is up")?;
        let (local, prefix) = settings.addr4.ok_or("No IPv4 address pushed")?;
        let target = settings.gw4.unwrap_or_else(|| first_host(local, prefix));
        for seq in 1..=count {
            if !self.engine.send_packet(&echo_request(local, target, seq)) {
                return Err(format!("Core refused ping {seq}"));
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match self.next(deadline) {
                    Some(Note::Packet(packet)) if is_echo_reply(&packet, target, seq) => break,
                    Some(Note::Down) => return Err("The tunnel went down while pinging".to_string()),
                    Some(_) => {}
                    None => return Err(format!("No reply to ping {seq} from {target}")),
                }
            }
        }
        Ok(())
    }

    fn saw(&self, name: &str) -> bool {
        self.seen.iter().any(|event| event.name == name)
    }

    fn event_names(&self) -> String {
        self.seen.iter().map(|event| event.name.as_str()).collect::<Vec<_>>().join(", ")
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.engine.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn first_host(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) };
    Ipv4Addr::from((u32::from(addr) & mask) + 1)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn echo_request(source: Ipv4Addr, target: Ipv4Addr, seq: u16) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0];
    icmp.extend_from_slice(&ECHO_ID.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(b"openvpn-rust-bindings lab ping!!");
    let sum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());

    let total = (20 + icmp.len()) as u16;
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 64, 1, 0, 0]);
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&target.octets());
    let sum = checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(&icmp);
    packet
}

fn is_echo_reply(packet: &[u8], from: Ipv4Addr, seq: u16) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != 1 {
        return false;
    }
    let header = usize::from(packet[0] & 0x0f) * 4;
    let Some(icmp) = packet.get(header..header + 8) else {
        return false;
    };
    packet[12..16] == from.octets() && icmp[0] == 0 && icmp[4..6] == ECHO_ID.to_be_bytes() && icmp[6..8] == seq.to_be_bytes()
}

fn credentials(user: &str, password: &str, response: &str) -> Credentials {
    Credentials {
        username: user.to_string(),
        password: Zeroizing::new(password.to_string()),
        response: Zeroizing::new(response.to_string()),
        ..Default::default()
    }
}

fn ensure(condition: bool, message: impl FnOnce() -> String) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message()) }
}

fn tcp_with_inline_key(lab: &Lab) -> Result<(), String> {
    let mut session = Session::start(lab.profile("client-tcp.ovpn")?, Options::default())?;
    let settings = session.wait_up()?;
    ensure(settings.addr4.map(|(addr, _)| addr.octets()[..3] == [10, 8, 0]) == Some(true), || format!("Unexpected address: {settings:?}"))?;
    ensure(settings.dns == vec!["10.8.0.1:53".parse().unwrap()], || format!("Unexpected DNS: {:?}", settings.dns))?;
    ensure(settings.split_domains == vec!["lab.internal".to_string()], || format!("Unexpected domains: {settings:?}"))?;
    session.ping(3)
}

fn udp_with_inline_key(lab: &Lab) -> Result<(), String> {
    let mut session = Session::start(lab.profile("client-udp.ovpn")?, Options::default())?;
    let settings = session.wait_up()?;
    ensure(settings.addr4.map(|(addr, _)| addr.octets()[..3] == [10, 9, 0]) == Some(true), || format!("Unexpected address: {settings:?}"))?;
    session.ping(3)
}

fn external_key(lab: &Lab, profile: &str, cert: &str, key: Key) -> Result<Session, String> {
    let options = Options {
        cert_pem: String::from_utf8(lab.file(cert)?).map_err(|_| "Certificate isn't text")?,
        key: Some(key),
        ..Default::default()
    };
    let mut session = Session::start(lab.profile(profile)?, options)?;
    session.wait_up()?;
    session.ping(3)?;
    ensure(session.events.signs.load(Ordering::SeqCst) > 0, || "Core never asked for a signature".to_string())?;
    Ok(session)
}

fn external_ec_key(lab: &Lab) -> Result<(), String> {
    external_key(lab, "client-tcp-epki.ovpn", "client.crt", Key::ec(&lab.file("client.pk8")?)?).map(drop)
}

fn external_rsa_key(lab: &Lab) -> Result<(), String> {
    let session = external_key(lab, "client-tcp-epki.ovpn", "client-rsa.crt", Key::rsa(&lab.file("client-rsa.pk8")?)?)?;
    println!("    signed with {:?}", session.events.algorithms.lock().unwrap());
    Ok(())
}

/// "TLSv1.2" or "TLSv1.3", from Core's handshake log line.
fn negotiated_tls(session: &Session) -> Option<String> {
    session.events.logs.lock().unwrap().iter().rev().find_map(|line| {
        line.split(|character: char| !character.is_ascii_alphanumeric() && character != '.')
            .find(|word| word.starts_with("TLSv1."))
            .map(str::to_string)
    })
}

/// Core ignores `tls-version-max` on purpose (client/cliopt.hpp: "We don't allow restricting max version"),
/// so a TLS 1.3 server still gets TLS 1.3. The PKCS#1 server below is the one that only speaks 1.2.
fn tls_version_max_is_ignored(lab: &Lab) -> Result<(), String> {
    let session = external_key(lab, "client-tcp-epki-tls12.ovpn", "client-rsa.crt", Key::rsa(&lab.file("client-rsa.pk8")?)?)?;
    let tls = negotiated_tls(&session);
    ensure(tls.as_deref() == Some("TLSv1.3"), || format!("Expected TLS 1.3 despite tls-version-max 1.2, Core logged {tls:?}"))
}

/// A server that only takes PKCS#1 v1.5 client signatures (lab/pkcs1.cnf), so Core has to ask for one.
fn external_rsa_key_pkcs1(lab: &Lab) -> Result<(), String> {
    let session = external_key(lab, "client-pkcs1-epki.ovpn", "client-rsa.crt", Key::rsa(&lab.file("client-rsa.pk8")?)?)?;
    let algorithms = session.events.algorithms.lock().unwrap().clone();
    println!("    signed with {algorithms:?}");
    ensure(algorithms.iter().any(|algorithm| algorithm.starts_with("RSA_PKCS1_PADDING/")), || {
        format!("Core never asked for a PKCS#1 signature: {algorithms:?}")
    })?;
    let tls = negotiated_tls(&session);
    ensure(tls.as_deref() == Some("TLSv1.2"), || format!("Expected TLS 1.2, Core logged {tls:?}"))
}

/// The PKCS#1 server only speaks TLS 1.2, so asking for at least 1.3 has to fail the handshake.
fn tls_1_3_minimum_refuses_a_tls_1_2_server(lab: &Lab) -> Result<(), String> {
    let options = Options {
        cert_pem: String::from_utf8(lab.file("client-rsa.crt")?).map_err(|_| "Certificate isn't text")?,
        key: Some(Key::rsa(&lab.file("client-rsa.pk8")?)?),
        tls_version_min: TlsVersionMin::Tls13,
        ..Default::default()
    };
    let mut session = Session::start(lab.profile("client-pkcs1-epki.ovpn")?, options)?;
    let fatal = session.wait_fatal()?;
    ensure(fatal.name == "CONNECTION_TIMEOUT" && session.saw("TRANSPORT_ERROR"), || {
        format!("Expected failed handshakes until CONNECTION_TIMEOUT, got {} after: {}", fatal.name, session.event_names())
    })
}

fn cbc_server_is_refused_by_default(lab: &Lab) -> Result<(), String> {
    let mut session = Session::start(lab.profile("client-cbc.ovpn")?, Options::default())?;
    let fatal = session.wait_fatal()?;
    ensure(fatal.name == "AUTH_FAILED", || format!("Expected AUTH_FAILED for no shared cipher, got {} {}", fatal.name, fatal.info))
}

fn cbc_server_with_non_preferred_ciphers(lab: &Lab) -> Result<(), String> {
    let options = Options { allow_non_preferred_ciphers: true, ..Default::default() };
    let mut session = Session::start(lab.profile("client-cbc.ovpn")?, options)?;
    session.wait_up()?;
    session.ping(2)
}

fn external_ed25519_key(lab: &Lab) -> Result<(), String> {
    let session = external_key(lab, "client-tcp-epki.ovpn", "client-ed25519.crt", Key::ed25519(&lab.file("client-ed25519.pk8")?)?)?;
    println!("    signed with {:?}", session.events.algorithms.lock().unwrap());
    Ok(())
}

/// The server answers the password with a CRV1 challenge. Core ends the attempt with DYNAMIC_CHALLENGE, and the
/// answer goes in with the challenge's cookie on a fresh session, since Core needs the profile evaluated again.
fn dynamic_challenge(lab: &Lab) -> Result<(), String> {
    let options = Options { credentials: Some(credentials("crv", "labpass", "")), ..Default::default() };
    let mut session = Session::start(lab.profile("client-dynamic.ovpn")?, options)?;
    let deadline = Instant::now() + FAIL_TIMEOUT;
    let cookie = loop {
        match session.next(deadline) {
            Some(Note::Event(event)) if event.name == "DYNAMIC_CHALLENGE" => break event.info,
            Some(Note::Up(_)) => return Err("Connected without the second step".to_string()),
            Some(_) => {}
            None => return Err(format!("No DYNAMIC_CHALLENGE. Events: {}", session.event_names())),
        }
    };
    let challenge = Engine::parse_dynamic_challenge(&cookie).ok_or_else(|| format!("Core couldn't read the challenge {cookie}"))?;
    ensure(challenge.challenge == "Enter the code from your app" && challenge.echo && challenge.response_required, || {
        format!("Unexpected challenge: {challenge:?}")
    })?;

    drop(session);
    let answer = Credentials { username: "crv".to_string(), response: Zeroizing::new("654321".to_string()), dynamic_cookie: cookie, ..Default::default() };
    let mut session = Session::start(lab.profile("client-dynamic.ovpn")?, Options { credentials: Some(answer), ..Default::default() })?;
    session.wait_up()?;
    session.ping(2)
}

/// Two connected sessions in one process, each with its own Core client, passing traffic at the same time.
fn two_sessions_in_one_process(lab: &Lab) -> Result<(), String> {
    let mut tcp = Session::start(lab.profile("client-tcp.ovpn")?, Options::default())?;
    let mut udp = Session::start(lab.profile("client-udp.ovpn")?, Options::default())?;
    tcp.wait_up()?;
    udp.wait_up()?;
    for _ in 0..3 {
        tcp.ping(1)?;
        udp.ping(1)?;
    }
    Ok(())
}

fn missing_key_fails_cleanly(lab: &Lab) -> Result<(), String> {
    let options = Options {
        cert_pem: String::from_utf8(lab.file("client.crt")?).map_err(|_| "Certificate isn't text")?,
        ..Default::default()
    };
    let mut session = Session::start(lab.profile("client-tcp-epki.ovpn")?, options)?;
    let fatal = session.wait_fatal()?;
    ensure(fatal.name == "EPKI_ERROR", || format!("Expected EPKI_ERROR, got {} {}", fatal.name, fatal.info))?;
    ensure(fatal.info.contains("No key for this session"), || format!("Our error text didn't come through: {}", fatal.info))
}

fn wrong_ca_is_refused(lab: &Lab) -> Result<(), String> {
    let mut session = Session::start(lab.profile("client-wrongca.ovpn")?, Options::default())?;
    let fatal = session.wait_fatal()?;
    println!("    refused with {} after: {}", fatal.name, session.event_names());
    Ok(())
}

fn server_with_a_client_certificate_is_refused(lab: &Lab) -> Result<(), String> {
    let mut session = Session::start(lab.profile("client-badserver.ovpn")?, Options::default())?;
    let fatal = session.wait_fatal()?;
    println!("    refused with {} after: {}", fatal.name, session.event_names());
    Ok(())
}

fn user_and_password(lab: &Lab) -> Result<(), String> {
    let options = Options { credentials: Some(credentials("lab", "labpass", "")), ..Default::default() };
    let mut session = Session::start(lab.profile("client-userpass.ovpn")?, options)?;
    session.wait_up()?;
    session.ping(2)
}

fn wrong_password_is_refused(lab: &Lab) -> Result<(), String> {
    let options = Options { credentials: Some(credentials("lab", "wrong", "")), ..Default::default() };
    let mut session = Session::start(lab.profile("client-userpass.ovpn")?, options)?;
    let fatal = session.wait_fatal()?;
    ensure(fatal.name == "AUTH_FAILED", || format!("Expected AUTH_FAILED, got {} {}", fatal.name, fatal.info))
}

fn static_challenge(lab: &Lab) -> Result<(), String> {
    let profile = lab.profile("client-challenge.ovpn")?;
    let probe = Engine::new(Arc::new(Events {
        notes: Mutex::new(mpsc::channel().0),
        key: None,
        signs: AtomicUsize::new(0),
        algorithms: Mutex::new(Vec::new()),
        logs: Mutex::new(Vec::new()),
    }))?;
    let evaluated = probe
        .eval(&EngineConfig { profile: profile.clone(), ..Default::default() })
        .map_err(|error| error.to_string())?;
    ensure(evaluated.static_challenge == Some(("Enter your code".to_string(), true)), || {
        format!("Unexpected challenge: {:?}", evaluated.static_challenge)
    })?;

    let options = Options { credentials: Some(credentials("lab", "labpass", "123456")), ..Default::default() };
    let mut session = Session::start(profile, options)?;
    session.wait_up()?;
    session.ping(2)
}

fn wrong_challenge_code_is_refused(lab: &Lab) -> Result<(), String> {
    let options = Options { credentials: Some(credentials("lab", "labpass", "000000")), ..Default::default() };
    let mut session = Session::start(lab.profile("client-challenge.ovpn")?, options)?;
    let fatal = session.wait_fatal()?;
    ensure(fatal.name == "AUTH_FAILED", || format!("Expected AUTH_FAILED, got {} {}", fatal.name, fatal.info))
}

fn renegotiation_signs_again(lab: &Lab) -> Result<(), String> {
    let profile = format!("{}\nreneg-sec 5\n", lab.profile("client-tcp-epki.ovpn")?);
    let options = Options {
        cert_pem: String::from_utf8(lab.file("client.crt")?).map_err(|_| "Certificate isn't text")?,
        key: Some(Key::ec(&lab.file("client.pk8")?)?),
        ..Default::default()
    };
    let mut session = Session::start(profile, options)?;
    session.wait_up()?;
    session.ping(1)?;
    let first = session.events.signs.load(Ordering::SeqCst);
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(15) {
        session.ping(1)?;
        thread::sleep(Duration::from_secs(1));
    }
    let signs = session.events.signs.load(Ordering::SeqCst);
    ensure(signs > first, || format!("No new signature after 15 seconds with reneg-sec 5 ({signs} in all)"))
}

/// What a caller with a real adapter needs from the pushed options: the redirect, the network kept outside the VPN,
/// metrics, block-ipv6, and the server's own address for its bypass route.
fn redirect_gateway_and_exclude_route(lab: &Lab) -> Result<(), String> {
    let mut session = Session::start(lab.profile("client-redirect.ovpn")?, Options::default())?;
    let settings = session.wait_up()?;
    ensure(settings.redirect == Redirect { ipv4: true, ipv6: false, def1: true }, || format!("Unexpected redirect: {:?}", settings.redirect))?;
    ensure(settings.excludes4 == vec![Route { address: Ipv4Addr::new(192, 0, 2, 0), prefix: 24, metric: None }], || {
        format!("Unexpected exclude routes: {:?}", settings.excludes4)
    })?;
    ensure(settings.routes4.contains(&Route { address: Ipv4Addr::new(198, 51, 100, 0), prefix: 24, metric: Some(7) }), || {
        format!("The route with its own metric is missing: {:?}", settings.routes4)
    })?;
    ensure(settings.route_metric == Some(50), || format!("Unexpected route-metric: {:?}", settings.route_metric))?;
    ensure(settings.block6, || "block-ipv6 wasn't passed on".to_string())?;
    let host: std::net::IpAddr = lab.host.parse().map_err(|_| format!("The lab host {} isn't an address", lab.host))?;
    ensure(settings.remote == Some(host), || format!("Expected the server address {host}, got {:?}", settings.remote))?;
    session.ping(2)
}

fn reconnects_after_a_server_restart(lab: &Lab) -> Result<(), String> {
    let mut session = Session::start(lab.profile("client-tcp.ovpn")?, Options::default())?;
    session.wait_up()?;
    session.ping(1)?;
    lab.run("kill -USR1 1")?;
    session.wait_down(Duration::from_secs(30))?;
    session.wait_up()?;
    ensure(session.saw("RECONNECTING"), || format!("No RECONNECTING event: {}", session.event_names()))?;
    session.ping(2)
}

type Case = fn(&Lab) -> Result<(), String>;

#[test]
#[ignore = "needs Docker, run with --ignored"]
fn lab() {
    let lab = Lab::start().unwrap();
    println!("lab at {} with ports {:?}", lab.host, lab.ports);
    let cases: Vec<(&str, Case)> = vec![
        ("tcp_with_inline_key", tcp_with_inline_key),
        ("udp_with_inline_key", udp_with_inline_key),
        ("external_ec_key", external_ec_key),
        ("external_rsa_key", external_rsa_key),
        ("tls_version_max_is_ignored", tls_version_max_is_ignored),
        ("external_rsa_key_pkcs1", external_rsa_key_pkcs1),
        ("tls_1_3_minimum_refuses_a_tls_1_2_server", tls_1_3_minimum_refuses_a_tls_1_2_server),
        ("cbc_server_is_refused_by_default", cbc_server_is_refused_by_default),
        ("cbc_server_with_non_preferred_ciphers", cbc_server_with_non_preferred_ciphers),
        ("external_ed25519_key", external_ed25519_key),
        ("dynamic_challenge", dynamic_challenge),
        ("two_sessions_in_one_process", two_sessions_in_one_process),
        ("missing_key_fails_cleanly", missing_key_fails_cleanly),
        ("wrong_ca_is_refused", wrong_ca_is_refused),
        ("server_with_a_client_certificate_is_refused", server_with_a_client_certificate_is_refused),
        ("user_and_password", user_and_password),
        ("wrong_password_is_refused", wrong_password_is_refused),
        ("static_challenge", static_challenge),
        ("wrong_challenge_code_is_refused", wrong_challenge_code_is_refused),
        ("renegotiation_signs_again", renegotiation_signs_again),
        ("redirect_gateway_and_exclude_route", redirect_gateway_and_exclude_route),
        ("reconnects_after_a_server_restart", reconnects_after_a_server_restart),
    ];
    let filter = env::var("OVPN_LAB_CASE").ok();
    let mut failures = Vec::new();
    for (name, case) in cases {
        if filter.as_deref().is_some_and(|filter| !name.contains(filter)) {
            continue;
        }
        let started = Instant::now();
        match case(&lab) {
            Ok(()) => println!("ok      {name} ({:.1?})", started.elapsed()),
            Err(error) => {
                println!("FAILED  {name} ({:.1?}): {error}", started.elapsed());
                failures.push(name);
            }
        }
    }
    assert!(failures.is_empty(), "failed: {failures:?}");
}
