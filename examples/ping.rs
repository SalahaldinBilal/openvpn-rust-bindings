// Connects with a profile and pings the server's tunnel address with hand-built ICMP packets.
// Usage: cargo run --example ping -- <profile.ovpn> [--remote "host port"] [--cert client.crt --key client.pk8]   (OVPN_LOG=1 prints Core's log)
// --remote replaces the profile's remote line, as the lab's profiles only name a placeholder.
// With --cert and --key, Core only gets the certificate and asks this program to sign with an ECDSA P-256 key.

use std::{
    env, fs,
    net::Ipv4Addr,
    process::ExitCode,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use base64ct::{Base64, Encoding};
use openvpn_rust_bindings::{CoreEvent, Engine, EngineConfig, EngineEvents, SignRequest, TunSettings};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
};

const ECHO_ID: u16 = 0x4f56;
const PINGS: u16 = 3;

enum Note {
    Up(Result<TunSettings, String>),
    Packet(Vec<u8>),
    Down,
    Fatal(String),
}

struct Events {
    notes: Mutex<mpsc::Sender<Note>>,
    log: bool,
    key: Option<EcdsaKeyPair>,
}

impl Events {
    fn send(&self, note: Note) {
        let _ = self.notes.lock().unwrap().send(note);
    }
}

impl EngineEvents for Events {
    fn event(&self, event: CoreEvent) {
        let fatal = if event.fatal { " (fatal)" } else { "" };
        eprintln!("event: {} {}{fatal}", event.name, event.info);
        if event.fatal {
            self.send(Note::Fatal(format!("{} {}", event.name, event.info)));
        }
    }

    fn log(&self, line: &str) {
        if self.log {
            eprintln!("core: {line}");
        }
    }

    fn sign(&self, request: SignRequest) -> Result<String, String> {
        eprintln!("sign: algorithm={} hash={} salt={}", request.algorithm, request.hash, request.salt_len);
        let key = self.key.as_ref().ok_or("This run has no external key")?;
        // An empty hash means Core already hashed the data, which ring can't sign.
        if request.hash != "SHA256" {
            return Err(format!("Only SHA256 is supported here, got '{}'", request.hash));
        }
        let data = Base64::decode_vec(&request.data_base64).map_err(|error| format!("Bad base64 from Core: {error}"))?;
        let signature = key.sign(&SystemRandom::new(), &data).map_err(|_| "Signing failed".to_string())?;
        Ok(Base64::encode_string(signature.as_ref()))
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

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: ping <profile.ovpn>");
        return ExitCode::FAILURE;
    };
    let profile = match fs::read_to_string(&path) {
        Ok(profile) => profile,
        Err(error) => {
            eprintln!("Couldn't read {path}: {error}");
            return ExitCode::FAILURE;
        }
    };

    let args: Vec<String> = env::args().collect();
    let option = |name: &str| args.iter().position(|arg| arg == name).and_then(|index| args.get(index + 1));
    let profile = match option("--remote") {
        Some(remote) => profile
            .lines()
            .map(|line| if line.starts_with("remote ") { format!("remote {remote}") } else { line.to_string() })
            .collect::<Vec<_>>()
            .join("\n"),
        None => profile,
    };
    let cert_pem = match option("--cert") {
        Some(path) => fs::read_to_string(path).expect("read the certificate"),
        None => String::new(),
    };
    let key = option("--key").map(|path| {
        let der = fs::read(path).expect("read the PKCS#8 key");
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &der, &SystemRandom::new()).expect("an ECDSA P-256 PKCS#8 key")
    });

    let (notes, inbox) = mpsc::channel();
    let events = Arc::new(Events {
        notes: Mutex::new(notes),
        log: env::var_os("OVPN_LOG").is_some(),
        key,
    });
    let engine = Arc::new(Engine::new(events).expect("create the engine"));
    let config = EngineConfig {
        profile,
        cert_pem,
        gui_version: "openvpn-rust-bindings ping".to_string(),
        conn_timeout_secs: 20,
        ..Default::default()
    };
    match engine.eval(&config) {
        Ok(evaluated) => println!("server: {} {} {}", evaluated.remote_host, evaluated.remote_port, evaluated.remote_proto),
        Err(error) => {
            eprintln!("Profile refused: {error}");
            return ExitCode::FAILURE;
        }
    }

    let session = {
        let engine = engine.clone();
        thread::spawn(move || engine.connect())
    };

    let ok = run_pings(&engine, &inbox);

    engine.stop();
    match session.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("session ended with: {error}"),
        Err(_) => eprintln!("session thread panicked"),
    }
    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

fn run_pings(engine: &Engine, inbox: &mpsc::Receiver<Note>) -> bool {
    let settings = loop {
        match inbox.recv_timeout(Duration::from_secs(30)) {
            Ok(Note::Up(Ok(settings))) => break settings,
            Ok(Note::Up(Err(error))) => {
                eprintln!("Bad tunnel settings: {error}");
                return false;
            }
            Ok(Note::Down) => {
                eprintln!("The tunnel went down before it came up");
                return false;
            }
            Ok(Note::Fatal(reason)) => {
                eprintln!("Core gave up: {reason}");
                return false;
            }
            Ok(Note::Packet(_)) => {}
            Err(_) => {
                eprintln!("No tunnel within 30 seconds");
                return false;
            }
        }
    };
    println!("tunnel up: {settings:?}");

    let Some((local, prefix)) = settings.addr4 else {
        eprintln!("The server pushed no IPv4 address");
        return false;
    };
    let target = settings.gw4.unwrap_or_else(|| first_host(local, prefix));

    let mut replies = 0;
    for seq in 1..=PINGS {
        let sent = Instant::now();
        if !engine.send_packet(&echo_request(local, target, seq)) {
            eprintln!("Core refused packet {seq}");
            continue;
        }
        let deadline = sent + Duration::from_secs(3);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match inbox.recv_timeout(left) {
                Ok(Note::Packet(packet)) if is_echo_reply(&packet, target, seq) => {
                    println!("reply from {target}: seq={seq} time={:?}", sent.elapsed());
                    replies += 1;
                    break;
                }
                Ok(Note::Down) => {
                    eprintln!("The tunnel went down");
                    return false;
                }
                Ok(Note::Fatal(reason)) => {
                    eprintln!("Core gave up: {reason}");
                    return false;
                }
                Ok(_) => {}
                Err(_) => {
                    eprintln!("no reply for seq={seq}");
                    break;
                }
            }
        }
    }
    println!("{replies}/{PINGS} replies");
    replies == PINGS
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
    icmp.extend_from_slice(b"openvpn-rust-bindings ping data!");
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
    packet[12..16] == from.octets()
        && icmp[0] == 0
        && icmp[4..6] == ECHO_ID.to_be_bytes()
        && icmp[6..8] == seq.to_be_bytes()
}
