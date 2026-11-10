mod ffi;
pub mod tun_settings;

// Never called from Rust, but the shim links against the OpenSSL and LZ4 they build.
use lz4_sys as _;
use openssl_sys as _;

use std::{
    ffi::c_void,
    ptr::NonNull,
    sync::{Arc, OnceLock},
};

use zeroize::Zeroizing;

use ffi::ShimStr;
pub use tun_settings::{Redirect, Route, TunSettings};

fn str_in(value: &str) -> ShimStr {
    ShimStr {
        ptr: value.as_ptr(),
        len: value.len(),
    }
}

// Safety: `value` points at `len` readable bytes for the duration of the call, or is null.
unsafe fn str_out(value: ShimStr) -> String {
    if value.ptr.is_null() || value.len == 0 {
        return String::new();
    }
    let bytes = unsafe { std::slice::from_raw_parts(value.ptr, value.len) };
    String::from_utf8_lossy(bytes).into_owned()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreEvent {
    pub error: bool,
    pub fatal: bool,
    pub name: String,
    pub info: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    pub data_base64: String,
    pub algorithm: String,
    pub hash: String,
    pub salt_len: String,
}

/// Called on Core's thread, so each one returns quickly and never blocks on Core.
pub trait EngineEvents: Send + Sync {
    fn event(&self, event: CoreEvent);
    fn log(&self, line: &str);
    /// Returns the signature in base64.
    fn sign(&self, request: SignRequest) -> Result<String, String>;
    fn tun_up(&self, settings: Result<TunSettings, String>);
    /// One IP packet leaving the tunnel. False drops it.
    fn packet(&self, packet: &[u8]) -> bool;
    fn tun_down(&self);
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineConfig {
    pub profile: String,
    pub cert_pem: String,
    pub chain_pem: String,
    /// Sent to the server as the client's name and version.
    pub gui_version: String,
    pub conn_timeout_secs: i32,
    pub compression: Compression,
    /// Also accepts data channel ciphers other than AES-GCM and ChaCha20-Poly1305, like AES-256-CBC.
    pub allow_non_preferred_ciphers: bool,
    pub tls_version_min: TlsVersionMin,
}

/// Compression on an encrypted tunnel can leak what's inside it (VORACLE), so it's off unless a server needs it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Compression {
    #[default]
    Off,
    /// Only packets from the server are decompressed. Nothing sent is compressed.
    Downlink,
    Both,
}

/// A profile's higher `tls-version-min` still wins.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TlsVersionMin {
    FromProfile,
    #[default]
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evaluated {
    pub autologin: bool,
    pub external_pki: bool,
    pub static_challenge: Option<(String, bool)>,
    pub remote_host: String,
    pub remote_port: String,
    pub remote_proto: String,
}

#[derive(Clone, Default)]
pub struct Credentials {
    pub username: String,
    pub password: Zeroizing<String>,
    pub response: Zeroizing<String>,
    pub dynamic_cookie: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransportStats {
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub packets_in: i64,
    pub packets_out: i64,
    pub last_packet_received: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicChallenge {
    pub challenge: String,
    pub echo: bool,
    pub response_required: bool,
    pub state_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineError {
    pub status: String,
    pub message: String,
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.status.is_empty(), self.message.is_empty()) {
            (true, true) => f.write_str("OpenVPN failed without saying why"),
            (true, false) => f.write_str(&self.message),
            (false, true) => f.write_str(&self.status),
            (false, false) => write!(f, "{}: {}", self.status, self.message),
        }
    }
}

impl std::error::Error for EngineError {}

static INIT: OnceLock<bool> = OnceLock::new();

// Every call into Core, even the static ones, needs the process-wide setup first.
fn init_process() -> Result<(), String> {
    if *INIT.get_or_init(|| unsafe { ffi::ovpn_shim_init_process() } != 0) {
        Ok(())
    } else {
        Err("OpenVPN 3 couldn't start".to_string())
    }
}

/// One OpenVPN 3 client with a userspace tunnel.
pub struct Engine {
    raw: NonNull<ffi::Shim>,
    // Boxed so the pointer Core holds stays put while `Engine` moves.
    _events: Box<Arc<dyn EngineEvents>>,
}

// Core documents stop, pause, resume, reconnect, stats and tun_recv as safe from any thread while connect runs.
unsafe impl Send for Engine {}
unsafe impl Sync for Engine {}

impl Engine {
    pub fn new(events: Arc<dyn EngineEvents>) -> Result<Self, String> {
        init_process()?;

        let events = Box::new(events);
        let callbacks = ffi::Callbacks {
            ctx: &*events as *const Arc<dyn EngineEvents> as *mut c_void,
            event: Some(on_event),
            log: Some(on_log),
            pki_sign: Some(on_sign),
            tun_up: Some(on_tun_up),
            tun_send: Some(on_tun_send),
            tun_down: Some(on_tun_down),
        };
        let raw = unsafe { ffi::ovpn_shim_new(&callbacks) };
        let raw = NonNull::new(raw).ok_or_else(|| "OpenVPN 3 couldn't create a client".to_string())?;
        Ok(Self { raw, _events: events })
    }

    pub fn eval(&self, config: &EngineConfig) -> Result<Evaluated, EngineError> {
        let raw = ffi::Config {
            profile: str_in(&config.profile),
            cert: str_in(&config.cert_pem),
            chain: str_in(&config.chain_pem),
            gui_version: str_in(&config.gui_version),
            conn_timeout_secs: config.conn_timeout_secs,
            compression: match config.compression {
                Compression::Off => 0,
                Compression::Downlink => 1,
                Compression::Both => 2,
            },
            allow_non_preferred_ciphers: i32::from(config.allow_non_preferred_ciphers),
            tls_version_min: match config.tls_version_min {
                TlsVersionMin::FromProfile => 0,
                TlsVersionMin::Tls12 => 1,
                TlsVersionMin::Tls13 => 2,
            },
        };
        let mut out: Option<Result<Evaluated, EngineError>> = None;
        unsafe {
            ffi::ovpn_shim_eval_config(self.raw.as_ptr(), &raw, &mut out as *mut _ as *mut c_void, on_eval);
        }
        out.unwrap_or_else(|| Err(no_answer()))
    }

    pub fn provide_credentials(&self, credentials: &Credentials) -> Result<(), EngineError> {
        let mut out: Option<Result<(), EngineError>> = None;
        unsafe {
            ffi::ovpn_shim_provide_creds(
                self.raw.as_ptr(),
                str_in(&credentials.username),
                str_in(&credentials.password),
                str_in(&credentials.response),
                str_in(&credentials.dynamic_cookie),
                &mut out as *mut _ as *mut c_void,
                on_status,
            );
        }
        out.unwrap_or_else(|| Err(no_answer()))
    }

    /// Blocks until the session ends, so it runs on its own thread.
    pub fn connect(&self) -> Result<(), EngineError> {
        let mut out: Option<Result<(), EngineError>> = None;
        unsafe {
            ffi::ovpn_shim_connect(self.raw.as_ptr(), &mut out as *mut _ as *mut c_void, on_status);
        }
        out.unwrap_or_else(|| Err(no_answer()))
    }

    pub fn stop(&self) {
        unsafe { ffi::ovpn_shim_stop(self.raw.as_ptr()) }
    }

    pub fn pause(&self, reason: &str) {
        unsafe { ffi::ovpn_shim_pause(self.raw.as_ptr(), str_in(reason)) }
    }

    pub fn resume(&self) {
        unsafe { ffi::ovpn_shim_resume(self.raw.as_ptr()) }
    }

    pub fn reconnect(&self, seconds: i32) {
        unsafe { ffi::ovpn_shim_reconnect(self.raw.as_ptr(), seconds) }
    }

    pub fn transport_stats(&self) -> TransportStats {
        let mut raw = ffi::Stats::default();
        unsafe { ffi::ovpn_shim_transport_stats(self.raw.as_ptr(), &mut raw) };
        TransportStats {
            bytes_in: raw.bytes_in,
            bytes_out: raw.bytes_out,
            packets_in: raw.packets_in,
            packets_out: raw.packets_out,
            last_packet_received: raw.last_packet_received,
        }
    }

    /// Hands one IP packet to Core. False means no tunnel is up to take it.
    pub fn send_packet(&self, packet: &[u8]) -> bool {
        unsafe { ffi::ovpn_shim_tun_recv(self.raw.as_ptr(), packet.as_ptr(), packet.len()) != 0 }
    }

    pub fn parse_dynamic_challenge(cookie: &str) -> Option<DynamicChallenge> {
        init_process().ok()?;
        let mut out: Option<DynamicChallenge> = None;
        let parsed = unsafe { ffi::ovpn_shim_parse_dynamic_challenge(str_in(cookie), &mut out as *mut _ as *mut c_void, on_challenge) };
        if parsed == 0 { None } else { out }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            ffi::ovpn_shim_stop(self.raw.as_ptr());
            ffi::ovpn_shim_free(self.raw.as_ptr());
        }
    }
}

fn no_answer() -> EngineError {
    EngineError {
        status: "exception".to_string(),
        message: "OpenVPN 3 didn't answer".to_string(),
    }
}

// Safety: `ctx` is the pointer `Engine::new` gave Core, alive as long as the client.
unsafe fn events<'a>(ctx: *mut c_void) -> &'a Arc<dyn EngineEvents> {
    unsafe { &*(ctx as *const Arc<dyn EngineEvents>) }
}

unsafe extern "C" fn on_event(ctx: *mut c_void, error: i32, fatal: i32, name: ShimStr, info: ShimStr) {
    let event = CoreEvent {
        error: error != 0,
        fatal: fatal != 0,
        name: unsafe { str_out(name) },
        info: unsafe { str_out(info) },
    };
    unsafe { events(ctx) }.event(event);
}

unsafe extern "C" fn on_log(ctx: *mut c_void, text: ShimStr) {
    let line = unsafe { str_out(text) };
    unsafe { events(ctx) }.log(line.trim_end());
}

unsafe extern "C" fn on_sign(
    ctx: *mut c_void,
    data: ShimStr,
    algorithm: ShimStr,
    hash: ShimStr,
    salt_len: ShimStr,
    reply_ctx: *mut c_void,
    reply: ffi::ReplyFn,
) {
    let request = SignRequest {
        data_base64: unsafe { str_out(data) },
        algorithm: unsafe { str_out(algorithm) },
        hash: unsafe { str_out(hash) },
        salt_len: unsafe { str_out(salt_len) },
    };
    let empty = str_in("");
    match unsafe { events(ctx) }.sign(request) {
        Ok(signature) => unsafe { reply(reply_ctx, str_in(&signature), empty) },
        Err(error) => unsafe { reply(reply_ctx, empty, str_in(&error)) },
    }
}

unsafe extern "C" fn on_tun_up(ctx: *mut c_void, settings: ShimStr) {
    let text = unsafe { str_out(settings) };
    unsafe { events(ctx) }.tun_up(TunSettings::parse(&text));
}

unsafe extern "C" fn on_tun_send(ctx: *mut c_void, data: *const u8, len: usize) -> i32 {
    if data.is_null() {
        return 0;
    }
    let packet = unsafe { std::slice::from_raw_parts(data, len) };
    i32::from(unsafe { events(ctx) }.packet(packet))
}

unsafe extern "C" fn on_tun_down(ctx: *mut c_void) {
    unsafe { events(ctx) }.tun_down();
}

unsafe extern "C" fn on_eval(out_ctx: *mut c_void, eval: *const ffi::Eval) {
    let out = unsafe { &mut *(out_ctx as *mut Option<Result<Evaluated, EngineError>>) };
    let eval = unsafe { &*eval };
    *out = Some(if eval.error != 0 {
        Err(EngineError {
            status: String::new(),
            message: unsafe { str_out(eval.message) },
        })
    } else {
        let challenge = unsafe { str_out(eval.static_challenge) };
        Ok(Evaluated {
            autologin: eval.autologin != 0,
            external_pki: eval.external_pki != 0,
            static_challenge: (!challenge.is_empty()).then(|| (challenge, eval.static_challenge_echo != 0)),
            remote_host: unsafe { str_out(eval.remote_host) },
            remote_port: unsafe { str_out(eval.remote_port) },
            remote_proto: unsafe { str_out(eval.remote_proto) },
        })
    });
}

unsafe extern "C" fn on_status(out_ctx: *mut c_void, status: *const ffi::Status) {
    let out = unsafe { &mut *(out_ctx as *mut Option<Result<(), EngineError>>) };
    let status = unsafe { &*status };
    *out = Some(if status.error != 0 {
        Err(EngineError {
            status: unsafe { str_out(status.status) },
            message: unsafe { str_out(status.message) },
        })
    } else {
        Ok(())
    });
}

unsafe extern "C" fn on_challenge(out_ctx: *mut c_void, challenge: *const ffi::Challenge) {
    let out = unsafe { &mut *(out_ctx as *mut Option<DynamicChallenge>) };
    let challenge = unsafe { &*challenge };
    *out = Some(DynamicChallenge {
        challenge: unsafe { str_out(challenge.challenge) },
        echo: challenge.echo != 0,
        response_required: challenge.response_required != 0,
        state_id: unsafe { str_out(challenge.state_id) },
    });
}
