use std::ffi::c_void;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShimStr {
    pub ptr: *const u8,
    pub len: usize,
}

pub enum Shim {}

pub type ReplyFn = unsafe extern "C" fn(reply_ctx: *mut c_void, value: ShimStr, error: ShimStr);

#[repr(C)]
pub struct Callbacks {
    pub ctx: *mut c_void,
    pub event: Option<unsafe extern "C" fn(*mut c_void, i32, i32, ShimStr, ShimStr)>,
    pub log: Option<unsafe extern "C" fn(*mut c_void, ShimStr)>,
    pub pki_sign: Option<unsafe extern "C" fn(*mut c_void, ShimStr, ShimStr, ShimStr, ShimStr, *mut c_void, ReplyFn)>,
    pub tun_up: Option<unsafe extern "C" fn(*mut c_void, ShimStr)>,
    pub tun_send: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
    pub tun_down: Option<unsafe extern "C" fn(*mut c_void)>,
}

#[repr(C)]
pub struct Config {
    pub profile: ShimStr,
    pub cert: ShimStr,
    pub chain: ShimStr,
    pub gui_version: ShimStr,
    pub conn_timeout_secs: i32,
    pub compression: i32,
    pub allow_non_preferred_ciphers: i32,
    pub tls_version_min: i32,
}

#[repr(C)]
pub struct Eval {
    pub error: i32,
    pub message: ShimStr,
    pub autologin: i32,
    pub external_pki: i32,
    pub static_challenge: ShimStr,
    pub static_challenge_echo: i32,
    pub remote_host: ShimStr,
    pub remote_port: ShimStr,
    pub remote_proto: ShimStr,
}

#[repr(C)]
pub struct Status {
    pub error: i32,
    pub status: ShimStr,
    pub message: ShimStr,
}

#[repr(C)]
#[derive(Default)]
pub struct Stats {
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub packets_in: i64,
    pub packets_out: i64,
    pub last_packet_received: i32,
}

#[repr(C)]
pub struct Challenge {
    pub challenge: ShimStr,
    pub echo: i32,
    pub response_required: i32,
    pub state_id: ShimStr,
}

pub type EvalFn = unsafe extern "C" fn(*mut c_void, *const Eval);
pub type StatusFn = unsafe extern "C" fn(*mut c_void, *const Status);
pub type ChallengeFn = unsafe extern "C" fn(*mut c_void, *const Challenge);

unsafe extern "C" {
    pub fn ovpn_shim_init_process() -> i32;
    pub fn ovpn_shim_new(callbacks: *const Callbacks) -> *mut Shim;
    pub fn ovpn_shim_free(client: *mut Shim);
    pub fn ovpn_shim_eval_config(client: *mut Shim, config: *const Config, out_ctx: *mut c_void, out: EvalFn) -> i32;
    pub fn ovpn_shim_provide_creds(
        client: *mut Shim,
        username: ShimStr,
        password: ShimStr,
        response: ShimStr,
        dynamic_cookie: ShimStr,
        out_ctx: *mut c_void,
        out: StatusFn,
    ) -> i32;
    pub fn ovpn_shim_connect(client: *mut Shim, out_ctx: *mut c_void, out: StatusFn) -> i32;
    pub fn ovpn_shim_stop(client: *mut Shim);
    pub fn ovpn_shim_pause(client: *mut Shim, reason: ShimStr);
    pub fn ovpn_shim_resume(client: *mut Shim);
    pub fn ovpn_shim_reconnect(client: *mut Shim, seconds: i32);
    pub fn ovpn_shim_transport_stats(client: *mut Shim, out: *mut Stats);
    pub fn ovpn_shim_tun_recv(client: *mut Shim, data: *const u8, len: usize) -> i32;
    pub fn ovpn_shim_parse_dynamic_challenge(cookie: ShimStr, out_ctx: *mut c_void, out: ChallengeFn) -> i32;
}
