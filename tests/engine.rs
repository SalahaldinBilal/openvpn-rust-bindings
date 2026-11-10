use std::sync::Arc;

use openvpn_rust_bindings::{CoreEvent, Engine, EngineConfig, EngineEvents, SignRequest, TunSettings};

struct Quiet;

impl EngineEvents for Quiet {
    fn event(&self, _event: CoreEvent) {}
    fn log(&self, _line: &str) {}
    fn sign(&self, _request: SignRequest) -> Result<String, String> {
        Err("no key in this test".to_string())
    }
    fn tun_up(&self, _settings: Result<TunSettings, String>) {}
    fn packet(&self, _packet: &[u8]) -> bool {
        false
    }
    fn tun_down(&self) {}
}

fn config(profile: &str) -> EngineConfig {
    EngineConfig {
        profile: profile.to_string(),
        gui_version: "openvpn-rust-bindings tests".to_string(),
        conn_timeout_secs: 10,
        ..Default::default()
    }
}

#[test]
fn reads_a_profile() {
    let engine = Engine::new(Arc::new(Quiet)).unwrap();
    let evaluated = engine
        .eval(&config("client\ndev tun\nproto udp\nremote vpn.example.com 1194\nauth-user-pass\nstatic-challenge \"Enter your code\" 1\n"))
        .unwrap();
    assert_eq!(evaluated.remote_host, "vpn.example.com");
    assert_eq!(evaluated.remote_port, "1194");
    assert!(!evaluated.autologin);
    assert_eq!(evaluated.static_challenge, Some(("Enter your code".to_string(), true)));
}

#[test]
fn reports_a_broken_profile() {
    let engine = Engine::new(Arc::new(Quiet)).unwrap();
    assert!(engine.eval(&config("this is not an openvpn profile")).is_err());
}

#[test]
fn parses_a_dynamic_challenge() {
    let challenge = Engine::parse_dynamic_challenge("CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:Y3Ix:Please enter token PIN").unwrap();
    assert_eq!(challenge.challenge, "Please enter token PIN");
    assert!(challenge.echo);
    assert!(challenge.response_required);
    assert_eq!(challenge.state_id, "Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l");
    assert!(Engine::parse_dynamic_challenge("not a challenge").is_none());
}

#[test]
fn packets_are_refused_without_a_tunnel() {
    let engine = Engine::new(Arc::new(Quiet)).unwrap();
    assert!(!engine.send_packet(&[0x45, 0, 0, 20]));
}
