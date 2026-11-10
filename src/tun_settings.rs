use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const MAX_LINES: usize = 4096;
const DNS_PORT: u16 = 53;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route<A> {
    pub address: A,
    pub prefix: u8,
    /// Set when the server gave this route a metric of its own.
    pub metric: Option<u32>,
}

/// The server's `redirect-gateway`: send all traffic through the VPN.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Redirect {
    pub ipv4: bool,
    pub ipv6: bool,
    /// Asked for with `def1`: cover the default route with 0.0.0.0/1 and 128.0.0.0/1 instead of replacing it.
    pub def1: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunSettings {
    pub addr4: Option<(Ipv4Addr, u8)>,
    pub addr6: Option<(Ipv6Addr, u8)>,
    pub gw4: Option<Ipv4Addr>,
    pub gw6: Option<Ipv6Addr>,
    pub routes4: Vec<Route<Ipv4Addr>>,
    pub routes6: Vec<Route<Ipv6Addr>>,
    /// Networks that stay outside the VPN (`route ... net_gateway`).
    pub excludes4: Vec<Route<Ipv4Addr>>,
    pub excludes6: Vec<Route<Ipv6Addr>>,
    pub redirect: Redirect,
    /// The VPN server's own address, which needs a route outside the tunnel when all traffic goes through it.
    pub remote: Option<IpAddr>,
    /// `route-metric`, for routes without a metric of their own.
    pub route_metric: Option<u32>,
    /// The server pushed `block-ipv4` or `block-ipv6`.
    pub block4: bool,
    pub block6: bool,
    pub dns: Vec<SocketAddr>,
    /// Search domains, appended to short names.
    pub domains: Vec<String>,
    /// Names whose lookups go to the VPN's DNS servers.
    pub split_domains: Vec<String>,
    pub mtu: Option<u16>,
}

impl TunSettings {
    /// Parses the shim's "key value" lines. Lines it doesn't know are skipped, a bad value is an error.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut settings = Self::default();
        for (index, line) in text.lines().enumerate() {
            if index >= MAX_LINES {
                return Err("The tunnel settings are too long".to_string());
            }
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once(' ').unwrap_or((line, ""));
            let value = value.trim();
            match key {
                "addr4" => settings.addr4 = Some(prefixed(value, 32)?),
                "addr6" => settings.addr6 = Some(prefixed(value, 128)?),
                "gw4" => settings.gw4 = Some(address(value)?),
                "gw6" => settings.gw6 = Some(address(value)?),
                "route4" => settings.routes4.push(route(value, 32)?),
                "route6" => settings.routes6.push(route(value, 128)?),
                "exclude4" => settings.excludes4.push(route(value, 32)?),
                "exclude6" => settings.excludes6.push(route(value, 128)?),
                "redirect4" => settings.redirect.ipv4 = true,
                "redirect6" => settings.redirect.ipv6 = true,
                "def1" => settings.redirect.def1 = true,
                "remote" => settings.remote = Some(address(value)?),
                "metric" => settings.route_metric = Some(value.parse().map_err(|_| format!("Bad route metric: {value}"))?),
                "block4" => settings.block4 = true,
                "block6" => settings.block6 = true,
                "dns" => settings.dns.push(dns_server(value)?),
                "domain" if !value.is_empty() => settings.domains.push(value.to_string()),
                "split" if !value.is_empty() => settings.split_domains.push(value.to_string()),
                "mtu" => {
                    let mtu: u16 = value.parse().map_err(|_| format!("Bad tunnel MTU: {value}"))?;
                    settings.mtu = Some(mtu);
                }
                _ => {}
            }
        }
        Ok(settings)
    }
}

fn address<T: std::str::FromStr>(value: &str) -> Result<T, String> {
    value.parse().map_err(|_| format!("Bad tunnel address: {value}"))
}

fn prefixed<T: std::str::FromStr>(value: &str, max: u8) -> Result<(T, u8), String> {
    let (addr, prefix) = value.split_once('/').ok_or_else(|| format!("Bad tunnel network: {value}"))?;
    let prefix: u8 = prefix.parse().map_err(|_| format!("Bad tunnel network: {value}"))?;
    if prefix > max {
        return Err(format!("Bad tunnel network: {value}"));
    }
    Ok((address(addr)?, prefix))
}

/// `10.0.0.0/8` or `10.0.0.0/8 5`, the second with the route's metric.
fn route<T: std::str::FromStr>(value: &str, max: u8) -> Result<Route<T>, String> {
    let (network, metric) = match value.split_once(' ') {
        Some((network, metric)) => (network, Some(metric.trim().parse().map_err(|_| format!("Bad route metric: {value}"))?)),
        None => (value, None),
    };
    let (address, prefix) = prefixed(network, max)?;
    Ok(Route { address, prefix, metric })
}

fn dns_server(value: &str) -> Result<SocketAddr, String> {
    let (addr, port) = match value.split_once(' ') {
        Some((addr, port)) => (addr, port.parse().map_err(|_| format!("Bad DNS server: {value}"))?),
        None => (value, DNS_PORT),
    };
    let ip: IpAddr = address(addr)?;
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_every_key() {
        let settings = TunSettings::parse(
            "addr4 10.8.0.2/24\ngw4 10.8.0.1\naddr6 fd00::2/64\nroute4 10.0.3.0/24\nroute4 10.0.4.0/24 7\nroute6 fd01::/48\n\
             exclude4 192.0.2.0/24\nexclude6 2001:db8::/32 3\nredirect4\nredirect6\ndef1\nremote 203.0.113.7\nmetric 50\nblock6\n\
             dns 10.8.0.1\ndns fd00::1 5353\ndomain corp.example\nsplit internal.example\nmtu 1500\n",
        )
        .unwrap();
        assert_eq!(settings.addr4, Some((Ipv4Addr::new(10, 8, 0, 2), 24)));
        assert_eq!(settings.gw4, Some(Ipv4Addr::new(10, 8, 0, 1)));
        assert_eq!(settings.addr6, Some(("fd00::2".parse().unwrap(), 64)));
        assert_eq!(settings.routes4, vec![
            Route { address: Ipv4Addr::new(10, 0, 3, 0), prefix: 24, metric: None },
            Route { address: Ipv4Addr::new(10, 0, 4, 0), prefix: 24, metric: Some(7) },
        ]);
        assert_eq!(settings.routes6.len(), 1);
        assert_eq!(settings.excludes4, vec![Route { address: Ipv4Addr::new(192, 0, 2, 0), prefix: 24, metric: None }]);
        assert_eq!(settings.excludes6[0].metric, Some(3));
        assert_eq!(settings.redirect, Redirect { ipv4: true, ipv6: true, def1: true });
        assert_eq!(settings.remote, Some("203.0.113.7".parse().unwrap()));
        assert_eq!(settings.route_metric, Some(50));
        assert!(settings.block6 && !settings.block4);
        assert_eq!(settings.dns, vec!["10.8.0.1:53".parse().unwrap(), "[fd00::1]:5353".parse().unwrap()]);
        assert_eq!(settings.domains, vec!["corp.example".to_string()]);
        assert_eq!(settings.split_domains, vec!["internal.example".to_string()]);
        assert_eq!(settings.mtu, Some(1500));
    }

    #[test]
    fn unknown_keys_are_skipped() {
        assert_eq!(TunSettings::parse("future thing\n\n").unwrap(), TunSettings::default());
    }

    #[test]
    fn bad_values_are_errors() {
        assert!(TunSettings::parse("addr4 10.8.0.2").is_err());
        assert!(TunSettings::parse("addr4 10.8.0.2/33").is_err());
        assert!(TunSettings::parse("route6 nope/64").is_err());
        assert!(TunSettings::parse("route4 10.0.0.0/8 low").is_err());
        assert!(TunSettings::parse("remote vpn.example.com").is_err());
        assert!(TunSettings::parse("mtu 70000").is_err());
        assert!(TunSettings::parse("dns 10.8.0.1 port").is_err());
    }

    #[test]
    fn too_many_lines_are_refused() {
        let text = "domain a\n".repeat(MAX_LINES + 1);
        assert!(TunSettings::parse(&text).is_err());
    }
}
