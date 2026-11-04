//! Quién puede usar el proxy, cuánto y hacia qué destinos.

use crate::config::Config;
use crate::store::now;
use anyhow::{bail, Context};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{LazyLock, Mutex};

/// Red en notación CIDR. Una IP sin prefijo equivale a esa sola dirección.
#[derive(Debug, Clone, Copy)]
pub struct Network {
    addr: IpAddr,
    prefix: u8,
}

impl FromStr for Network {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, prefix)) => (ip, Some(prefix.parse::<u8>().with_context(|| format!("prefijo inválido en {s}"))?)),
            None => (s, None),
        };
        let addr: IpAddr = ip.parse().with_context(|| format!("IP inválida en {s}"))?;
        let bits = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(bits);
        if prefix > bits {
            bail!("prefijo fuera de rango en {s}");
        }
        Ok(Self { addr: addr.to_canonical(), prefix })
    }
}

impl Network {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.prefix)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.prefix)).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }

    fn covers_everyone(&self) -> bool {
        self.prefix == 0
    }

    fn is_loopback(&self) -> bool {
        self.addr.is_loopback()
    }
}

fn parse_networks(list: &[String]) -> anyhow::Result<Vec<Network>> {
    list.iter().map(|s| s.parse()).collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClientDecision {
    Allow,
    Denied,
    RateLimited,
}

/// Decide si un cliente puede usar el proxy en este momento.
pub struct ClientGate {
    allowed: Vec<Network>,
    limit_per_minute: u32,
    /// Minuto en curso y peticiones de cada IP en él. Se vacía al cambiar de minuto,
    /// así que su tamaño queda acotado por los clientes permitidos.
    window: Mutex<(u64, HashMap<IpAddr, u32>)>,
}

impl ClientGate {
    /// Falla si la configuración dejaría el proxy abierto a la red.
    pub fn new(cfg: &Config, listen: SocketAddr) -> anyhow::Result<Self> {
        let allowed = parse_networks(&cfg.allowed_clients).context("allowed_clients inválido")?;
        if allowed.is_empty() {
            bail!("allowed_clients está vacío: nadie podría usar el proxy");
        }
        if allowed.iter().any(Network::covers_everyone) {
            bail!("allowed_clients no puede incluir a todo Internet (prefijo /0): sería un proxy abierto");
        }
        if !listen.ip().is_loopback() && allowed.iter().all(Network::is_loopback) {
            bail!(
                "el proxy escucha en {listen}, pero allowed_clients solo permite este equipo. \
                 Agrega la subred de tus clientes, por ejemplo \"192.168.1.0/24\""
            );
        }
        Ok(Self { allowed, limit_per_minute: cfg.rate_limit_per_minute, window: Mutex::new((0, HashMap::new())) })
    }

    pub fn check(&self, client: IpAddr) -> ClientDecision {
        self.check_at(client, now() / 60)
    }

    fn check_at(&self, client: IpAddr, minute: u64) -> ClientDecision {
        let client = client.to_canonical();
        if !self.allowed.iter().any(|n| n.contains(client)) {
            return ClientDecision::Denied;
        }
        if self.limit_per_minute == 0 {
            return ClientDecision::Allow;
        }
        let mut window = self.window.lock().expect("el contador de peticiones no se envenena");
        if window.0 != minute {
            *window = (minute, HashMap::new());
        }
        let count = window.1.entry(client).or_insert(0);
        if *count >= self.limit_per_minute {
            return ClientDecision::RateLimited;
        }
        *count += 1;
        ClientDecision::Allow
    }
}

/// Destinos que un cliente no debe alcanzar a través del proxy: el propio equipo, la red local y
/// servicios internos como 169.254.169.254. Incluye rangos IPv6 que encapsulan direcciones IPv4.
static INTERNAL_NETWORKS: LazyLock<Vec<Network>> = LazyLock::new(|| {
    [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/96",
        "64:ff9b::/96",
        "2002::/16",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    ]
    .iter()
    .map(|s| s.parse().expect("red interna válida"))
    .collect()
});

#[derive(Debug)]
pub enum ResolveError {
    Blocked(IpAddr),
    Lookup(io::Error),
}

impl From<ResolveError> for io::Error {
    fn from(e: ResolveError) -> Self {
        match e {
            ResolveError::Blocked(ip) => io::Error::new(io::ErrorKind::PermissionDenied, format!("destino interno bloqueado: {ip}")),
            ResolveError::Lookup(e) => e,
        }
    }
}

/// Decide a qué direcciones puede conectarse el proxy en nombre de un cliente.
pub struct DestinationPolicy {
    allowed_internal: Vec<Network>,
}

impl DestinationPolicy {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        Ok(Self {
            allowed_internal: parse_networks(&cfg.allowed_internal_networks).context("allowed_internal_networks inválido")?,
        })
    }

    pub fn permits(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        !INTERNAL_NETWORKS.iter().any(|n| n.contains(ip)) || self.allowed_internal.iter().any(|n| n.contains(ip))
    }

    /// Resuelve el host y exige que TODAS sus direcciones estén permitidas: un nombre que mezcla
    /// IPs públicas e internas es la forma habitual de saltarse este tipo de filtro.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ResolveError> {
        let addrs: Vec<SocketAddr> = match literal_ip(host) {
            Some(ip) => vec![SocketAddr::new(ip, port)],
            None => tokio::net::lookup_host((host, port)).await.map_err(ResolveError::Lookup)?.collect(),
        };
        match addrs.iter().find(|a| !self.permits(a.ip())) {
            Some(blocked) => Err(ResolveError::Blocked(blocked.ip())),
            None => Ok(addrs),
        }
    }
}

/// Interpreta un host como IP literal, con o sin los corchetes de IPv6.
pub fn literal_ip(host: &str) -> Option<IpAddr> {
    host.trim_start_matches('[').trim_end_matches(']').parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> Network {
        s.parse().unwrap()
    }

    fn listen(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn gate(allowed: &[&str], limit: u32) -> ClientGate {
        let cfg = Config {
            allowed_clients: allowed.iter().map(|s| s.to_string()).collect(),
            rate_limit_per_minute: limit,
            ..Config::default()
        };
        ClientGate::new(&cfg, listen("192.168.1.2:3128")).unwrap()
    }

    #[test]
    fn redes_cidr() {
        assert!(net("192.168.1.0/24").contains(ip("192.168.1.200")));
        assert!(!net("192.168.1.0/24").contains(ip("192.168.2.1")));
        assert!(net("10.0.0.5").contains(ip("10.0.0.5")));
        assert!(!net("10.0.0.5").contains(ip("10.0.0.6")));
        assert!(net("fd00::/8").contains(ip("fd12::1")));
        assert!(!net("192.168.1.0/24").contains(ip("fd12::1")));
        assert!(net("0.0.0.0/0").contains(ip("8.8.8.8")));
        assert!("10.0.0.0/33".parse::<Network>().is_err());
        assert!("no-es-ip/8".parse::<Network>().is_err());
    }

    #[test]
    fn solo_entran_los_clientes_permitidos() {
        let g = gate(&["192.168.1.0/24"], 0);
        assert_eq!(g.check(ip("192.168.1.9")), ClientDecision::Allow);
        assert_eq!(g.check(ip("::ffff:192.168.1.9")), ClientDecision::Allow);
        assert_eq!(g.check(ip("192.168.2.9")), ClientDecision::Denied);
    }

    #[test]
    fn el_limite_es_por_ip_y_por_minuto() {
        let g = gate(&["192.168.1.0/24"], 2);
        let (a, b) = (ip("192.168.1.1"), ip("192.168.1.2"));
        assert_eq!(g.check_at(a, 100), ClientDecision::Allow);
        assert_eq!(g.check_at(a, 100), ClientDecision::Allow);
        assert_eq!(g.check_at(a, 100), ClientDecision::RateLimited);
        assert_eq!(g.check_at(b, 100), ClientDecision::Allow);
        assert_eq!(g.check_at(a, 101), ClientDecision::Allow);
    }

    #[test]
    fn no_arranca_si_quedaria_abierto() {
        let cfg = |allowed: &[&str]| Config { allowed_clients: allowed.iter().map(|s| s.to_string()).collect(), ..Config::default() };
        let lan = listen("0.0.0.0:3128");
        assert!(ClientGate::new(&cfg(&[]), listen("127.0.0.1:3128")).is_err());
        assert!(ClientGate::new(&cfg(&["0.0.0.0/0"]), lan).is_err());
        assert!(ClientGate::new(&cfg(&["::/0"]), lan).is_err());
        assert!(ClientGate::new(&cfg(&["127.0.0.1/32", "::1/128"]), lan).is_err());
        assert!(ClientGate::new(&cfg(&["192.168.1.0/24"]), lan).is_ok());
        assert!(ClientGate::new(&cfg(&["127.0.0.1/32"]), listen("127.0.0.1:3128")).is_ok());
    }

    #[test]
    fn destinos_internos_bloqueados_salvo_excepcion() {
        let closed = DestinationPolicy::new(&Config::default()).unwrap();
        for blocked in [
            "127.0.0.1", "127.8.8.8", "10.1.2.3", "172.16.0.1", "192.168.0.1", "169.254.169.254", "100.64.0.1",
            "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "::", "fe80::1", "fd00::1", "ff02::1",
            "::ffff:127.0.0.1", "::127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::",
        ] {
            assert!(!closed.permits(ip(blocked)), "{blocked} debería estar bloqueada");
        }
        for public in ["8.8.8.8", "172.32.0.1", "2606:4700::1111"] {
            assert!(closed.permits(ip(public)), "{public} debería estar permitida");
        }

        let cfg = Config { allowed_internal_networks: vec!["10.1.0.0/16".into()], ..Config::default() };
        let open = DestinationPolicy::new(&cfg).unwrap();
        assert!(open.permits(ip("10.1.2.3")));
        assert!(!open.permits(ip("10.2.0.1")));
        assert!(!open.permits(ip("127.0.0.1")));
    }

    #[tokio::test]
    async fn resolver_rechaza_literales_y_nombres_internos() {
        let closed = DestinationPolicy::new(&Config::default()).unwrap();
        assert!(matches!(closed.resolve("[::1]", 80).await, Err(ResolveError::Blocked(_))));
        assert!(matches!(closed.resolve("127.0.0.1", 80).await, Err(ResolveError::Blocked(_))));
        assert!(matches!(closed.resolve("localhost", 80).await, Err(ResolveError::Blocked(_))));
        assert_eq!(closed.resolve("8.8.8.8", 443).await.unwrap(), vec![listen("8.8.8.8:443")]);
    }
}
