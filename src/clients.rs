//! Totales por cliente para quien administra el proxy. Apagado por defecto.
//!
//! Permite encontrar a quien satura la red: cuántas peticiones y bytes, nunca qué sitios. Vive solo en
//! memoria, se olvida tras un día sin actividad y solo se ve con el token del puerto de administración.
//! Si cambia lo que se guarda aquí, hay que actualizar notice.rs y docs/AVISO.md.

use crate::stats::Outcome;
use crate::store::now;
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

const FORGET_AFTER_SECS: u64 = 86_400;
/// Tope de clientes en memoria: una subred IPv6 permitida podría tener muchísimas direcciones.
const MAX_CLIENTS: usize = 4096;

#[derive(Debug, Clone, Default, Serialize)]
pub struct ClientTotals {
    pub requests: u64,
    pub served_from_copy: u64,
    pub bytes: u64,
    pub bytes_from_copy: u64,
    pub tunnels: u64,
    pub blocked: u64,
    pub rate_limited: u64,
    pub last_seen: u64,
}

#[derive(Serialize)]
pub struct ClientRow {
    pub ip: IpAddr,
    #[serde(flatten)]
    pub totals: ClientTotals,
}

pub struct ClientStats {
    enabled: bool,
    clients: Mutex<HashMap<IpAddr, ClientTotals>>,
}

impl ClientStats {
    pub fn new(enabled: bool) -> Self {
        Self { enabled, clients: Mutex::new(HashMap::new()) }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    fn update(&self, client: IpAddr, change: impl FnOnce(&mut ClientTotals)) {
        if !self.enabled {
            return;
        }
        let client = client.to_canonical();
        let mut clients = self.clients.lock().expect("los totales no se envenenan");
        if clients.len() >= MAX_CLIENTS && !clients.contains_key(&client) {
            return;
        }
        let totals = clients.entry(client).or_default();
        totals.last_seen = now();
        change(totals);
    }

    pub fn record(&self, client: IpAddr, outcome: Outcome, bytes: Option<u64>) {
        let bytes = bytes.unwrap_or(0);
        self.update(client, |t| match outcome {
            Outcome::Tunnel => t.tunnels += 1,
            Outcome::Blocked => t.blocked += 1,
            _ => {
                t.requests += 1;
                t.bytes += bytes;
                if matches!(outcome, Outcome::Hit | Outcome::Revalidated) {
                    t.served_from_copy += 1;
                    t.bytes_from_copy += bytes;
                }
            }
        });
    }

    pub fn record_rate_limited(&self, client: IpAddr) {
        self.update(client, |t| t.rate_limited += 1);
    }

    pub fn forget_idle(&self) {
        let oldest = now().saturating_sub(FORGET_AFTER_SECS);
        self.clients.lock().expect("los totales no se envenenan").retain(|_, t| t.last_seen >= oldest);
    }

    /// De mayor a menor consumo.
    pub fn rows(&self) -> Vec<ClientRow> {
        let clients = self.clients.lock().expect("los totales no se envenenan");
        let mut rows: Vec<ClientRow> = clients.iter().map(|(ip, totals)| ClientRow { ip: *ip, totals: totals.clone() }).collect();
        rows.sort_by(|a, b| b.totals.bytes.cmp(&a.totals.bytes).then(b.totals.requests.cmp(&a.totals.requests)).then(a.ip.cmp(&b.ip)));
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn apagado_no_guarda_nada() {
        let c = ClientStats::new(false);
        c.record(ip("10.0.0.1"), Outcome::Hit, Some(10));
        c.record_rate_limited(ip("10.0.0.1"));
        assert!(c.rows().is_empty());
    }

    #[test]
    fn suma_por_cliente_y_ordena_por_consumo() {
        let c = ClientStats::new(true);
        c.record(ip("10.0.0.1"), Outcome::Hit, Some(10));
        c.record(ip("::ffff:10.0.0.1"), Outcome::Miss, Some(20));
        c.record(ip("10.0.0.1"), Outcome::Tunnel, None);
        c.record(ip("10.0.0.2"), Outcome::Bypass, Some(100));
        c.record(ip("10.0.0.3"), Outcome::Blocked, None);
        c.record_rate_limited(ip("10.0.0.3"));

        let rows = c.rows();
        assert_eq!(rows.iter().map(|r| r.ip).collect::<Vec<_>>(), [ip("10.0.0.2"), ip("10.0.0.1"), ip("10.0.0.3")]);
        let first = &rows[1].totals;
        assert_eq!((first.requests, first.served_from_copy, first.bytes, first.bytes_from_copy, first.tunnels), (2, 1, 30, 10, 1));
        assert_eq!((rows[2].totals.requests, rows[2].totals.blocked, rows[2].totals.rate_limited), (0, 1, 1));
    }

    #[test]
    fn no_crece_sin_limite_y_olvida_a_los_inactivos() {
        let c = ClientStats::new(true);
        for n in 0..(MAX_CLIENTS as u32 + 10) {
            c.record(IpAddr::V4(n.into()), Outcome::Tunnel, None);
        }
        assert_eq!(c.rows().len(), MAX_CLIENTS);

        let active = IpAddr::V4(0.into());
        c.clients.lock().unwrap().iter_mut().filter(|(ip, _)| **ip != active).for_each(|(_, t)| t.last_seen = 0);
        c.forget_idle();
        assert_eq!(c.rows().iter().map(|r| r.ip).collect::<Vec<_>>(), [active]);
    }
}
