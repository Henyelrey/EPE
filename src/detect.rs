//! Detecciones de actividad inusual, para quien administra el proxy.
//!
//! Avisan, pero no bloquean: una IP señala un equipo y no a una persona, y un volumen alto puede ser una
//! actualización legítima. Guardan la IP, el tipo de aviso y cuántas veces ocurrió, nunca qué sitios. Viven
//! solo en memoria, se olvidan tras un día y solo se ven con el token del puerto de administración.
//! Si cambia lo que se guarda aquí, hay que actualizar notice.rs y docs/AVISO.md.
//!
//! Límites conocidos:
//! - Cuenta por minuto de reloj, así que una ráfaga repartida entre dos minutos puede no llegar al umbral.
//! - Hudsucker no expone los bytes de un túnel, y tampoco lee el SNI si el dominio no se intercepta.

use crate::ban::BanList;
use crate::monitor::format_bytes;
use crate::security::{SecurityEvent, SecurityLog};
use crate::stats::Stats;
use crate::store::now;
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

const SECS_PER_MINUTE: u64 = 60;
const FORGET_AFTER_SECS: u64 = 86_400;
/// Topes de memoria: una subred IPv6 permitida podría tener muchísimas direcciones.
const MAX_TRACKED_CLIENTS: usize = 4096;
const MAX_EVENTS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Volume,
    Denied,
    RarePort,
    HostMismatch,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub kind: Kind,
    pub ip: IpAddr,
    pub count: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    /// Lo último que ocurrió. No incluye sitios ni direcciones.
    pub detail: String,
}

/// Umbrales por IP y minuto. 0 desactiva esa regla.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub requests_per_minute: u64,
    pub bytes_per_minute: u64,
    pub denied_per_minute: u64,
}

/// Lo que hizo una IP en el minuto en curso. Cada regla avisa una sola vez por minuto.
#[derive(Default)]
struct Window {
    requests: u64,
    bytes: u64,
    denied: u64,
    requests_flagged: bool,
    bytes_flagged: bool,
    denied_flagged: bool,
}

#[derive(Default)]
struct State {
    minute: u64,
    window: HashMap<IpAddr, Window>,
    events: Vec<Event>,
}

impl State {
    fn note(&mut self, stats: &Stats, kind: Kind, ip: IpAddr, detail: String, at: u64) {
        Stats::inc(counter(stats, kind));
        if let Some(event) = self.events.iter_mut().find(|e| e.kind == kind && e.ip == ip) {
            event.count += 1;
            event.last_seen = at;
            event.detail = detail;
            return;
        }
        if self.events.len() >= MAX_EVENTS {
            if let Some(oldest) = (0..self.events.len()).min_by_key(|&i| self.events[i].last_seen) {
                self.events.swap_remove(oldest);
            }
        }
        self.events.push(Event { kind, ip, count: 1, first_seen: at, last_seen: at, detail });
    }
}

fn counter(stats: &Stats, kind: Kind) -> &AtomicU64 {
    match kind {
        Kind::Volume => &stats.detections_volume,
        Kind::Denied => &stats.detections_denied,
        Kind::RarePort => &stats.detections_rare_port,
        Kind::HostMismatch => &stats.detections_host_mismatch,
    }
}

pub struct Detector {
    enabled: bool,
    limits: Limits,
    stats: Arc<Stats>,
    state: Mutex<State>,
    security: Option<Arc<SecurityLog>>,
    bans: Option<Arc<BanList>>,
}

/// Qué tipos de aviso disparan un auto-bloqueo. El desajuste de Host solo avisa (nivel bajo).
fn block_reason(kind: Kind) -> Option<&'static str> {
    match kind {
        Kind::Denied => Some("denied"),
        Kind::Volume => Some("volume"),
        Kind::RarePort => Some("rare_port"),
        Kind::HostMismatch => None,
    }
}

impl Detector {
    pub fn new(enabled: bool, limits: Limits, stats: Arc<Stats>) -> Self {
        Self { enabled, limits, stats, state: Mutex::new(State::default()), security: None, bans: None }
    }

    /// Copia al log de seguridad los avisos que no se registran ya en otro sitio.
    pub fn with_security_log(mut self, security: Arc<SecurityLog>) -> Self {
        self.security = Some(security);
        self
    }

    /// Conecta la lista de auto-bloqueo: al marcar a una IP como abusiva, se la bloquea.
    pub fn with_ban_list(mut self, bans: Arc<BanList>) -> Self {
        self.bans = Some(bans);
        self
    }

    /// Libera los bloqueos vencidos. Lo llama el mantenimiento periódico.
    pub fn expire_bans(&self) {
        if let Some(bans) = &self.bans {
            bans.expire();
        }
    }

    fn try_block(&self, client: IpAddr, kind: Kind, detail: &str) {
        if let (Some(bans), Some(reason)) = (&self.bans, block_reason(kind)) {
            bans.block(client, reason, detail);
        }
    }

    fn log_security(&self, kind: Kind, ip: IpAddr, detail: &str) {
        let reason = match kind {
            Kind::Volume => "volume",
            Kind::Denied => "denied",
            Kind::HostMismatch => "host_mismatch",
            // El rechazo ya deja su evento, con el destino y el puerto.
            Kind::RarePort => return,
        };
        if let Some(security) = &self.security {
            security.record(SecurityEvent { event: "detection", srcip: Some(ip), reason: Some(reason), detail: Some(detail), ..Default::default() });
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Anota el resultado de una petición o conexión.
    pub fn observe(&self, client: IpAddr, status: Option<u16>, bytes: Option<u64>) {
        if self.enabled {
            self.observe_at(client.to_canonical(), status, bytes, now());
        }
    }

    fn observe_at(&self, client: IpAddr, status: Option<u16>, bytes: Option<u64>, at: u64) {
        let limits = self.limits;
        let mut guard = self.state.lock().expect("las detecciones no se envenenan");
        let state = &mut *guard;
        let minute = at / SECS_PER_MINUTE;
        if state.minute != minute {
            state.minute = minute;
            state.window.clear();
        }
        if state.window.len() >= MAX_TRACKED_CLIENTS && !state.window.contains_key(&client) {
            return;
        }
        let w = state.window.entry(client).or_default();
        w.requests += 1;
        w.bytes += bytes.unwrap_or(0);
        w.denied += u64::from(matches!(status, Some(403 | 404)));

        let mut found: Vec<(Kind, String)> = Vec::new();
        if limits.requests_per_minute > 0 && w.requests >= limits.requests_per_minute && !w.requests_flagged {
            w.requests_flagged = true;
            found.push((Kind::Volume, format!("Al menos {} peticiones en un minuto.", limits.requests_per_minute)));
        }
        if limits.bytes_per_minute > 0 && w.bytes >= limits.bytes_per_minute && !w.bytes_flagged {
            w.bytes_flagged = true;
            found.push((Kind::Volume, format!("Al menos {} en un minuto, sin contar túneles.", format_bytes(limits.bytes_per_minute))));
        }
        if limits.denied_per_minute > 0 && w.denied >= limits.denied_per_minute && !w.denied_flagged {
            w.denied_flagged = true;
            found.push((Kind::Denied, format!("Al menos {} respuestas 403 o 404 en un minuto.", limits.denied_per_minute)));
        }
        for (kind, detail) in found {
            self.log_security(kind, client, &detail);
            self.try_block(client, kind, &detail);
            state.note(&self.stats, kind, client, detail, at);
        }
    }

    /// Un túnel a un puerto que no está en `allowed_connect_ports`.
    pub fn rare_port(&self, client: IpAddr, port: u16) {
        self.report(client, Kind::RarePort, format!("Último puerto pedido: {port}."));
    }

    /// El nombre declarado no coincide con el destino real. Se indica cuál, pero no los nombres.
    pub fn host_mismatch(&self, client: IpAddr, detail: &str) {
        self.report(client, Kind::HostMismatch, detail.to_owned());
    }

    fn report(&self, client: IpAddr, kind: Kind, detail: String) {
        if self.enabled {
            self.log_security(kind, client.to_canonical(), &detail);
            self.try_block(client.to_canonical(), kind, &detail);
            let mut state = self.state.lock().expect("las detecciones no se envenenan");
            state.note(&self.stats, kind, client.to_canonical(), detail, now());
        }
    }

    pub fn forget_old(&self) {
        let oldest = now().saturating_sub(FORGET_AFTER_SECS);
        self.state.lock().expect("las detecciones no se envenenan").events.retain(|e| e.last_seen >= oldest);
    }

    /// Lo más reciente primero.
    pub fn events(&self) -> Vec<Event> {
        let mut events = self.state.lock().expect("las detecciones no se envenenan").events.clone();
        events.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.ip.cmp(&b.ip)));
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering::Relaxed;

    const LIMITS: Limits = Limits { requests_per_minute: 3, bytes_per_minute: 1000, denied_per_minute: 2 };
    const T: u64 = 6000;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn detector(enabled: bool) -> Detector {
        Detector::new(enabled, LIMITS, Arc::new(Stats::default()))
    }

    fn summary(d: &Detector) -> Vec<(Kind, u64)> {
        d.events().iter().map(|e| (e.kind, e.count)).collect()
    }

    #[test]
    fn apagado_no_guarda_nada_ni_cuenta() {
        let d = detector(false);
        for _ in 0..10 {
            d.observe(ip("10.0.0.1"), Some(403), Some(5000));
        }
        d.rare_port(ip("10.0.0.1"), 25);
        d.host_mismatch(ip("10.0.0.1"), "x");
        assert!(d.events().is_empty());
        assert_eq!(d.stats.detections_rare_port.load(Relaxed), 0);
    }

    #[test]
    fn por_debajo_del_umbral_no_avisa() {
        let d = detector(true);
        d.observe_at(ip("10.0.0.1"), Some(200), Some(10), T);
        d.observe_at(ip("10.0.0.1"), Some(404), Some(10), T);
        assert!(d.events().is_empty());
    }

    #[test]
    fn cada_regla_avisa_una_vez_por_minuto() {
        let d = detector(true);
        for _ in 0..10 {
            d.observe_at(ip("10.0.0.1"), Some(200), Some(1), T);
        }
        assert_eq!(summary(&d), [(Kind::Volume, 1)]);
        assert!(d.events()[0].detail.contains("3 peticiones"));

        for _ in 0..10 {
            d.observe_at(ip("10.0.0.1"), Some(200), Some(1), T + SECS_PER_MINUTE);
        }
        assert_eq!(summary(&d), [(Kind::Volume, 2)]);
        let event = &d.events()[0];
        assert_eq!((event.first_seen, event.last_seen), (T, T + SECS_PER_MINUTE));
        assert_eq!(d.stats.detections_volume.load(Relaxed), 2);
    }

    #[test]
    fn avisa_por_bytes_aunque_sean_pocas_peticiones() {
        let d = detector(true);
        d.observe_at(ip("10.0.0.1"), Some(200), Some(1000), T);
        assert_eq!(summary(&d), [(Kind::Volume, 1)]);
        assert!(d.events()[0].detail.contains("sin contar túneles"));
    }

    #[test]
    fn un_pico_de_rechazos_no_incluye_otros_errores() {
        let d = detector(true);
        d.observe_at(ip("10.0.0.1"), Some(500), None, T);
        d.observe_at(ip("10.0.0.2"), Some(403), None, T);
        d.observe_at(ip("10.0.0.2"), Some(404), None, T);
        assert_eq!(summary(&d), [(Kind::Denied, 1)]);
        assert_eq!(d.events()[0].ip, ip("10.0.0.2"));
    }

    #[test]
    fn las_ips_y_los_minutos_no_se_mezclan() {
        let d = detector(true);
        d.observe_at(ip("10.0.0.1"), None, None, T);
        d.observe_at(ip("10.0.0.2"), None, None, T);
        d.observe_at(ip("10.0.0.1"), None, None, T);
        d.observe_at(ip("10.0.0.1"), None, None, T + SECS_PER_MINUTE);
        assert!(d.events().is_empty());
    }

    #[test]
    fn un_umbral_en_cero_desactiva_esa_regla() {
        let limits = Limits { requests_per_minute: 0, bytes_per_minute: 0, denied_per_minute: 0 };
        let d = Detector::new(true, limits, Arc::new(Stats::default()));
        d.observe_at(ip("10.0.0.1"), Some(403), Some(u64::MAX / 2), T);
        assert!(d.events().is_empty());
    }

    #[test]
    fn agrupa_por_tipo_e_ip_con_ipv4_en_forma_canonica() {
        let d = detector(true);
        d.rare_port(ip("10.0.0.1"), 25);
        d.rare_port(ip("::ffff:10.0.0.1"), 6667);
        d.host_mismatch(ip("10.0.0.1"), "El Host no coincide con el destino.");
        let events = d.events();
        assert_eq!(events.len(), 2);
        let port = events.iter().find(|e| e.kind == Kind::RarePort).unwrap();
        assert_eq!((port.ip, port.count), (ip("10.0.0.1"), 2));
        assert!(port.detail.contains("6667"));
        assert_eq!(d.stats.detections_rare_port.load(Relaxed), 2);
        assert_eq!(d.stats.detections_host_mismatch.load(Relaxed), 1);
    }

    #[test]
    fn la_memoria_tiene_tope() {
        let d = detector(true);
        for n in 0..(MAX_EVENTS as u32 + 10) {
            d.rare_port(IpAddr::V4(n.into()), 25);
        }
        assert_eq!(d.events().len(), MAX_EVENTS);

        let d = Detector::new(true, Limits { requests_per_minute: 1, bytes_per_minute: 0, denied_per_minute: 0 }, Arc::new(Stats::default()));
        for n in 0..(MAX_TRACKED_CLIENTS as u32 + 10) {
            d.observe_at(IpAddr::V4(n.into()), None, None, T);
        }
        assert_eq!(d.state.lock().unwrap().window.len(), MAX_TRACKED_CLIENTS);
        // Al cambiar de minuto se vacía: los clientes que no cupieron vuelven a contarse.
        d.observe_at(IpAddr::V4(u32::MAX.into()), None, None, T + SECS_PER_MINUTE);
        assert_eq!(d.state.lock().unwrap().window.len(), 1);
    }

    #[test]
    fn olvida_lo_antiguo_y_ordena_por_lo_mas_reciente() {
        let d = detector(true);
        d.rare_port(ip("10.0.0.1"), 25);
        d.rare_port(ip("10.0.0.2"), 25);
        {
            let mut state = d.state.lock().unwrap();
            let old = state.events.iter_mut().find(|e| e.ip == ip("10.0.0.1")).unwrap();
            old.last_seen = 0;
        }
        assert_eq!(d.events()[0].ip, ip("10.0.0.2"));
        d.forget_old();
        assert_eq!(d.events().len(), 1);
        assert_eq!(d.events()[0].ip, ip("10.0.0.2"));
    }
}
