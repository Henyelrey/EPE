//! Log de eventos de seguridad, pensado para que lo lea un SIEM como Wazuh. Apagado por defecto.
//!
//! Solo anota lo anómalo: rechazos, intentos de token fallidos, detecciones y alertas. La navegación
//! normal no pasa por aquí. Incluye la IP real, porque sin ella un SIEM no puede correlacionar un ataque,
//! y por eso el aviso a los usuarios indica si está activo. Nunca incluye tokens, parámetros ni cuerpos.
//!
//! Escribir nunca retrasa una petición, y un atacante no puede llenar el disco a base de rechazos: cada
//! tipo de evento de cada IP tiene un tope por minuto. Si cambia lo que se anota aquí, hay que actualizar
//! notice.rs y docs/AVISO.md.

use crate::access_log::{clip, start_writer, timestamp};
use crate::config::Config;
use crate::stats::Stats;
use crate::store::now;
use anyhow::bail;
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

const FILE_PREFIX: &str = "security";
const MAX_PER_MINUTE: u32 = 120;
const MAX_TRACKED_KEYS: usize = 4096;
const SECS_PER_MINUTE: u64 = 60;

/// Lo que se sabe de un evento. Solo `event` es obligatorio.
#[derive(Default)]
pub struct SecurityEvent<'a> {
    pub event: &'static str,
    pub srcip: Option<IpAddr>,
    pub dstip: Option<IpAddr>,
    pub host: Option<&'a str>,
    pub port: Option<u16>,
    pub path: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub detail: Option<&'a str>,
}

#[derive(Serialize)]
struct Line<'a> {
    app: &'static str,
    ts: String,
    event: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    srcip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dstip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<&'a str>,
    /// No puede llamarse `port`: en el índice de Wazuh ese campo es un objeto y rechazaría la alerta.
    #[serde(skip_serializing_if = "Option::is_none")]
    dstport: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
}

/// Cuántas líneas lleva cada tipo de evento de cada IP en el minuto en curso.
#[derive(Default)]
struct Throttle {
    minute: u64,
    counts: HashMap<(&'static str, Option<IpAddr>), u32>,
}

enum Verdict {
    Write,
    /// Esta línea llega al tope: se escribe y se avisa de que las siguientes se descartan.
    WriteLast,
    Drop,
}

impl Throttle {
    fn check(&mut self, event: &'static str, srcip: Option<IpAddr>, at: u64) -> Verdict {
        let minute = at / SECS_PER_MINUTE;
        if self.minute != minute {
            self.minute = minute;
            self.counts.clear();
        }
        if self.counts.len() >= MAX_TRACKED_KEYS && !self.counts.contains_key(&(event, srcip)) {
            return Verdict::Drop;
        }
        let count = self.counts.entry((event, srcip)).or_default();
        *count = count.saturating_add(1);
        match (*count).cmp(&MAX_PER_MINUTE) {
            std::cmp::Ordering::Less => Verdict::Write,
            std::cmp::Ordering::Equal => Verdict::WriteLast,
            std::cmp::Ordering::Greater => Verdict::Drop,
        }
    }
}

pub struct SecurityLog {
    queue: Option<mpsc::Sender<String>>,
    stats: Arc<Stats>,
    throttle: Mutex<Throttle>,
}

impl SecurityLog {
    pub fn start(cfg: &Config, stats: Arc<Stats>) -> anyhow::Result<Self> {
        if !cfg.security_log_enabled {
            return Ok(Self::disabled(stats));
        }
        if cfg.security_log_retention_days == 0 {
            bail!("security_log_retention_days debe ser al menos 1");
        }
        let queue = start_writer(&cfg.security_log_dir, FILE_PREFIX, cfg.security_log_retention_days, stats.clone())?;
        Ok(Self { queue: Some(queue), stats, throttle: Mutex::new(Throttle::default()) })
    }

    pub fn disabled(stats: Arc<Stats>) -> Self {
        Self { queue: None, stats, throttle: Mutex::new(Throttle::default()) }
    }

    pub fn record(&self, e: SecurityEvent<'_>) {
        if self.queue.is_none() {
            return;
        }
        let secs = now();
        let srcip = e.srcip.map(|ip| ip.to_canonical());
        let verdict = self.throttle.lock().expect("el tope de eventos no se envenena").check(e.event, srcip, secs);
        if matches!(verdict, Verdict::Drop) {
            Stats::inc(&self.stats.access_log_dropped);
            return;
        }
        self.write(&Line {
            app: "rayo-cache",
            ts: timestamp(secs),
            event: e.event,
            srcip,
            dstip: e.dstip.map(|ip| ip.to_canonical()),
            host: e.host.map(clip),
            dstport: e.port,
            path: e.path.map(clip),
            reason: e.reason.map(clip),
            detail: e.detail.map(clip),
        });
        if matches!(verdict, Verdict::WriteLast) {
            self.write(&Line {
                app: "rayo-cache",
                ts: timestamp(secs),
                event: "security_log_throttled",
                srcip,
                dstip: None,
                host: None,
                dstport: None,
                path: None,
                reason: Some(e.event),
                detail: Some("Se alcanzó el tope por minuto: las líneas siguientes de este evento se descartan."),
            });
        }
    }

    fn write(&self, line: &Line<'_>) {
        let Some(queue) = &self.queue else {
            return;
        };
        let Ok(mut text) = serde_json::to_string(line) else {
            return;
        };
        text.push('\n');
        if queue.try_send(text).is_err() {
            Stats::inc(&self.stats.access_log_dropped);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_log::SECS_PER_DAY;
    use std::time::Duration;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn el_tope_es_por_evento_e_ip_y_se_reinicia_cada_minuto() {
        let mut t = Throttle::default();
        let a = Some(ip("10.0.0.1"));
        for _ in 1..MAX_PER_MINUTE {
            assert!(matches!(t.check("x", a, 60), Verdict::Write));
        }
        assert!(matches!(t.check("x", a, 61), Verdict::WriteLast));
        assert!(matches!(t.check("x", a, 62), Verdict::Drop));
        assert!(matches!(t.check("y", a, 62), Verdict::Write), "otro evento lleva su propia cuenta");
        assert!(matches!(t.check("x", Some(ip("10.0.0.2")), 62), Verdict::Write), "otra IP también");
        assert!(matches!(t.check("x", a, 120), Verdict::Write), "un minuto nuevo empieza de cero");
    }

    #[test]
    fn la_memoria_del_tope_esta_limitada() {
        let mut t = Throttle { minute: 1, ..Throttle::default() };
        for n in 0..MAX_TRACKED_KEYS {
            let addr = IpAddr::from(std::net::Ipv6Addr::from(n as u128));
            t.check("x", Some(addr), 60);
        }
        assert!(matches!(t.check("x", Some(ip("10.0.0.1")), 60), Verdict::Drop));
        assert_eq!(t.counts.len(), MAX_TRACKED_KEYS);
    }

    #[test]
    fn apagado_no_crea_nada() {
        let dir = std::env::temp_dir().join(format!("rayo-sec-off-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config { security_log_dir: dir.clone(), ..Config::default() };
        assert!(!cfg.security_log_enabled, "el log de seguridad debe venir apagado");
        SecurityLog::start(&cfg, Arc::new(Stats::default())).unwrap().record(SecurityEvent { event: "x", ..Default::default() });
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn escribe_json_con_lo_que_necesita_un_siem() {
        let dir = std::env::temp_dir().join(format!("rayo-sec-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config { security_log_enabled: true, security_log_dir: dir.clone(), ..Config::default() };
        let log = SecurityLog::start(&cfg, Arc::new(Stats::default())).unwrap();
        log.record(SecurityEvent {
            event: "port_blocked",
            srcip: Some(ip("::ffff:192.168.1.10")),
            host: Some("example.com"),
            port: Some(25),
            ..Default::default()
        });
        let path = dir.join(format!("security-{}.jsonl", crate::access_log::date_string(now() / SECS_PER_DAY)));
        let mut text = String::new();
        for _ in 0..100 {
            text = std::fs::read_to_string(&path).unwrap_or_default();
            if !text.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let line: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(line["app"], "rayo-cache");
        assert_eq!(line["event"], "port_blocked");
        assert_eq!(line["srcip"], "192.168.1.10");
        assert_eq!(line["dstport"], 25);
        assert!(line.get("detail").is_none(), "lo que no aplica no se escribe");
        drop(log);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
