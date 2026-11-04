//! Registro en vivo y gráfica de tráfico del panel.
//!
//! El registro muestra qué dominios pide cada equipo, por eso viene apagado y el aviso indica si está
//! activo. Vive solo en memoria, guarda las últimas peticiones, se olvida tras un día o al reiniciar y
//! solo se ve con el token. Anota lo mismo que el log de acceso: nunca parámetros, cookies ni cuerpos.
//! Si cambia lo que se guarda aquí, hay que actualizar notice.rs y docs/AVISO.md.
//!
//! La gráfica solo usa los totales generales: no contiene nada por persona.

use crate::access_log::{clip, Pseudonyms, Record, SECS_PER_DAY};
use crate::config::LiveClientMode;
use crate::stats::Stats;
use crate::store::now;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_ENTRIES: usize = 1000;
const FORGET_AFTER_SECS: u64 = SECS_PER_DAY;
const SAMPLE_SECS: u64 = 3;
/// Cinco minutos de historia.
const MAX_POINTS: usize = 100;

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub ts: u64,
    pub client: Option<String>,
    pub method: String,
    pub host: String,
    pub port: Option<u16>,
    pub path: Option<String>,
    pub result: &'static str,
    pub status: Option<u16>,
    pub bytes: Option<u64>,
    pub ms: u64,
}

pub struct LiveLog {
    enabled: bool,
    mode: LiveClientMode,
    pseudonyms: Pseudonyms,
    entries: Mutex<VecDeque<Entry>>,
}

impl LiveLog {
    pub fn new(enabled: bool, mode: LiveClientMode) -> Self {
        Self { enabled, mode, pseudonyms: Pseudonyms::new(), entries: Mutex::new(VecDeque::new()) }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn mode(&self) -> LiveClientMode {
        self.mode
    }

    pub fn record(&self, r: &Record<'_>) {
        if !self.enabled {
            return;
        }
        let ts = now();
        let client = match self.mode {
            LiveClientMode::Pseudonym => Some(self.pseudonyms.pseudonym(r.client, ts / SECS_PER_DAY)),
            LiveClientMode::Ip => Some(r.client.to_canonical().to_string()),
            LiveClientMode::None => None,
        };
        let entry = Entry {
            ts,
            client,
            method: clip(r.method).to_owned(),
            host: clip(r.host).to_owned(),
            port: r.port,
            path: r.path.filter(|_| r.outcome.is_public_copy()).map(|path| clip(path).to_owned()),
            result: r.outcome.label(),
            status: r.status,
            bytes: r.bytes,
            ms: r.elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
        };
        let mut entries = self.entries.lock().expect("el registro en vivo no se envenena");
        if entries.len() == MAX_ENTRIES {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Las más recientes primero.
    pub fn entries(&self) -> Vec<Entry> {
        self.entries.lock().expect("el registro en vivo no se envenena").iter().rev().cloned().collect()
    }

    fn forget_before(&self, oldest_kept: u64) {
        let mut entries = self.entries.lock().expect("el registro en vivo no se envenena");
        while entries.front().is_some_and(|entry| entry.ts < oldest_kept) {
            entries.pop_front();
        }
    }
}

/// Bytes por segundo durante un intervalo.
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub struct TrafficPoint {
    pub ts: u64,
    pub copy: f64,
    pub stored: f64,
    pub bypass: f64,
}

#[derive(Default)]
pub struct Traffic {
    points: Mutex<VecDeque<TrafficPoint>>,
}

impl Traffic {
    pub const INTERVAL_SECS: u64 = SAMPLE_SECS;
    pub const CAPACITY: usize = MAX_POINTS;

    pub fn points(&self) -> Vec<TrafficPoint> {
        self.points.lock().expect("la gráfica no se envenena").iter().copied().collect()
    }

    fn push(&self, point: TrafficPoint) {
        let mut points = self.points.lock().expect("la gráfica no se envenena");
        if points.len() == MAX_POINTS {
            points.pop_front();
        }
        points.push_back(point);
    }
}

fn totals(stats: &Stats) -> [u64; 3] {
    [&stats.bytes_from_cache, &stats.bytes_from_origin, &stats.bytes_bypass].map(|counter| counter.load(Ordering::Relaxed))
}

fn point(ts: u64, before: [u64; 3], after: [u64; 3], secs: f64) -> TrafficPoint {
    let rate = |i: usize| after[i].saturating_sub(before[i]) as f64 / secs;
    TrafficPoint { ts, copy: rate(0), stored: rate(1), bypass: rate(2) }
}

/// Toma las muestras de la gráfica y olvida lo viejo del registro. Los contadores restaurados del
/// disco quedan fuera porque la primera muestra solo sirve de punto de partida.
pub fn start(stats: Arc<Stats>, live: Arc<LiveLog>, traffic: Arc<Traffic>) {
    tokio::spawn(async move {
        let mut before = totals(&stats);
        let mut last = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_secs(SAMPLE_SECS));
        tick.tick().await;
        loop {
            tick.tick().await;
            let after = totals(&stats);
            let secs = last.elapsed().as_secs_f64().max(0.001);
            traffic.push(point(now(), before, after, secs));
            before = after;
            last = Instant::now();
            live.forget_before(now().saturating_sub(FORGET_AFTER_SECS));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::Outcome;

    fn record(outcome: Outcome) -> Record<'static> {
        Record {
            client: "::ffff:192.168.1.10".parse().unwrap(),
            method: "GET",
            scheme: Some("https"),
            host: "cdn.example.com",
            port: None,
            path: Some("/a.js"),
            outcome,
            status: Some(200),
            bytes: Some(10),
            elapsed: Duration::from_millis(3),
        }
    }

    #[test]
    fn apagado_no_guarda_nada() {
        let live = LiveLog::new(false, LiveClientMode::Ip);
        live.record(&record(Outcome::Hit));
        assert!(live.entries().is_empty());
    }

    #[test]
    fn muestra_primero_lo_mas_reciente_y_tiene_tope() {
        let live = LiveLog::new(true, LiveClientMode::None);
        for n in 0..MAX_ENTRIES + 5 {
            let mut r = record(Outcome::Hit);
            r.bytes = Some(n as u64);
            live.record(&r);
        }
        let entries = live.entries();
        assert_eq!(entries.len(), MAX_ENTRIES);
        assert_eq!(entries[0].bytes, Some((MAX_ENTRIES + 4) as u64));
    }

    #[test]
    fn la_ruta_solo_sale_en_contenido_publico() {
        let live = LiveLog::new(true, LiveClientMode::None);
        live.record(&record(Outcome::Bypass));
        live.record(&record(Outcome::Miss));
        let entries = live.entries();
        assert_eq!(entries[0].path.as_deref(), Some("/a.js"));
        assert_eq!(entries[1].path, None);
    }

    #[test]
    fn el_cliente_se_muestra_segun_el_modo() {
        let shown = |mode| {
            let live = LiveLog::new(true, mode);
            live.record(&record(Outcome::Hit));
            live.entries()[0].client.clone()
        };
        assert_eq!(shown(LiveClientMode::Ip).as_deref(), Some("192.168.1.10"));
        assert_eq!(shown(LiveClientMode::None), None);
        let pseudonym = shown(LiveClientMode::Pseudonym).unwrap();
        assert_eq!(pseudonym.len(), 16);
        assert!(!pseudonym.contains("192"));
    }

    #[test]
    fn olvida_lo_viejo() {
        let live = LiveLog::new(true, LiveClientMode::None);
        live.record(&record(Outcome::Hit));
        live.forget_before(now().saturating_sub(100));
        assert_eq!(live.entries().len(), 1);
        live.forget_before(now() + 100);
        assert!(live.entries().is_empty());
    }

    #[test]
    fn calcula_el_trafico_por_segundo() {
        let p = point(7, [100, 0, 50], [400, 30, 50], 3.0);
        assert_eq!(p, TrafficPoint { ts: 7, copy: 100.0, stored: 10.0, bypass: 0.0 });
        assert_eq!(point(7, [100, 0, 0], [0, 0, 0], 1.0).copy, 0.0, "un contador nunca resta");
    }

    #[test]
    fn la_grafica_tiene_tope() {
        let traffic = Traffic::default();
        for n in 0..MAX_POINTS + 3 {
            traffic.push(TrafficPoint { ts: n as u64, copy: 0.0, stored: 0.0, bypass: 0.0 });
        }
        let points = traffic.points();
        assert_eq!(points.len(), MAX_POINTS);
        assert_eq!(points[0].ts, 3);
    }
}
