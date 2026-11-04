//! Mantenimiento periódico: guarda los contadores, mide el volumen y evalúa las alertas.
//!
//! Las alertas se ven en el panel y en /metrics, y dejan una línea en el registro al activarse y
//! al apagarse. El proxy no envía avisos a ninguna parte: para eso está Prometheus.

use crate::clients::ClientStats;
use crate::config::Config;
use crate::detect::Detector;
use crate::stats::Stats;
use crate::store::{disk_space, now, write_atomic};
use serde::Serialize;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const STATS_FILE: &str = "stats.json";
/// Las alertas por errores miran las últimas 5 pasadas: con el intervalo por defecto, 5 minutos.
const WINDOW_TICKS: usize = 5;
/// Con menos peticiones que estas, un porcentaje de errores no dice nada.
const MIN_REQUESTS_FOR_RATE: u64 = 10;
const SECS_PER_DAY: i64 = 86_400;

pub const ALERT_NAMES: [&str; 7] = ["disk_space", "disk_limit", "ca_expiry", "origin_errors", "corrupt_objects", "store_writes", "detections"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alert {
    pub name: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    pub disk_free_percent: u64,
    pub ca_days: u64,
    pub origin_error_percent: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Sample {
    /// Peticiones terminadas, no iniciadas: los errores también se cuentan al terminar. Si no,
    /// un origen lento dejaría los errores en una ventana distinta a la de sus peticiones.
    finished: u64,
    origin_errors: u64,
    corrupt_objects: u64,
    store_write_errors: u64,
    detections: u64,
}

impl Sample {
    fn read(stats: &Stats) -> Self {
        Self {
            finished: [&stats.hits, &stats.misses, &stats.revalidated, &stats.bypass, &stats.origin_errors, &stats.cache_errors]
                .iter()
                .map(|counter| counter.load(Relaxed))
                .sum(),
            origin_errors: stats.origin_errors.load(Relaxed),
            corrupt_objects: stats.corrupt_objects.load(Relaxed),
            store_write_errors: stats.store_write_errors.load(Relaxed),
            detections: stats.detections_total(),
        }
    }

    fn since(self, earlier: Self) -> Self {
        Self {
            finished: self.finished.saturating_sub(earlier.finished),
            origin_errors: self.origin_errors.saturating_sub(earlier.origin_errors),
            corrupt_objects: self.corrupt_objects.saturating_sub(earlier.corrupt_objects),
            store_write_errors: self.store_write_errors.saturating_sub(earlier.store_write_errors),
            detections: self.detections.saturating_sub(earlier.detections),
        }
    }
}

struct Inputs {
    /// Espacio disponible y total del volumen, si se pudo medir.
    volume: Option<(u64, u64)>,
    used_bytes: u64,
    limit_bytes: u64,
    ca_not_after: i64,
    now: i64,
    recent: Sample,
}

pub fn format_bytes(bytes: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    let value = bytes as f64;
    if value >= GIB {
        format!("{:.1} GiB", value / GIB).replace('.', ",")
    } else {
        format!("{:.0} MiB", value / MIB)
    }
}

/// Una caché llena frente a su límite es lo normal con LRU, así que no es una alerta. Lo que sí
/// importa es que se agote el volumen, o que la caché siga creciendo porque no se puede borrar.
fn evaluate(i: &Inputs, t: &Thresholds) -> Vec<Alert> {
    let mut alerts = Vec::new();
    let mut add = |name, message| alerts.push(Alert { name, message });

    if let Some((free, total)) = i.volume {
        if total > 0 && free.saturating_mul(100) / total < t.disk_free_percent {
            add("disk_space", format!("Quedan {} libres en el volumen de la caché, de {}.", format_bytes(free), format_bytes(total)));
        }
    }
    // El margen evita avisar por el instante entre guardar un objeto y expulsar otro.
    if i.limit_bytes > 0 && i.used_bytes > i.limit_bytes.saturating_add(i.limit_bytes / 10) {
        add(
            "disk_limit",
            format!("La caché ocupa {}, más que su límite de {}: no se están pudiendo borrar copias.", format_bytes(i.used_bytes), format_bytes(i.limit_bytes)),
        );
    }
    let days_left = i.ca_not_after.saturating_sub(i.now).div_euclid(SECS_PER_DAY);
    if days_left < 0 {
        add("ca_expiry", "La CA ya venció: los dominios interceptados darán error. Genera otra e instálala en los dispositivos.".to_owned());
    } else if days_left <= i64::try_from(t.ca_days).unwrap_or(i64::MAX) {
        add("ca_expiry", format!("La CA vence en {days_left} días. Genera otra e instálala en los dispositivos antes de esa fecha."));
    }
    let r = i.recent;
    if r.finished >= MIN_REQUESTS_FOR_RATE && r.origin_errors.saturating_mul(100) >= r.finished.saturating_mul(t.origin_error_percent) {
        add("origin_errors", format!("{} de las últimas {} peticiones no pudieron contactar al origen.", r.origin_errors, r.finished));
    }
    if r.corrupt_objects > 0 {
        add("corrupt_objects", format!("Se descartaron {} objetos corruptos en los últimos minutos: puede estar fallando el disco.", r.corrupt_objects));
    }
    if r.store_write_errors > 0 {
        add("store_writes", format!("{} respuestas no se pudieron guardar en los últimos minutos. Revisa el disco y los permisos.", r.store_write_errors));
    }
    // El mensaje queda en el registro, que puede guardarse: la IP solo se ve en el panel.
    if r.detections > 0 {
        add("detections", format!("{} avisos de actividad inusual en los últimos minutos. El detalle está en el panel.", r.detections));
    }
    alerts
}

pub struct Monitor {
    alerts: Mutex<Vec<Alert>>,
    ca_not_after: i64,
}

impl Monitor {
    pub fn new(ca_not_after: i64) -> Self {
        Self { alerts: Mutex::new(Vec::new()), ca_not_after }
    }

    pub fn ca_not_after(&self) -> i64 {
        self.ca_not_after
    }

    pub fn active(&self) -> Vec<Alert> {
        self.alerts.lock().expect("las alertas no se envenenan").clone()
    }

    pub fn prometheus(&self) -> String {
        let active = self.active();
        let mut out = String::from("# HELP rayo_alert 1 si la alerta está activa.\n# TYPE rayo_alert gauge\n");
        for name in ALERT_NAMES {
            let on = u8::from(active.iter().any(|a| a.name == name));
            let _ = writeln!(out, "rayo_alert{{name=\"{name}\"}} {on}");
        }
        let _ = writeln!(out, "# HELP rayo_ca_not_after_seconds Fecha de vencimiento de la CA.\n# TYPE rayo_ca_not_after_seconds gauge");
        let _ = writeln!(out, "rayo_ca_not_after_seconds {}", self.ca_not_after);
        out
    }

    /// Guarda las alertas nuevas y deja constancia en el registro de lo que cambió.
    fn update(&self, current: Vec<Alert>) {
        let mut alerts = self.alerts.lock().expect("las alertas no se envenenan");
        for alert in &current {
            if !alerts.iter().any(|a| a.name == alert.name) {
                tracing::warn!(alerta = alert.name, "{}", alert.message);
            }
        }
        for old in alerts.iter() {
            if !current.iter().any(|a| a.name == old.name) {
                tracing::info!(alerta = old.name, "alerta resuelta");
            }
        }
        *alerts = current;
    }
}

fn stats_path(data_dir: &Path) -> PathBuf {
    data_dir.join(STATS_FILE)
}

/// Recupera los contadores guardados. Un archivo dañado no impide arrancar: se empieza de cero.
pub async fn restore_stats(data_dir: &Path, stats: &Stats) {
    match tokio::fs::read_to_string(stats_path(data_dir)).await {
        Ok(text) => {
            if let Err(e) = stats.restore(&text) {
                tracing::warn!(error = %e, "no se pudieron recuperar los contadores: empiezan de cero");
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(error = %e, "no se pudieron leer los contadores: empiezan de cero"),
    }
    stats.mark_started();
}

pub async fn save_stats(data_dir: &Path, stats: &Stats) {
    if let Err(e) = write_atomic(&stats_path(data_dir), stats.saved_json().as_bytes()).await {
        tracing::warn!(error = %e, "no se pudieron guardar los contadores");
    }
}

/// Lanza la pasada periódica.
pub fn start(cfg: &Config, stats: Arc<Stats>, clients: Arc<ClientStats>, detector: Arc<Detector>, monitor: Arc<Monitor>) {
    let data_dir = cfg.data_dir.clone();
    let every = Duration::from_secs(cfg.maintenance_interval_secs.max(1));
    let thresholds = Thresholds {
        disk_free_percent: cfg.alert_disk_free_percent,
        ca_days: cfg.alert_ca_days,
        origin_error_percent: cfg.alert_origin_error_percent,
    };
    tokio::spawn(async move {
        let mut history: VecDeque<Sample> = VecDeque::with_capacity(WINDOW_TICKS + 1);
        let mut tick = tokio::time::interval(every);
        loop {
            tick.tick().await;
            let dir = data_dir.clone();
            let volume = tokio::task::spawn_blocking(move || disk_space(&dir)).await.ok().flatten();
            if let Some((free, total)) = volume {
                stats.disk_free_bytes.store(free, Relaxed);
                stats.disk_total_bytes.store(total, Relaxed);
            }
            let sample = Sample::read(&stats);
            if history.len() > WINDOW_TICKS {
                history.pop_front();
            }
            history.push_back(sample);
            let inputs = Inputs {
                volume,
                used_bytes: stats.disk_used_bytes.load(Relaxed),
                limit_bytes: stats.disk_limit_bytes.load(Relaxed),
                ca_not_after: monitor.ca_not_after,
                now: i64::try_from(now()).unwrap_or(i64::MAX),
                recent: sample.since(history.front().copied().unwrap_or(sample)),
            };
            monitor.update(evaluate(&inputs, &thresholds));
            clients.forget_idle();
            detector.forget_old();
            save_stats(&data_dir, &stats).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;
    const THRESHOLDS: Thresholds = Thresholds { disk_free_percent: 10, ca_days: 30, origin_error_percent: 20 };

    fn calm() -> Inputs {
        Inputs {
            volume: Some((50 * GIB, 100 * GIB)),
            used_bytes: 10 * GIB,
            limit_bytes: 10 * GIB,
            ca_not_after: 1000 * SECS_PER_DAY,
            now: 0,
            recent: Sample::default(),
        }
    }

    fn names(i: &Inputs) -> Vec<&'static str> {
        evaluate(i, &THRESHOLDS).iter().map(|a| a.name).collect()
    }

    #[test]
    fn una_cache_llena_frente_a_su_limite_no_es_una_alerta() {
        assert!(names(&calm()).is_empty());
    }

    #[test]
    fn avisa_si_se_agota_el_volumen() {
        let low = Inputs { volume: Some((9 * GIB, 100 * GIB)), ..calm() };
        assert_eq!(names(&low), ["disk_space"]);
        assert!(evaluate(&low, &THRESHOLDS)[0].message.contains("9,0 GiB"));
        assert!(names(&Inputs { volume: Some((10 * GIB, 100 * GIB)), ..calm() }).is_empty());
        assert!(names(&Inputs { volume: None, ..calm() }).is_empty());
    }

    #[test]
    fn avisa_si_la_cache_no_deja_de_crecer() {
        assert_eq!(names(&Inputs { used_bytes: 12 * GIB, ..calm() }), ["disk_limit"]);
        assert!(names(&Inputs { used_bytes: 12 * GIB, limit_bytes: 0, ..calm() }).is_empty());
    }

    #[test]
    fn avisa_antes_de_que_venza_la_ca() {
        let at = |days: i64| Inputs { ca_not_after: days * SECS_PER_DAY, ..calm() };
        assert!(names(&at(31)).is_empty());
        assert_eq!(names(&at(30)), ["ca_expiry"]);
        assert!(evaluate(&at(30), &THRESHOLDS)[0].message.contains("30 días"));
        assert_eq!(names(&Inputs { ca_not_after: -1, ..calm() }), ["ca_expiry"]);
        assert!(evaluate(&Inputs { ca_not_after: -1, ..calm() }, &THRESHOLDS)[0].message.contains("ya venció"));
    }

    #[test]
    fn los_errores_del_origen_son_una_proporcion_con_un_minimo() {
        let at = |finished, origin_errors| Inputs { recent: Sample { finished, origin_errors, ..Sample::default() }, ..calm() };
        assert!(names(&at(9, 9)).is_empty(), "muy pocas peticiones");
        assert!(names(&at(100, 19)).is_empty());
        assert_eq!(names(&at(100, 20)), ["origin_errors"]);
    }

    #[test]
    fn un_objeto_corrupto_o_un_fallo_de_escritura_avisan_de_inmediato() {
        let recent = Sample { corrupt_objects: 1, store_write_errors: 2, ..Sample::default() };
        assert_eq!(names(&Inputs { recent, ..calm() }), ["corrupt_objects", "store_writes"]);
    }

    #[test]
    fn una_deteccion_avisa_sin_decir_que_ip_fue() {
        let recent = Sample { detections: 2, ..Sample::default() };
        let inputs = Inputs { recent, ..calm() };
        assert_eq!(names(&inputs), ["detections"]);
        let message = &evaluate(&inputs, &THRESHOLDS)[0].message;
        assert!(message.contains("2 avisos") && message.contains("panel"));
    }

    #[test]
    fn las_metricas_incluyen_todas_las_alertas() {
        let monitor = Monitor::new(123);
        monitor.update(vec![Alert { name: "ca_expiry", message: "x".into() }]);
        let text = monitor.prometheus();
        assert!(text.contains("rayo_alert{name=\"ca_expiry\"} 1\n"));
        assert!(text.contains("rayo_alert{name=\"disk_space\"} 0\n"));
        assert!(text.contains("rayo_ca_not_after_seconds 123\n"));
        monitor.update(vec![]);
        assert!(monitor.active().is_empty());
    }

    #[test]
    fn la_ventana_cuenta_solo_lo_ocurrido_desde_entonces() {
        let now = Sample { finished: 10, origin_errors: 5, corrupt_objects: 1, ..Sample::default() };
        let then = Sample { finished: 4, origin_errors: 5, ..Sample::default() };
        assert_eq!(now.since(then), Sample { finished: 6, corrupt_objects: 1, ..Sample::default() });
    }

    #[tokio::test]
    async fn los_contadores_sobreviven_a_un_reinicio() {
        let dir = std::env::temp_dir().join(format!("rayo-monitor-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let first = Stats::default();
        restore_stats(&dir, &first).await;
        Stats::add(&first.requests, 7);
        Stats::add(&first.bytes_from_cache, 1000);
        save_stats(&dir, &first).await;

        let second = Stats::default();
        restore_stats(&dir, &second).await;
        assert_eq!(second.requests.load(Relaxed), 7);
        assert_eq!(second.bytes_from_cache.load(Relaxed), 1000);
        assert_eq!(second.since.load(Relaxed), first.since.load(Relaxed));

        std::fs::write(stats_path(&dir), "{dañado").unwrap();
        let third = Stats::default();
        restore_stats(&dir, &third).await;
        assert_eq!(third.requests.load(Relaxed), 0);
        assert!(third.since.load(Relaxed) > 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
