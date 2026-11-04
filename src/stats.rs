//! Contadores en vivo, expuestos en http://rayo.stats/ y en /metrics del puerto de administración.
//! Se guardan en disco cada cierto tiempo, salvo los histogramas de latencia, que empiezan de cero al arrancar.
//!
//! Con el proxy sin peticiones en curso, se cumple:
//! requests = hits + misses + revalidated + bypass + origin_errors + cache_errors
//!
//! Los túneles en passthrough no entran en ninguno de estos contadores de bytes: Hudsucker no
//! expone cuántos bytes pasan por ellos, así que el ratio solo describe el tráfico descifrado o HTTP.

use serde::Serialize;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

/// Cómo terminó una petición o conexión.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Hit,
    Revalidated,
    Miss,
    Bypass,
    OriginError,
    CacheError,
    /// Destino interno rechazado. No cuenta como petición de contenido.
    Blocked,
    /// Túnel sin descifrar. No cuenta como petición de contenido.
    Tunnel,
}

impl Outcome {
    /// El contenido salió de una copia o se pudo guardar como una: según las reglas de caché, es público.
    /// En los demás casos la ruta podría ser personal, como un enlace para cambiar la contraseña.
    pub fn is_public_copy(self) -> bool {
        matches!(self, Outcome::Hit | Outcome::Revalidated | Outcome::Miss)
    }

    pub fn label(self) -> &'static str {
        match self {
            Outcome::Hit => "hit",
            Outcome::Revalidated => "revalidated",
            Outcome::Miss => "miss",
            Outcome::Bypass => "bypass",
            Outcome::OriginError => "origin_error",
            Outcome::CacheError => "cache_error",
            Outcome::Blocked => "blocked",
            Outcome::Tunnel => "tunnel",
        }
    }
}

/// Límites superiores de los tramos de latencia, en milisegundos.
const LATENCY_BUCKETS_MS: [u64; 12] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

/// Histograma de latencia. Cada tramo guarda sus propias muestras; la última posición es "más que todos".
#[derive(Default)]
pub struct Histogram {
    buckets: [AtomicU64; LATENCY_BUCKETS_MS.len() + 1],
    sum_micros: AtomicU64,
}

impl Histogram {
    fn observe(&self, elapsed: Duration) {
        let micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
        let index = LATENCY_BUCKETS_MS.iter().position(|ms| micros <= ms * 1000).unwrap_or(LATENCY_BUCKETS_MS.len());
        self.buckets[index].fetch_add(1, Relaxed);
        self.sum_micros.fetch_add(micros, Relaxed);
    }

    fn count(&self) -> u64 {
        self.buckets.iter().map(|b| b.load(Relaxed)).sum()
    }

    fn summary(&self) -> serde_json::Value {
        let count = self.count();
        let avg_ms = if count == 0 { 0.0 } else { self.sum_micros.load(Relaxed) as f64 / count as f64 / 1000.0 };
        serde_json::json!({ "count": count, "avg_ms": avg_ms })
    }

    fn write_prometheus(&self, out: &mut String, result: &str) {
        let mut cumulative = 0;
        for (i, ms) in LATENCY_BUCKETS_MS.iter().enumerate() {
            cumulative += self.buckets[i].load(Relaxed);
            let _ = writeln!(
                out,
                "rayo_request_duration_seconds_bucket{{result=\"{result}\",le=\"{}\"}} {cumulative}",
                *ms as f64 / 1000.0
            );
        }
        cumulative += self.buckets[LATENCY_BUCKETS_MS.len()].load(Relaxed);
        let _ = writeln!(out, "rayo_request_duration_seconds_bucket{{result=\"{result}\",le=\"+Inf\"}} {cumulative}");
        let _ = writeln!(out, "rayo_request_duration_seconds_sum{{result=\"{result}\"}} {}", self.sum_micros.load(Relaxed) as f64 / 1e6);
        let _ = writeln!(out, "rayo_request_duration_seconds_count{{result=\"{result}\"}} {cumulative}");
    }
}

#[derive(Default)]
pub struct Latency {
    pub hit: Histogram,
    pub revalidated: Histogram,
    pub miss: Histogram,
    pub bypass: Histogram,
    pub error: Histogram,
}

/// Instante de arranque; existe para que `Stats` pueda seguir creándose con `default()`.
struct StartedAt(Instant);

impl Default for StartedAt {
    fn default() -> Self {
        Self(Instant::now())
    }
}

#[derive(Default)]
pub struct Stats {
    started_at: StartedAt,
    pub requests: AtomicU64,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub revalidated: AtomicU64,
    pub bypass: AtomicU64,
    /// El origen no respondió o cortó el cuerpo.
    pub origin_errors: AtomicU64,
    /// El origen confirmó con 304 una copia que ya no se pudo leer del disco.
    pub cache_errors: AtomicU64,
    pub stored_new: AtomicU64,
    pub dedup: AtomicU64,
    pub bytes_from_cache: AtomicU64,
    pub bytes_from_origin: AtomicU64,
    pub bytes_bypass: AtomicU64,
    pub tls_intercepted: AtomicU64,
    pub tls_passthrough: AtomicU64,
    /// Rechazos antes de contar la petición: cliente no permitido, límite por IP y destino interno.
    pub denied_clients: AtomicU64,
    pub rate_limited: AtomicU64,
    pub blocked_destinations: AtomicU64,
    /// Túneles rechazados por pedir un puerto que no está en `allowed_connect_ports`.
    pub blocked_ports: AtomicU64,
    /// Avisos de actividad inusual por tipo. Sin IPs: esas solo están en memoria, en detect.rs.
    pub detections_volume: AtomicU64,
    pub detections_denied: AtomicU64,
    pub detections_rare_port: AtomicU64,
    pub detections_host_mismatch: AtomicU64,
    /// Peticiones atendidas sin caché porque no había memoria disponible.
    pub over_budget: AtomicU64,
    /// Peticiones que esperaron a otra igual en vez de ir al origen de inmediato.
    pub coalesced: AtomicU64,
    /// Objetos que no pasaron la verificación de integridad y se descartaron.
    pub corrupt_objects: AtomicU64,
    /// Respuestas que no se pudieron guardar en disco.
    pub store_write_errors: AtomicU64,
    /// Líneas del log de acceso perdidas porque el disco no daba abasto o falló la escritura.
    pub access_log_dropped: AtomicU64,
    pub access_log_errors: AtomicU64,
    /// Lo que ocupa la caché: bytes de objetos y metadatos, y cantidad de objetos.
    pub disk_used_bytes: AtomicU64,
    pub disk_objects: AtomicU64,
    pub disk_limit_bytes: AtomicU64,
    /// Última medición del volumen donde está la caché.
    pub disk_free_bytes: AtomicU64,
    pub disk_total_bytes: AtomicU64,
    /// Entradas y bytes expulsados por el límite de disco.
    pub evicted_entries: AtomicU64,
    pub evicted_bytes: AtomicU64,
    /// Fecha del primer arranque que empezó a sumar estos contadores.
    pub since: AtomicU64,
    pub latency: Latency,
}

/// Foto de los contadores. Lo que lleva `serde(skip)` no sale en http://rayo.stats/, que cualquier
/// página abierta en un navegador con el proxy puede pedir: solo se ve en /metrics, con token.
#[derive(Serialize)]
pub struct Snapshot {
    #[serde(skip)]
    uptime_secs: u64,
    requests: u64,
    hits: u64,
    misses: u64,
    revalidated_304: u64,
    bypass: u64,
    origin_errors: u64,
    cache_errors: u64,
    #[serde(skip)]
    request_hit_ratio: f64,
    stored_new_objects: u64,
    deduplicated_objects: u64,
    bytes_from_cache: u64,
    bytes_from_origin: u64,
    bytes_bypass: u64,
    byte_hit_ratio: f64,
    tls_intercepted: u64,
    tls_passthrough: u64,
    denied_clients: u64,
    rate_limited: u64,
    blocked_destinations: u64,
    #[serde(skip)]
    blocked_ports: u64,
    #[serde(skip)]
    detections_volume: u64,
    #[serde(skip)]
    detections_denied: u64,
    #[serde(skip)]
    detections_rare_port: u64,
    #[serde(skip)]
    detections_host_mismatch: u64,
    over_budget: u64,
    coalesced: u64,
    #[serde(skip)]
    corrupt_objects: u64,
    #[serde(skip)]
    store_write_errors: u64,
    #[serde(skip)]
    access_log_dropped: u64,
    #[serde(skip)]
    access_log_errors: u64,
    #[serde(skip)]
    disk_used_bytes: u64,
    #[serde(skip)]
    disk_objects: u64,
    #[serde(skip)]
    disk_limit_bytes: u64,
    #[serde(skip)]
    disk_free_bytes: u64,
    #[serde(skip)]
    disk_total_bytes: u64,
    #[serde(skip)]
    evicted_entries: u64,
    #[serde(skip)]
    evicted_bytes: u64,
    #[serde(skip)]
    since: u64,
}

fn ratio(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 / total as f64
    }
}

fn help_and_type(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// Métrica sin etiquetas.
fn single(out: &mut String, name: &str, kind: &str, help: &str, value: impl std::fmt::Display) {
    help_and_type(out, name, kind, help);
    let _ = writeln!(out, "{name} {value}");
}

/// Contador con una etiqueta que toma varios valores.
fn labeled(out: &mut String, name: &str, help: &str, label: &str, values: &[(&str, u64)]) {
    help_and_type(out, name, "counter", help);
    for (value, count) in values {
        let _ = writeln!(out, "{name}{{{label}=\"{value}\"}} {count}");
    }
}

impl Stats {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Relaxed);
    }
    pub fn add(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Relaxed);
    }

    /// Registra cuánto tardó la respuesta en estar lista. Bloqueos y túneles no tienen latencia propia.
    pub fn observe(&self, outcome: Outcome, elapsed: Duration) {
        let histogram = match outcome {
            Outcome::Hit => &self.latency.hit,
            Outcome::Revalidated => &self.latency.revalidated,
            Outcome::Miss => &self.latency.miss,
            Outcome::Bypass => &self.latency.bypass,
            Outcome::OriginError | Outcome::CacheError => &self.latency.error,
            Outcome::Blocked | Outcome::Tunnel => return,
        };
        histogram.observe(elapsed);
    }

    pub fn snapshot(&self) -> Snapshot {
        let cache = self.bytes_from_cache.load(Relaxed);
        let origin = self.bytes_from_origin.load(Relaxed);
        let bypass = self.bytes_bypass.load(Relaxed);
        let requests = self.requests.load(Relaxed);
        let hits = self.hits.load(Relaxed);
        let revalidated = self.revalidated.load(Relaxed);
        Snapshot {
            uptime_secs: self.started_at.0.elapsed().as_secs(),
            requests,
            hits,
            misses: self.misses.load(Relaxed),
            revalidated_304: revalidated,
            bypass: self.bypass.load(Relaxed),
            origin_errors: self.origin_errors.load(Relaxed),
            cache_errors: self.cache_errors.load(Relaxed),
            request_hit_ratio: ratio(hits + revalidated, requests),
            stored_new_objects: self.stored_new.load(Relaxed),
            deduplicated_objects: self.dedup.load(Relaxed),
            bytes_from_cache: cache,
            bytes_from_origin: origin,
            bytes_bypass: bypass,
            byte_hit_ratio: ratio(cache, cache + origin + bypass),
            tls_intercepted: self.tls_intercepted.load(Relaxed),
            tls_passthrough: self.tls_passthrough.load(Relaxed),
            denied_clients: self.denied_clients.load(Relaxed),
            rate_limited: self.rate_limited.load(Relaxed),
            blocked_destinations: self.blocked_destinations.load(Relaxed),
            blocked_ports: self.blocked_ports.load(Relaxed),
            detections_volume: self.detections_volume.load(Relaxed),
            detections_denied: self.detections_denied.load(Relaxed),
            detections_rare_port: self.detections_rare_port.load(Relaxed),
            detections_host_mismatch: self.detections_host_mismatch.load(Relaxed),
            over_budget: self.over_budget.load(Relaxed),
            coalesced: self.coalesced.load(Relaxed),
            corrupt_objects: self.corrupt_objects.load(Relaxed),
            store_write_errors: self.store_write_errors.load(Relaxed),
            access_log_dropped: self.access_log_dropped.load(Relaxed),
            access_log_errors: self.access_log_errors.load(Relaxed),
            disk_used_bytes: self.disk_used_bytes.load(Relaxed),
            disk_objects: self.disk_objects.load(Relaxed),
            disk_limit_bytes: self.disk_limit_bytes.load(Relaxed),
            disk_free_bytes: self.disk_free_bytes.load(Relaxed),
            disk_total_bytes: self.disk_total_bytes.load(Relaxed),
            evicted_entries: self.evicted_entries.load(Relaxed),
            evicted_bytes: self.evicted_bytes.load(Relaxed),
            since: self.since.load(Relaxed),
        }
    }

    /// Lo que se conserva entre reinicios. Las medidas del disco no: se vuelven a tomar al arrancar.
    fn persistent(&self) -> [(&'static str, &AtomicU64); 31] {
        [
            ("since", &self.since),
            ("requests", &self.requests),
            ("hits", &self.hits),
            ("misses", &self.misses),
            ("revalidated", &self.revalidated),
            ("bypass", &self.bypass),
            ("origin_errors", &self.origin_errors),
            ("cache_errors", &self.cache_errors),
            ("stored_new", &self.stored_new),
            ("dedup", &self.dedup),
            ("bytes_from_cache", &self.bytes_from_cache),
            ("bytes_from_origin", &self.bytes_from_origin),
            ("bytes_bypass", &self.bytes_bypass),
            ("tls_intercepted", &self.tls_intercepted),
            ("tls_passthrough", &self.tls_passthrough),
            ("denied_clients", &self.denied_clients),
            ("rate_limited", &self.rate_limited),
            ("blocked_destinations", &self.blocked_destinations),
            ("blocked_ports", &self.blocked_ports),
            ("detections_volume", &self.detections_volume),
            ("detections_denied", &self.detections_denied),
            ("detections_rare_port", &self.detections_rare_port),
            ("detections_host_mismatch", &self.detections_host_mismatch),
            ("over_budget", &self.over_budget),
            ("coalesced", &self.coalesced),
            ("corrupt_objects", &self.corrupt_objects),
            ("store_write_errors", &self.store_write_errors),
            ("access_log_dropped", &self.access_log_dropped),
            ("access_log_errors", &self.access_log_errors),
            ("evicted_entries", &self.evicted_entries),
            ("evicted_bytes", &self.evicted_bytes),
        ]
    }

    pub fn saved_json(&self) -> String {
        let values: std::collections::BTreeMap<&str, u64> = self.persistent().iter().map(|(name, value)| (*name, value.load(Relaxed))).collect();
        serde_json::to_string_pretty(&values).unwrap_or_default()
    }

    /// Recupera lo guardado. Un archivo dañado no cambia nada; un contador desconocido se ignora.
    pub fn restore(&self, text: &str) -> serde_json::Result<()> {
        let values: std::collections::HashMap<String, u64> = serde_json::from_str(text)?;
        for (name, counter) in self.persistent() {
            if let Some(value) = values.get(name) {
                counter.store(*value, Relaxed);
            }
        }
        Ok(())
    }

    pub fn detections_total(&self) -> u64 {
        [&self.detections_volume, &self.detections_denied, &self.detections_rare_port, &self.detections_host_mismatch]
            .iter()
            .map(|counter| counter.load(Relaxed))
            .sum()
    }

    /// Anota la fecha de inicio la primera vez que se empieza a contar.
    pub fn mark_started(&self) {
        let _ = self.since.compare_exchange(0, crate::store::now(), Relaxed, Relaxed);
    }

    /// Datos del panel. No incluye nada por cliente.
    pub fn panel_json(&self) -> serde_json::Value {
        let s = self.snapshot();
        serde_json::json!({
            "since": s.since,
            "uptime_secs": s.uptime_secs,
            "requests": s.requests,
            "request_hit_ratio": s.request_hit_ratio,
            "byte_hit_ratio": s.byte_hit_ratio,
            "results": {
                "hit": s.hits,
                "revalidated": s.revalidated_304,
                "miss": s.misses,
                "bypass": s.bypass,
                "origin_error": s.origin_errors,
                "cache_error": s.cache_errors,
            },
            "bytes": { "cache": s.bytes_from_cache, "origin": s.bytes_from_origin, "bypass": s.bytes_bypass },
            "latency": {
                "hit": self.latency.hit.summary(),
                "revalidated": self.latency.revalidated.summary(),
                "miss": self.latency.miss.summary(),
                "bypass": self.latency.bypass.summary(),
                "error": self.latency.error.summary(),
            },
            "disk": {
                "used": s.disk_used_bytes,
                "limit": s.disk_limit_bytes,
                "objects": s.disk_objects,
                "free": s.disk_free_bytes,
                "total": s.disk_total_bytes,
                "evicted_entries": s.evicted_entries,
                "evicted_bytes": s.evicted_bytes,
            },
            "tls": { "intercepted": s.tls_intercepted, "passthrough": s.tls_passthrough },
            "rejections": { "client": s.denied_clients, "rate_limit": s.rate_limited, "destination": s.blocked_destinations, "port": s.blocked_ports },
            "detections": {
                "volume": s.detections_volume,
                "denied": s.detections_denied,
                "rare_port": s.detections_rare_port,
                "host_mismatch": s.detections_host_mismatch,
            },
            "health": {
                "corrupt_objects": s.corrupt_objects,
                "store_write_errors": s.store_write_errors,
                "over_budget": s.over_budget,
                "coalesced": s.coalesced,
                "access_log_dropped": s.access_log_dropped,
                "access_log_errors": s.access_log_errors,
            },
        })
    }

    /// Métricas en el formato de texto de Prometheus.
    pub fn prometheus(&self) -> String {
        let s = self.snapshot();
        let mut out = String::new();
        single(&mut out, "rayo_uptime_seconds", "gauge", "Segundos desde que arrancó el proxy.", s.uptime_secs);
        single(&mut out, "rayo_requests_total", "counter", "Peticiones de contenido recibidas.", s.requests);
        single(&mut out, "rayo_request_hit_ratio", "gauge", "Parte de las peticiones servidas desde una copia.", s.request_hit_ratio);
        single(&mut out, "rayo_byte_hit_ratio", "gauge", "Parte de los bytes servidos desde una copia. No incluye túneles.", s.byte_hit_ratio);
        labeled(
            &mut out,
            "rayo_results_total",
            "Peticiones de contenido por resultado.",
            "result",
            &[
                ("hit", s.hits),
                ("revalidated", s.revalidated_304),
                ("miss", s.misses),
                ("bypass", s.bypass),
                ("origin_error", s.origin_errors),
                ("cache_error", s.cache_errors),
            ],
        );
        labeled(
            &mut out,
            "rayo_bytes_total",
            "Bytes entregados a los clientes por procedencia. No incluye túneles.",
            "source",
            &[("cache", s.bytes_from_cache), ("origin", s.bytes_from_origin), ("bypass", s.bytes_bypass)],
        );
        labeled(
            &mut out,
            "rayo_stored_objects_total",
            "Respuestas guardadas en disco.",
            "kind",
            &[("new", s.stored_new_objects), ("deduplicated", s.deduplicated_objects)],
        );
        labeled(
            &mut out,
            "rayo_tls_connections_total",
            "Conexiones por decisión de intercepción.",
            "mode",
            &[("intercepted", s.tls_intercepted), ("passthrough", s.tls_passthrough)],
        );
        labeled(
            &mut out,
            "rayo_rejections_total",
            "Peticiones rechazadas por motivo.",
            "reason",
            &[("client", s.denied_clients), ("rate_limit", s.rate_limited), ("destination", s.blocked_destinations), ("port", s.blocked_ports)],
        );
        labeled(
            &mut out,
            "rayo_detections_total",
            "Avisos de actividad inusual por tipo.",
            "kind",
            &[
                ("volume", s.detections_volume),
                ("denied", s.detections_denied),
                ("rare_port", s.detections_rare_port),
                ("host_mismatch", s.detections_host_mismatch),
            ],
        );
        single(&mut out, "rayo_over_budget_total", "counter", "Peticiones atendidas sin caché por falta de memoria.", s.over_budget);
        single(&mut out, "rayo_coalesced_total", "counter", "Peticiones que esperaron a otra igual.", s.coalesced);
        single(&mut out, "rayo_corrupt_objects_total", "counter", "Objetos descartados por no pasar la verificación de integridad.", s.corrupt_objects);
        single(&mut out, "rayo_store_write_errors_total", "counter", "Respuestas que no se pudieron guardar en disco.", s.store_write_errors);
        single(&mut out, "rayo_access_log_dropped_total", "counter", "Líneas del log de acceso perdidas por saturación.", s.access_log_dropped);
        single(&mut out, "rayo_access_log_errors_total", "counter", "Errores al escribir el log de acceso.", s.access_log_errors);
        single(&mut out, "rayo_disk_used_bytes", "gauge", "Bytes de objetos y metadatos de la caché.", s.disk_used_bytes);
        single(&mut out, "rayo_disk_objects", "gauge", "Objetos de la caché en disco.", s.disk_objects);
        single(&mut out, "rayo_disk_limit_bytes", "gauge", "Límite de la caché en disco (0 = sin límite).", s.disk_limit_bytes);
        single(&mut out, "rayo_disk_free_bytes", "gauge", "Espacio libre del volumen de la caché.", s.disk_free_bytes);
        single(&mut out, "rayo_disk_total_bytes", "gauge", "Tamaño del volumen de la caché.", s.disk_total_bytes);
        single(&mut out, "rayo_evicted_entries_total", "counter", "Entradas expulsadas por el límite de disco.", s.evicted_entries);
        single(&mut out, "rayo_evicted_bytes_total", "counter", "Bytes liberados por el límite de disco.", s.evicted_bytes);

        help_and_type(&mut out, "rayo_request_duration_seconds", "histogram", "Tiempo hasta tener lista la respuesta, por resultado.");
        self.latency.hit.write_prometheus(&mut out, "hit");
        self.latency.revalidated.write_prometheus(&mut out, "revalidated");
        self.latency.miss.write_prometheus(&mut out, "miss");
        self.latency.bypass.write_prometheus(&mut out, "bypass");
        self.latency.error.write_prometheus(&mut out, "error");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_hit_ratio_incluye_el_bypass() {
        let s = Stats::default();
        assert_eq!(s.snapshot().byte_hit_ratio, 0.0);
        Stats::add(&s.bytes_from_cache, 100);
        Stats::add(&s.bytes_from_origin, 100);
        Stats::add(&s.bytes_bypass, 200);
        assert_eq!(s.snapshot().byte_hit_ratio, 0.25);
    }

    #[test]
    fn request_hit_ratio_cuenta_copias_servidas() {
        let s = Stats::default();
        assert_eq!(s.snapshot().request_hit_ratio, 0.0);
        Stats::add(&s.requests, 4);
        Stats::inc(&s.hits);
        Stats::inc(&s.revalidated);
        assert_eq!(s.snapshot().request_hit_ratio, 0.5);
    }

    #[test]
    fn histograma_acumulado_para_prometheus() {
        let s = Stats::default();
        s.observe(Outcome::Hit, Duration::from_micros(500));
        s.observe(Outcome::Hit, Duration::from_millis(5));
        s.observe(Outcome::Hit, Duration::from_secs(60));
        s.observe(Outcome::Blocked, Duration::from_secs(1));
        let text = s.prometheus();
        assert!(text.contains("rayo_request_duration_seconds_bucket{result=\"hit\",le=\"0.001\"} 1\n"));
        assert!(text.contains("rayo_request_duration_seconds_bucket{result=\"hit\",le=\"0.005\"} 2\n"));
        assert!(text.contains("rayo_request_duration_seconds_bucket{result=\"hit\",le=\"10\"} 2\n"));
        assert!(text.contains("rayo_request_duration_seconds_bucket{result=\"hit\",le=\"+Inf\"} 3\n"));
        assert!(text.contains("rayo_request_duration_seconds_count{result=\"hit\"} 3\n"));
        assert!(text.contains("rayo_request_duration_seconds_count{result=\"miss\"} 0\n"));
    }

    #[test]
    fn las_estadisticas_publicas_no_crecen() {
        let json = serde_json::to_value(Stats::default().snapshot()).unwrap();
        for private in ["uptime_secs", "request_hit_ratio", "corrupt_objects", "store_write_errors", "disk_used_bytes", "disk_objects", "disk_limit_bytes", "disk_free_bytes", "evicted_entries", "since"] {
            assert!(json.get(private).is_none(), "{private} no debe salir en rayo.stats");
        }
        assert!(json.get("requests").is_some());
    }

    #[test]
    fn guarda_y_recupera_los_contadores_pero_no_las_medidas_del_disco() {
        let s = Stats::default();
        Stats::add(&s.hits, 3);
        Stats::add(&s.evicted_bytes, 9);
        s.disk_used_bytes.store(5, Relaxed);
        let text = s.saved_json();

        let back = Stats::default();
        back.restore(&text).unwrap();
        assert_eq!(back.hits.load(Relaxed), 3);
        assert_eq!(back.evicted_bytes.load(Relaxed), 9);
        assert_eq!(back.disk_used_bytes.load(Relaxed), 0);

        back.restore(r#"{"hits": 8, "contador_futuro": 1}"#).unwrap();
        assert_eq!(back.hits.load(Relaxed), 8);
        assert!(back.restore("{dañado").is_err());
        assert_eq!(back.hits.load(Relaxed), 8);
    }

    #[test]
    fn el_panel_no_incluye_datos_por_cliente() {
        let json = Stats::default().panel_json().to_string();
        assert!(!json.contains("client\":{"));
        assert!(json.contains("\"disk\""));
        assert!(json.contains("\"latency\""));
    }

    #[test]
    fn cada_metrica_declara_su_tipo_una_sola_vez() {
        let text = Stats::default().prometheus();
        let mut names: Vec<&str> = text.lines().filter_map(|l| l.strip_prefix("# TYPE ")).map(|l| l.split(' ').next().unwrap()).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total);
    }
}
