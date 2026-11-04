//! Contadores en vivo, expuestos en http://rayo.stats/ y en /metrics del puerto de administración.
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
    /// Última medición del disco: bytes de objetos y metadatos, y cantidad de objetos.
    pub disk_used_bytes: AtomicU64,
    pub disk_objects: AtomicU64,
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
            over_budget: self.over_budget.load(Relaxed),
            coalesced: self.coalesced.load(Relaxed),
            corrupt_objects: self.corrupt_objects.load(Relaxed),
            store_write_errors: self.store_write_errors.load(Relaxed),
            access_log_dropped: self.access_log_dropped.load(Relaxed),
            access_log_errors: self.access_log_errors.load(Relaxed),
            disk_used_bytes: self.disk_used_bytes.load(Relaxed),
            disk_objects: self.disk_objects.load(Relaxed),
        }
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
            &[("client", s.denied_clients), ("rate_limit", s.rate_limited), ("destination", s.blocked_destinations)],
        );
        single(&mut out, "rayo_over_budget_total", "counter", "Peticiones atendidas sin caché por falta de memoria.", s.over_budget);
        single(&mut out, "rayo_coalesced_total", "counter", "Peticiones que esperaron a otra igual.", s.coalesced);
        single(&mut out, "rayo_corrupt_objects_total", "counter", "Objetos descartados por no pasar la verificación de integridad.", s.corrupt_objects);
        single(&mut out, "rayo_store_write_errors_total", "counter", "Respuestas que no se pudieron guardar en disco.", s.store_write_errors);
        single(&mut out, "rayo_access_log_dropped_total", "counter", "Líneas del log de acceso perdidas por saturación.", s.access_log_dropped);
        single(&mut out, "rayo_access_log_errors_total", "counter", "Errores al escribir el log de acceso.", s.access_log_errors);
        single(&mut out, "rayo_disk_used_bytes", "gauge", "Bytes de objetos y metadatos en la última medición.", s.disk_used_bytes);
        single(&mut out, "rayo_disk_objects", "gauge", "Objetos en disco en la última medición.", s.disk_objects);

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
        for private in ["uptime_secs", "request_hit_ratio", "corrupt_objects", "store_write_errors", "disk_used_bytes", "disk_objects"] {
            assert!(json.get(private).is_none(), "{private} no debe salir en rayo.stats");
        }
        assert!(json.get("requests").is_some());
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
