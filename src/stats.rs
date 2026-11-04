//! Contadores en vivo, expuestos en http://rayo.stats/ (a través del proxy).
//!
//! Con el proxy sin peticiones en curso, se cumple:
//! requests = hits + misses + revalidated + bypass + origin_errors + cache_errors
//!
//! Los túneles en passthrough no entran en ninguno de estos contadores de bytes: Hudsucker no
//! expone cuántos bytes pasan por ellos, así que el ratio solo describe el tráfico descifrado o HTTP.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

#[derive(Default)]
pub struct Stats {
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
}

#[derive(Serialize)]
pub struct Snapshot {
    requests: u64,
    hits: u64,
    misses: u64,
    revalidated_304: u64,
    bypass: u64,
    origin_errors: u64,
    cache_errors: u64,
    stored_new_objects: u64,
    deduplicated_objects: u64,
    bytes_from_cache: u64,
    bytes_from_origin: u64,
    bytes_bypass: u64,
    byte_hit_ratio: f64,
    tls_intercepted: u64,
    tls_passthrough: u64,
}

impl Stats {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Relaxed);
    }
    pub fn add(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Relaxed);
    }
    pub fn snapshot(&self) -> Snapshot {
        let cache = self.bytes_from_cache.load(Relaxed);
        let origin = self.bytes_from_origin.load(Relaxed);
        let bypass = self.bytes_bypass.load(Relaxed);
        let total = cache + origin + bypass;
        Snapshot {
            requests: self.requests.load(Relaxed),
            hits: self.hits.load(Relaxed),
            misses: self.misses.load(Relaxed),
            revalidated_304: self.revalidated.load(Relaxed),
            bypass: self.bypass.load(Relaxed),
            origin_errors: self.origin_errors.load(Relaxed),
            cache_errors: self.cache_errors.load(Relaxed),
            stored_new_objects: self.stored_new.load(Relaxed),
            deduplicated_objects: self.dedup.load(Relaxed),
            bytes_from_cache: cache,
            bytes_from_origin: origin,
            bytes_bypass: bypass,
            byte_hit_ratio: if total == 0 { 0.0 } else { cache as f64 / total as f64 },
            tls_intercepted: self.tls_intercepted.load(Relaxed),
            tls_passthrough: self.tls_passthrough.load(Relaxed),
        }
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
}
