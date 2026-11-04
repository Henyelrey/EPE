//! rayo-cache: proxy de caché local con intercepción TLS selectiva.
//!
//! Uso:  rayo-cache [ruta/config.toml]
//! Luego configura 127.0.0.1:3128 como proxy HTTP y HTTPS e instala ca/rayo-ca.crt
//! en el almacén de confianza de TUS dispositivos.

mod access;
mod access_log;
mod admin;
mod ca;
mod clients;
mod coalesce;
mod config;
mod detect;
mod handler;
mod live;
mod memory;
mod monitor;
mod notice;
mod policy;
mod secure;
mod security;
mod stats;
mod store;
mod upstream;

use handler::{CacheHandler, Shared};
use hudsucker::Proxy;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "rayo_cache=info,hudsucker=warn".into()))
        .init();

    let cfg_path = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| "config.toml".into());
    let cfg = config::Config::load_or_create(&cfg_path)?;
    let addr: SocketAddr = cfg.listen.parse()?;

    let clients = access::ClientGate::new(&cfg, addr)?;
    let destinations = Arc::new(access::DestinationPolicy::new(&cfg)?);
    let stats = Arc::new(stats::Stats::default());

    let ca = ca::load_or_generate(&cfg.ca_cert, &cfg.ca_key, &cfg.intercept_domains)?;
    monitor::restore_stats(&cfg.data_dir, &stats).await;
    let store = store::Store::open(&cfg.data_dir, cfg.mem_index_entries, cfg.max_disk_bytes, stats.clone()).await?;
    let normalizer = policy::KeyNormalizer::new(&cfg)?;
    let connector = upstream::connector(&cfg.upstream_extra_ca, destinations.clone(), stats.clone())?;

    // Hudsucker anota la IP del cliente en sus spans de nivel INFO: con un filtro como RUST_LOG=info,
    // esa IP acompaña a cada línea del registro aunque rayo-cache no esté en modo debug.
    let detailed_logs = tracing::enabled!(target: "rayo_cache", tracing::Level::DEBUG)
        || tracing::enabled!(target: "hudsucker::proxy::internal", tracing::Level::INFO);
    let ca_summary = ca::summary(&cfg.ca_cert)?;
    let notice = notice::render(&cfg, &ca_summary, detailed_logs).into();

    tracing::info!(
        "escuchando en {addr} | clientes permitidos: {:?} | intercepta TLS de {} dominio(s), el resto va en passthrough | stats: http://{}/ | aviso: http://{}/",
        cfg.allowed_clients,
        cfg.intercept_domains.len(),
        cfg.stats_host,
        cfg.notice_host
    );
    if !addr.ip().is_loopback() && cfg.operator_contact.trim().is_empty() {
        tracing::warn!("operator_contact está vacío: el aviso no dirá a quién acudir. Complétalo en una red compartida.");
    }
    if cfg.access_log_enabled {
        tracing::info!(
            "log de acceso activo en {}, se conserva {} día(s). El aviso a los usuarios lo indica.",
            cfg.access_log_dir.display(),
            cfg.access_log_retention_days
        );
    }

    if cfg.client_stats_enabled {
        tracing::info!("totales por cliente activos, solo en memoria. El aviso a los usuarios lo indica.");
    }
    if cfg.detections_enabled {
        tracing::info!("detecciones de actividad inusual activas, solo en memoria. El aviso a los usuarios lo indica.");
    }
    if cfg.live_log_enabled {
        tracing::info!("registro en vivo activo, solo en memoria. El aviso a los usuarios lo indica.");
    }
    if cfg.security_log_enabled {
        tracing::info!(
            "log de seguridad activo en {}, se conserva {} día(s). El aviso a los usuarios lo indica.",
            cfg.security_log_dir.display(),
            cfg.security_log_retention_days
        );
    }
    if cfg.allowed_connect_ports.is_empty() {
        tracing::warn!("allowed_connect_ports está vacío: los clientes pueden abrir túneles a cualquier puerto público.");
    }
    if cfg.max_disk_bytes > 0 && cfg.max_disk_bytes < cfg.max_object_bytes as u64 {
        tracing::warn!("max_disk_bytes es menor que max_object_bytes: un objeto grande expulsaría toda la caché.");
    }

    let access_log = access_log::AccessLog::start(&cfg, stats.clone())?;
    let security = Arc::new(security::SecurityLog::start(&cfg, stats.clone())?);
    let started = format!("Escucha en {addr}; descifra {} dominio(s).", cfg.intercept_domains.len());
    security.record(security::SecurityEvent { event: "startup", detail: Some(&started), ..Default::default() });
    let client_stats = Arc::new(clients::ClientStats::new(cfg.client_stats_enabled));
    let limits = detect::Limits {
        requests_per_minute: cfg.detect_requests_per_minute,
        bytes_per_minute: cfg.detect_bytes_per_minute,
        denied_per_minute: cfg.detect_denied_per_minute,
    };
    let detector = Arc::new(detect::Detector::new(cfg.detections_enabled, limits, stats.clone()).with_security_log(security.clone()));
    let health = Arc::new(monitor::Monitor::new(ca_summary.not_after).with_security_log(security.clone()));
    let live_log = Arc::new(live::LiveLog::new(cfg.live_log_enabled, cfg.live_log_client));
    let traffic = Arc::new(live::Traffic::default());
    admin::start(&cfg, stats.clone(), health.clone(), client_stats.clone(), detector.clone(), live_log.clone(), traffic.clone(), security.clone()).await?;
    live::start(stats.clone(), live_log.clone(), traffic);
    monitor::start(&cfg, stats.clone(), client_stats.clone(), detector.clone(), health);

    let data_dir = cfg.data_dir.clone();
    let final_stats = stats.clone();
    let memory = memory::MemoryBudget::new(cfg.max_buffered_bytes);
    let flights = coalesce::Flights::new(cfg.coalesce_wait_secs);
    let shared = Arc::new(Shared { cfg, store, stats, normalizer, clients, destinations, memory, flights, access_log, client_stats, detector, live_log, security: security.clone(), notice });

    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(ca)
        .with_http_connector(connector)
        .with_http_handler(CacheHandler::new(shared))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .build()?;

    let result = proxy.start().await;
    security.record(security::SecurityEvent { event: "shutdown", ..Default::default() });
    // La línea se escribe en otra tarea: se le da tiempo antes de salir.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    monitor::save_stats(&data_dir, &final_stats).await;
    result?;
    Ok(())
}
