//! rayo-cache: proxy de caché local con intercepción TLS selectiva.
//!
//! Uso:  rayo-cache [ruta/config.toml]
//! Luego configura 127.0.0.1:3128 como proxy HTTP y HTTPS e instala ca/rayo-ca.crt
//! en el almacén de confianza de TUS dispositivos.

mod access;
mod access_log;
mod admin;
mod ca;
mod coalesce;
mod config;
mod handler;
mod memory;
mod notice;
mod policy;
mod secure;
mod stats;
mod store;
mod upstream;

use handler::{CacheHandler, Shared};
use hudsucker::Proxy;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
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
    let store = store::Store::open(&cfg.data_dir, cfg.mem_index_entries, stats.clone()).await?;
    let normalizer = policy::KeyNormalizer::new(&cfg)?;
    let connector = upstream::connector(&cfg.upstream_extra_ca, destinations.clone(), stats.clone())?;

    // Hudsucker anota la IP del cliente en sus spans de nivel INFO: con un filtro como RUST_LOG=info,
    // esa IP acompaña a cada línea del registro aunque rayo-cache no esté en modo debug.
    let detailed_logs = tracing::enabled!(target: "rayo_cache", tracing::Level::DEBUG)
        || tracing::enabled!(target: "hudsucker::proxy::internal", tracing::Level::INFO);
    let notice = notice::render(&cfg, &ca::summary(&cfg.ca_cert)?, detailed_logs).into();

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

    let access_log = access_log::AccessLog::start(&cfg, stats.clone())?;
    admin::start(&cfg, stats.clone()).await?;
    store::watch_disk(cfg.data_dir.clone(), stats.clone(), Duration::from_secs(cfg.disk_scan_interval_secs.max(1)));

    let memory = memory::MemoryBudget::new(cfg.max_buffered_bytes);
    let flights = coalesce::Flights::new(cfg.coalesce_wait_secs);
    let shared = Arc::new(Shared { cfg, store, stats, normalizer, clients, destinations, memory, flights, access_log, notice });

    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(ca)
        .with_http_connector(connector)
        .with_http_handler(CacheHandler::new(shared))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .build()?;

    proxy.start().await?;
    Ok(())
}
