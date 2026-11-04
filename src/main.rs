//! rayo-cache: proxy de caché local con intercepción TLS selectiva.
//!
//! Uso:  rayo-cache [ruta/config.toml]
//! Luego configura 127.0.0.1:3128 como proxy HTTP y HTTPS e instala ca/rayo-ca.crt
//! en el almacén de confianza de TUS dispositivos.

mod ca;
mod config;
mod handler;
mod policy;
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

    let ca = ca::load_or_generate(&cfg.ca_cert, &cfg.ca_key)?;
    let store = store::Store::open(&cfg.data_dir, cfg.mem_index_entries).await?;
    let normalizer = policy::KeyNormalizer::new(&cfg)?;
    let connector = upstream::connector(&cfg.upstream_extra_ca)?;

    tracing::info!(
        "escuchando en {addr} | intercepta TLS de {} dominio(s), el resto va en passthrough | stats: http://{}/",
        cfg.intercept_domains.len(),
        cfg.stats_host
    );

    let shared = Arc::new(Shared { cfg, store, stats: Default::default(), normalizer });

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
