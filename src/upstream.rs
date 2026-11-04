//! Conexión del proxy hacia los orígenes (rustls + Hyper).
//!
//! Confía en las raíces públicas (webpki-roots) y, opcionalmente, en CAs extra
//! (p. ej. la CA privada de la intranet de tu campus o de un laboratorio).
//!
//! El destino se valida al resolver el nombre, justo antes de conectar. Validarlo antes no bastaría:
//! un dominio puede responder con una IP pública a la comprobación y con una interna al conectar.

use crate::access::{DestinationPolicy, ResolveError};
use crate::stats::Stats;
use anyhow::Context;
use hudsucker::rustls::{
    self,
    crypto::aws_lc_rs,
    pki_types::{pem::PemObject, CertificateDer},
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::{dns::Name, HttpConnector};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
    vec,
};
use tower_service::Service;

/// Resolvedor que rechaza los nombres que apuntan a destinos internos.
#[derive(Clone)]
pub struct GuardedResolver {
    destinations: Arc<DestinationPolicy>,
    stats: Arc<Stats>,
}

impl Service<Name> for GuardedResolver {
    type Response = vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            // Con puerto 0, HttpConnector aplica después el puerto de la URL.
            match this.destinations.resolve(name.as_str(), 0).await {
                Ok(addrs) => Ok(addrs.into_iter()),
                Err(e) => {
                    if matches!(e, ResolveError::Blocked(_)) {
                        Stats::inc(&this.stats.blocked_destinations);
                    }
                    Err(e.into())
                }
            }
        })
    }
}

pub fn connector(
    extra_cas: &[PathBuf],
    destinations: Arc<DestinationPolicy>,
    stats: Arc<Stats>,
) -> anyhow::Result<HttpsConnector<HttpConnector<GuardedResolver>>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for path in extra_cas {
        for cert in CertificateDer::pem_file_iter(path).with_context(|| format!("leyendo {}", path.display()))? {
            roots.add(cert?)?;
        }
        tracing::info!("CA extra de confianza para orígenes: {}", path.display());
    }

    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut http = HttpConnector::new_with_resolver(GuardedResolver { destinations, stats });
    http.enforce_http(false);
    http.set_nodelay(true);
    http.set_connect_timeout(Some(Duration::from_secs(10)));

    Ok(HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http))
}
