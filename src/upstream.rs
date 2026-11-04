//! Conexión del proxy hacia los orígenes (rustls + Hyper).
//!
//! Confía en las raíces públicas (webpki-roots) y, opcionalmente, en CAs extra
//! (p. ej. la CA privada de la intranet de tu campus o de un laboratorio).

use anyhow::Context;
use hudsucker::rustls::{
    self,
    crypto::aws_lc_rs,
    pki_types::{pem::PemObject, CertificateDer},
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use std::{path::PathBuf, sync::Arc, time::Duration};

pub fn connector(extra_cas: &[PathBuf]) -> anyhow::Result<HttpsConnector<HttpConnector>> {
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

    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_nodelay(true);
    http.set_connect_timeout(Some(Duration::from_secs(10)));

    Ok(HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http))
}
