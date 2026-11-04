//! Puerto de administración, separado del proxy.
//!
//! No es un host virtual como rayo.stats porque cualquier página abierta en un navegador que use el
//! proxy puede enviarle peticiones a un host virtual. Aquí todo lo que no sea /healthz exige un token
//! que una página ajena no conoce.

use crate::config::Config;
use crate::secure::{random_bytes, write_private};
use crate::stats::Stats;
use anyhow::{bail, Context};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

const MIN_TOKEN_CHARS: usize = 32;

/// Lee el token o, si no existe, crea uno. Su valor nunca se escribe en el registro.
fn load_or_create_token(path: &Path) -> anyhow::Result<String> {
    if path.exists() {
        let token = std::fs::read_to_string(path).with_context(|| format!("leyendo {}", path.display()))?;
        let token = token.trim().to_owned();
        if token.chars().count() < MIN_TOKEN_CHARS {
            bail!("el token de {} es demasiado corto: usa al menos {MIN_TOKEN_CHARS} caracteres", path.display());
        }
        return Ok(token);
    }
    let token = hex::encode(random_bytes::<32>());
    write_private(path, token.as_bytes())?;
    tracing::info!("token de administración creado en {}", path.display());
    Ok(token)
}

/// Compara sin revelar por el tiempo de respuesta cuántos caracteres coinciden.
fn same_secret(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

fn is_authorized(authorization: Option<&HeaderValue>, token: &str) -> bool {
    let Some(presented) = authorization.and_then(|v| v.as_bytes().strip_prefix(b"Bearer ")) else {
        return false;
    };
    same_secret(presented, token.as_bytes())
}

fn plain(status: StatusCode, text: &'static str) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(Bytes::from_static(text.as_bytes())));
    *res.status_mut() = status;
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    res
}

fn route(method: &Method, path: &str, authorization: Option<&HeaderValue>, token: &str, stats: &Stats) -> Response<Full<Bytes>> {
    if method != Method::GET {
        return plain(StatusCode::METHOD_NOT_ALLOWED, "solo GET\n");
    }
    match path {
        "/healthz" => plain(StatusCode::OK, "ok\n"),
        "/metrics" if is_authorized(authorization, token) => {
            let mut res = Response::new(Full::new(Bytes::from(stats.prometheus())));
            res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"));
            res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            res
        }
        "/metrics" => {
            let mut res = plain(StatusCode::UNAUTHORIZED, "falta el token\n");
            res.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            res
        }
        _ => plain(StatusCode::NOT_FOUND, "no existe\n"),
    }
}

/// Abre el puerto. Si no se puede, el proxy no arranca: mejor saberlo que quedarse sin métricas.
pub async fn start(cfg: &Config, stats: Arc<Stats>) -> anyhow::Result<()> {
    let listen = cfg.admin_listen.trim();
    if listen.is_empty() {
        return Ok(());
    }
    let addr: SocketAddr = listen.parse().with_context(|| format!("admin_listen inválido: {listen}"))?;
    let token: Arc<str> = load_or_create_token(&cfg.admin_token_file)?.into();
    let listener = TcpListener::bind(addr).await.with_context(|| format!("abriendo el puerto de administración {addr}"))?;
    if !addr.ip().is_loopback() {
        tracing::warn!("el puerto de administración escucha en {addr}: el token viaja sin cifrar por esa red");
    }
    tracing::info!("administración en http://{addr}/metrics (token en {})", cfg.admin_token_file.display());

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let (stats, token) = (stats.clone(), token.clone());
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let res = route(
                        req.method(),
                        req.uri().path(),
                        req.headers().get(header::AUTHORIZATION),
                        &token,
                        &stats,
                    );
                    async move { Ok::<_, std::convert::Infallible>(res) }
                });
                // El límite evita que una conexión a medias quede ocupando recursos para siempre.
                let _ = hyper::server::conn::http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(10))
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn status(method: Method, path: &str, authorization: Option<&str>) -> StatusCode {
        let value = authorization.map(|a| HeaderValue::from_str(a).unwrap());
        route(&method, path, value.as_ref(), TOKEN, &Stats::default()).status()
    }

    #[test]
    fn las_metricas_exigen_el_token() {
        let good = format!("Bearer {TOKEN}");
        assert_eq!(status(Method::GET, "/metrics", Some(&good)), StatusCode::OK);
        assert_eq!(status(Method::GET, "/metrics", None), StatusCode::UNAUTHORIZED);
        assert_eq!(status(Method::GET, "/metrics", Some("Bearer incorrecto")), StatusCode::UNAUTHORIZED);
        assert_eq!(status(Method::GET, "/metrics", Some(TOKEN)), StatusCode::UNAUTHORIZED);
        assert_eq!(status(Method::GET, "/metrics", Some(&format!("Basic {TOKEN}"))), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn el_resto_de_rutas() {
        assert_eq!(status(Method::GET, "/healthz", None), StatusCode::OK);
        assert_eq!(status(Method::GET, "/", None), StatusCode::NOT_FOUND);
        assert_eq!(status(Method::POST, "/metrics", Some(&format!("Bearer {TOKEN}"))), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn comparacion_de_secretos() {
        assert!(same_secret(b"abc", b"abc"));
        assert!(!same_secret(b"abc", b"abd"));
        assert!(!same_secret(b"abc", b"abcd"));
    }

    #[test]
    fn crea_el_token_una_vez_y_rechaza_uno_debil() {
        let dir = std::env::temp_dir().join(format!("rayo-admin-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("admin.token");
        let first = load_or_create_token(&path).unwrap();
        assert_eq!(first.len(), 64);
        assert_eq!(load_or_create_token(&path).unwrap(), first);

        std::fs::write(&path, "corto\n").unwrap();
        assert!(load_or_create_token(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
