//! Puerto de administración, separado del proxy: panel, métricas y detalle por cliente.
//!
//! No es un host virtual como rayo.stats porque cualquier página abierta en un navegador que use el
//! proxy puede enviarle peticiones a un host virtual. Aquí todo dato exige un token que una página
//! ajena no conoce. Sin token solo se obtiene /healthz y el panel vacío, que no contiene ningún dato.

use crate::clients::ClientStats;
use crate::config::Config;
use crate::monitor::Monitor;
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

const PANEL_HTML: &str = include_str!("panel/index.html");
const PANEL_CSS: &str = include_str!("panel/panel.css");
const PANEL_JS: &str = include_str!("panel/panel.js");
/// El panel no necesita nada externo: solo sus propios archivos y sus propios datos.
const PANEL_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

struct AdminState {
    token: String,
    stats: Arc<Stats>,
    monitor: Arc<Monitor>,
    clients: Arc<ClientStats>,
}

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

fn respond(status: StatusCode, content_type: &'static str, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(body.into()));
    *res.status_mut() = status;
    let headers = res.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn plain(status: StatusCode, text: &'static str) -> Response<Full<Bytes>> {
    respond(status, "text/plain; charset=utf-8", text)
}

fn json(value: &serde_json::Value) -> Response<Full<Bytes>> {
    respond(StatusCode::OK, "application/json", value.to_string())
}

fn panel_page() -> Response<Full<Bytes>> {
    let mut res = respond(StatusCode::OK, "text/html; charset=utf-8", PANEL_HTML);
    let headers = res.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(PANEL_CSP));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    res
}

fn summary(state: &AdminState) -> serde_json::Value {
    let mut value = state.stats.panel_json();
    value["alerts"] = serde_json::json!(state.monitor.active());
    value["ca_not_after"] = state.monitor.ca_not_after().into();
    value["client_stats_enabled"] = state.clients.enabled().into();
    value
}

fn route(method: &Method, path: &str, authorization: Option<&HeaderValue>, state: &AdminState) -> Response<Full<Bytes>> {
    if method != Method::GET {
        return plain(StatusCode::METHOD_NOT_ALLOWED, "solo GET\n");
    }
    match path {
        "/healthz" => return plain(StatusCode::OK, "ok\n"),
        "/" => return panel_page(),
        "/panel.css" => return respond(StatusCode::OK, "text/css; charset=utf-8", PANEL_CSS),
        "/panel.js" => return respond(StatusCode::OK, "text/javascript; charset=utf-8", PANEL_JS),
        "/metrics" | "/api/summary" | "/api/clients" => {}
        _ => return plain(StatusCode::NOT_FOUND, "no existe\n"),
    }
    if !is_authorized(authorization, &state.token) {
        let mut res = plain(StatusCode::UNAUTHORIZED, "falta el token\n");
        res.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return res;
    }
    match path {
        "/metrics" => {
            let text = state.stats.prometheus() + &state.monitor.prometheus();
            respond(StatusCode::OK, "text/plain; version=0.0.4; charset=utf-8", text)
        }
        "/api/summary" => json(&summary(state)),
        _ => json(&serde_json::json!({ "enabled": state.clients.enabled(), "clients": state.clients.rows() })),
    }
}

/// Abre el puerto. Si no se puede, el proxy no arranca: mejor saberlo que quedarse sin métricas.
pub async fn start(cfg: &Config, stats: Arc<Stats>, monitor: Arc<Monitor>, clients: Arc<ClientStats>) -> anyhow::Result<()> {
    let listen = cfg.admin_listen.trim();
    if listen.is_empty() {
        return Ok(());
    }
    let addr: SocketAddr = listen.parse().with_context(|| format!("admin_listen inválido: {listen}"))?;
    let token = load_or_create_token(&cfg.admin_token_file)?;
    let listener = TcpListener::bind(addr).await.with_context(|| format!("abriendo el puerto de administración {addr}"))?;
    if !addr.ip().is_loopback() {
        tracing::warn!("el puerto de administración escucha en {addr}: el token viaja sin cifrar por esa red");
    }
    tracing::info!("panel en http://{addr}/ y métricas en /metrics (token en {})", cfg.admin_token_file.display());

    let state = Arc::new(AdminState { token, stats, monitor, clients });
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let state = state.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let res = route(req.method(), req.uri().path(), req.headers().get(header::AUTHORIZATION), &state);
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
    use crate::stats::Outcome;
    use http_body_util::BodyExt;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn state() -> AdminState {
        AdminState {
            token: TOKEN.to_owned(),
            stats: Arc::new(Stats::default()),
            monitor: Arc::new(Monitor::new(99)),
            clients: Arc::new(ClientStats::new(true)),
        }
    }

    fn get(state: &AdminState, method: Method, path: &str, authorization: Option<&str>) -> Response<Full<Bytes>> {
        let value = authorization.map(|a| HeaderValue::from_str(a).unwrap());
        route(&method, path, value.as_ref(), state)
    }

    fn status(method: Method, path: &str, authorization: Option<&str>) -> StatusCode {
        get(&state(), method, path, authorization).status()
    }

    async fn body(res: Response<Full<Bytes>>) -> String {
        String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    }

    #[test]
    fn todos_los_datos_exigen_el_token() {
        let good = format!("Bearer {TOKEN}");
        for path in ["/metrics", "/api/summary", "/api/clients"] {
            assert_eq!(status(Method::GET, path, Some(&good)), StatusCode::OK, "{path}");
            assert_eq!(status(Method::GET, path, None), StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(status(Method::GET, path, Some("Bearer incorrecto")), StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(status(Method::GET, path, Some(TOKEN)), StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(status(Method::GET, path, Some(&format!("Basic {TOKEN}"))), StatusCode::UNAUTHORIZED, "{path}");
        }
    }

    #[test]
    fn el_resto_de_rutas() {
        assert_eq!(status(Method::GET, "/healthz", None), StatusCode::OK);
        assert_eq!(status(Method::GET, "/otra", None), StatusCode::NOT_FOUND);
        assert_eq!(status(Method::POST, "/metrics", Some(&format!("Bearer {TOKEN}"))), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn el_panel_sin_token_no_contiene_datos() {
        let state = state();
        Stats::add(&state.stats.requests, 123_456);
        state.clients.record("10.9.8.7".parse().unwrap(), Outcome::Hit, Some(1));

        let page = get(&state, Method::GET, "/", None);
        assert_eq!(page.status(), StatusCode::OK);
        let csp = page.headers().get(header::CONTENT_SECURITY_POLICY).unwrap().to_str().unwrap();
        assert!(csp.contains("default-src 'none'") && csp.contains("script-src 'self'"));
        assert!(!csp.contains("unsafe"));
        let html = body(page).await;
        assert!(!html.contains("123456") && !html.contains("10.9.8.7"));
        assert!(!html.contains("<script>"), "un script en línea lo bloquearía la política de seguridad");

        for (path, kind) in [("/panel.css", "text/css"), ("/panel.js", "text/javascript")] {
            let res = get(&state, Method::GET, path, None);
            assert_eq!(res.status(), StatusCode::OK);
            assert!(res.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap().starts_with(kind));
        }
    }

    #[tokio::test]
    async fn el_resumen_incluye_alertas_y_ningun_cliente() {
        let state = state();
        state.clients.record("10.9.8.7".parse().unwrap(), Outcome::Hit, Some(1));
        let text = body(get(&state, Method::GET, "/api/summary", Some(&format!("Bearer {TOKEN}")))).await;
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["ca_not_after"], 99);
        assert_eq!(value["client_stats_enabled"], true);
        assert!(value["alerts"].as_array().unwrap().is_empty());
        assert!(!text.contains("10.9.8.7"));

        let text = body(get(&state, Method::GET, "/api/clients", Some(&format!("Bearer {TOKEN}")))).await;
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["clients"][0]["ip"], "10.9.8.7");
        assert_eq!(value["clients"][0]["bytes_from_copy"], 1);
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
