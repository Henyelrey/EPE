//! Lógica del proxy: decide qué descifrar, sirve HITs, guarda MISSes y revalida con ETag.

use crate::config::Config;
use crate::policy::{self, AbsUrl, KeyNormalizer};
use crate::stats::Stats;
use crate::store::{now, Meta, PutOutcome, Store};
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hudsucker::futures::{stream, StreamExt};
use hudsucker::hyper::header::{self, HeaderValue};
use hudsucker::hyper::{Request, Response, StatusCode};
use hudsucker::rustls::server::ClientHello;
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};
use std::sync::Arc;

pub struct Shared {
    pub cfg: Config,
    pub store: Store,
    pub stats: Stats,
    pub normalizer: KeyNormalizer,
}

/// Lo que se recuerda entre `handle_request` y `handle_response` del mismo intercambio.
struct Pending {
    url: String,
    key: String,
    key_hash: String,
    /// Copia vencida que se está revalidando con If-None-Match / If-Modified-Since.
    stale: Option<Arc<Meta>>,
}

#[derive(Clone)]
pub struct CacheHandler {
    shared: Arc<Shared>,
    pending: Option<Arc<Pending>>,
}

impl CacheHandler {
    pub fn new(shared: Arc<Shared>) -> Self {
        Self { shared, pending: None }
    }

    async fn serve_from_cache(&self, meta: &Meta, status: &'static str) -> Option<Response<Body>> {
        let body = self.shared.store.read_object(meta).await?;
        let mut b = Response::builder().status(StatusCode::OK);
        for (k, v) in &meta.headers {
            b = b.header(k.as_str(), v.as_str());
        }
        let age = now().saturating_sub(meta.stored_at);
        let res = b
            .header(header::CONTENT_LENGTH, body.len())
            .header(header::AGE, age)
            .header("x-rayo-cache", status)
            .body(Body::from(body.clone()))
            .ok()?;
        Stats::add(&self.shared.stats.bytes_from_cache, body.len() as u64);
        Some(res)
    }

    fn stats_response(&self) -> Response<Body> {
        let json = serde_json::to_string_pretty(&self.shared.stats.snapshot()).unwrap_or_default();
        Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json))
            .expect("respuesta estática válida")
    }
}

impl HttpHandler for CacheHandler {
    /// Intercepción selectiva en modo proxy explícito (CONNECT host:443).
    async fn should_intercept_connect(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        let host = req.uri().host().unwrap_or_default();
        let yes = self.shared.cfg.should_intercept(host);
        let s = &self.shared.stats;
        Stats::inc(if yes { &s.tls_intercepted } else { &s.tls_passthrough });
        tracing::debug!(host, intercept = yes, "CONNECT");
        yes
    }

    /// Segundo filtro sobre el SNI real del ClientHello: si no está en la lista, pasa cifrado.
    async fn should_intercept_tls(&mut self, _ctx: &HttpContext, hello: ClientHello<'_>) -> bool {
        hello.server_name().map(|sni| self.shared.cfg.should_intercept(sni)).unwrap_or(false)
    }

    async fn handle_request(&mut self, _ctx: &HttpContext, mut req: Request<Body>) -> RequestOrResponse {
        let sh = &self.shared;
        self.pending = None;

        // Hudsucker también pasa aquí el CONNECT inicial del túnel: no es contenido.
        if req.method() == hudsucker::hyper::Method::CONNECT {
            return req.into();
        }

        let Some(url) = AbsUrl::from_request(&req) else {
            return req.into();
        };
        if url.hostname() == sh.cfg.stats_host {
            return self.stats_response().into();
        }
        Stats::inc(&sh.stats.requests);

        let scope_ok = match url.scheme.as_str() {
            // HTTPS solo llega aquí si pasó el filtro de intercepción.
            "https" => true,
            "http" => sh.cfg.cache_plain_http,
            _ => false,
        };
        if !scope_ok || !policy::request_is_cacheable(&req) {
            Stats::inc(&sh.stats.bypass);
            return req.into();
        }

        let normalized = sh.normalizer.normalize(&url);
        let key = format!("{normalized}|{}", policy::encoding_bucket(req.headers()));
        let key_hash = Store::key_hash(&key);

        let mut stale = None;
        if let Some(meta) = sh.store.get(&key_hash).await {
            if meta.is_fresh() {
                if let Some(res) = self.serve_from_cache(&meta, "HIT").await {
                    Stats::inc(&sh.stats.hits);
                    tracing::info!(url = %normalized, "HIT");
                    return res.into();
                }
            } else {
                // Vencido: se pide al origen solo si cambió (ahorra el cuerpo completo si responde 304).
                let h = req.headers_mut();
                if !h.contains_key(header::IF_NONE_MATCH) && !h.contains_key(header::IF_MODIFIED_SINCE) {
                    if let Some(v) = meta.etag.as_deref().and_then(|e| HeaderValue::from_str(e).ok()) {
                        h.insert(header::IF_NONE_MATCH, v);
                    }
                    if let Some(v) = meta.last_modified.as_deref().and_then(|e| HeaderValue::from_str(e).ok()) {
                        h.insert(header::IF_MODIFIED_SINCE, v);
                    }
                    stale = Some(meta);
                }
            }
        }

        self.pending = Some(Arc::new(Pending { url: normalized, key, key_hash, stale }));
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let Some(p) = self.pending.take() else {
            return res;
        };
        let sh = self.shared.clone();

        // 1) Revalidación exitosa: el origen confirma que nuestra copia sigue válida.
        if res.status() == StatusCode::NOT_MODIFIED {
            if let Some(meta) = &p.stale {
                let ttl = policy::ttl_secs(res.headers(), sh.cfg.default_ttl_secs);
                let _ = sh.store.refresh(&p.key_hash, meta, ttl).await;
                if let Some(cached) = self.serve_from_cache(meta, "REVALIDATED").await {
                    Stats::inc(&sh.stats.revalidated);
                    tracing::info!(url = %p.url, "REVALIDATED (304)");
                    return cached;
                }
            }
            return res;
        }

        // 2) No cacheable: se reenvía tal cual, en streaming.
        if !policy::response_is_cacheable(&res, sh.cfg.max_object_bytes) {
            Stats::inc(&sh.stats.bypass);
            return res;
        }

        // 3) Se acumula el cuerpo hasta el límite. Si lo supera, se reenvía sin guardar.
        let (mut parts, mut body) = res.into_parts();
        let mut buf = BytesMut::new();
        let max = sh.cfg.max_object_bytes;
        let complete = loop {
            match body.frame().await {
                None => break true,
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        buf.extend_from_slice(&data);
                        if buf.len() > max {
                            break false;
                        }
                    }
                }
                Some(Err(e)) => {
                    tracing::warn!(url = %p.url, error = %e, "error leyendo cuerpo del origen");
                    return Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::empty())
                        .expect("respuesta estática válida");
                }
            }
        };

        if !complete {
            Stats::inc(&sh.stats.bypass);
            let head = stream::once(async move { Ok::<Bytes, hudsucker::Error>(buf.freeze()) });
            let rest = body.into_data_stream();
            return Response::from_parts(parts, Body::from_stream(head.chain(rest)));
        }

        let bytes = buf.freeze();
        Stats::inc(&sh.stats.misses);
        Stats::add(&sh.stats.bytes_from_origin, bytes.len() as u64);

        let h = &parts.headers;
        let ttl = policy::ttl_secs(h, sh.cfg.default_ttl_secs);
        let meta = Meta {
            url: p.url.clone(),
            key: p.key.clone(),
            object: String::new(),
            size: 0,
            headers: h
                .iter()
                .filter(|(k, _)| !policy::is_hop_by_hop(k.as_str()))
                .filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned())))
                .collect(),
            stored_at: now(),
            expires_at: now() + ttl,
            etag: h.get(header::ETAG).and_then(|v| v.to_str().ok()).map(str::to_owned),
            last_modified: h.get(header::LAST_MODIFIED).and_then(|v| v.to_str().ok()).map(str::to_owned),
        };

        match sh.store.put(&p.key_hash, meta, &bytes).await {
            Ok(PutOutcome::New) => Stats::inc(&sh.stats.stored_new),
            Ok(PutOutcome::Deduplicated) => {
                Stats::inc(&sh.stats.dedup);
                tracing::info!(url = %p.url, "contenido idéntico ya almacenado (dedup)");
            }
            Err(e) => tracing::warn!(url = %p.url, error = %e, "no se pudo guardar"),
        }
        tracing::info!(url = %p.url, bytes = bytes.len(), ttl, "MISS → guardado");

        parts.headers.remove(header::TRANSFER_ENCODING);
        parts.headers.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
        parts.headers.insert("x-rayo-cache", HeaderValue::from_static("MISS"));
        Response::from_parts(parts, Body::from(bytes))
    }
}
