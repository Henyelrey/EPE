//! Reglas de caché: qué se puede guardar, por cuánto tiempo y con qué clave.

use crate::config::{matches_suffix, Config, StoreIdRule};
use hudsucker::hyper::{header, HeaderMap, Method, Request, Response, StatusCode, Uri};
use regex::Regex;

/// Reglas Store-ID precompiladas (la idea de los "plugins" de ThunderCache 3.x, pero declarativa).
pub struct KeyNormalizer {
    rules: Vec<(String, Regex, String)>,
    strip_params: Vec<String>,
    strip_prefixes: Vec<String>,
}

impl KeyNormalizer {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        let rules = cfg
            .store_id
            .iter()
            .map(|StoreIdRule { host_suffix, pattern, replace }| {
                Ok((host_suffix.clone(), Regex::new(pattern)?, replace.clone()))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self {
            rules,
            strip_params: cfg.strip_query_params.clone(),
            strip_prefixes: cfg.strip_query_prefixes.clone(),
        })
    }

    /// URL canónica: esquema+host en minúsculas, query sin tracking y ordenada, reglas Store-ID.
    pub fn normalize(&self, url: &AbsUrl) -> String {
        let mut params: Vec<&str> = url
            .query
            .as_deref()
            .unwrap_or("")
            .split('&')
            .filter(|p| !p.is_empty())
            .filter(|p| {
                let name = p.split('=').next().unwrap_or("");
                !self.strip_params.iter().any(|s| s == name)
                    && !self.strip_prefixes.iter().any(|pre| name.starts_with(pre.as_str()))
            })
            .collect();
        params.sort_unstable();
        let mut out = format!("{}://{}{}", url.scheme, url.host, url.path);
        if !params.is_empty() {
            out.push('?');
            out.push_str(&params.join("&"));
        }
        for (suffix, re, rep) in &self.rules {
            if matches_suffix(&url.host, suffix) && re.is_match(&out) {
                out = re.replace(&out, rep.as_str()).into_owned();
            }
        }
        out
    }
}

pub struct AbsUrl {
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub query: Option<String>,
}

impl AbsUrl {
    /// Tras la intercepción, Hudsucker entrega URIs absolutas; si no, se usa el header Host.
    pub fn from_request<B>(req: &Request<B>) -> Option<Self> {
        let uri: &Uri = req.uri();
        let host = uri
            .host()
            .map(str::to_owned)
            .or_else(|| {
                req.headers()
                    .get(header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .map(|h| h.split(':').next().unwrap_or(h).to_owned())
            })?
            .to_ascii_lowercase();
        let scheme = uri.scheme_str().unwrap_or("https").to_ascii_lowercase();
        let port = uri.port_u16().filter(|p| !matches!((scheme.as_str(), p), ("http", 80) | ("https", 443)));
        let host = match port {
            Some(p) => format!("{host}:{p}"),
            None => host,
        };
        Some(Self {
            scheme,
            host,
            path: uri.path().to_owned(),
            query: uri.query().map(str::to_owned),
        })
    }

    pub fn hostname(&self) -> &str {
        self.host.split(':').next().unwrap_or(&self.host)
    }
}

/// Las variantes comprimidas se guardan por separado según lo que acepta el cliente.
pub fn encoding_bucket(headers: &HeaderMap) -> &'static str {
    let ae = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ae.contains("br") {
        "br"
    } else if ae.contains("gzip") {
        "gzip"
    } else {
        "identity"
    }
}

/// ¿La petición es candidata? Solo GET anónimos y completos (sin Range ni credenciales).
pub fn request_is_cacheable<B>(req: &Request<B>) -> bool {
    let h = req.headers();
    req.method() == Method::GET
        && !h.contains_key(header::AUTHORIZATION)
        && !h.contains_key(header::RANGE)
        && !cache_control_has(h, "no-store")
}

/// ¿La respuesta se puede compartir entre usuarios?
pub fn response_is_cacheable<B>(res: &Response<B>, max_bytes: usize) -> bool {
    let h = res.headers();
    if res.status() != StatusCode::OK {
        return false;
    }
    if cache_control_has(h, "no-store") || cache_control_has(h, "private") {
        return false;
    }
    // Una respuesta con cookie de sesión es personal: nunca se comparte.
    if h.contains_key(header::SET_COOKIE) {
        return false;
    }
    // Solo se tolera Vary por Accept-Encoding (ya está en la clave).
    if let Some(v) = h.get(header::VARY).and_then(|v| v.to_str().ok()) {
        let ok = v
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .all(|s| s == "accept-encoding" || s.is_empty());
        if !ok {
            return false;
        }
    }
    if let Some(len) = content_length(h) {
        if len > max_bytes {
            return false;
        }
    }
    true
}

/// TTL en segundos. `no-cache` → 0: se guarda pero se revalida siempre (ideal para contenido dinámico con ETag).
pub fn ttl_secs(h: &HeaderMap, default_ttl: u64) -> u64 {
    if cache_control_has(h, "no-cache") || (cache_control_has(h, "must-revalidate") && max_age(h) == Some(0)) {
        return 0;
    }
    max_age(h).unwrap_or(default_ttl)
}

fn max_age(h: &HeaderMap) -> Option<u64> {
    let cc = h.get(header::CACHE_CONTROL)?.to_str().ok()?.to_ascii_lowercase();
    let pick = |name: &str| {
        cc.split(',')
            .map(str::trim)
            .find_map(|d| d.strip_prefix(name)?.strip_prefix('=')?.trim_matches('"').parse::<u64>().ok())
    };
    pick("s-maxage").or_else(|| pick("max-age"))
}

pub fn cache_control_has(h: &HeaderMap, directive: &str) -> bool {
    h.get_all(header::CACHE_CONTROL).iter().any(|v| {
        v.to_str()
            .map(|s| s.split(',').any(|d| d.trim().eq_ignore_ascii_case(directive)))
            .unwrap_or(false)
    })
}

pub fn content_length(h: &HeaderMap) -> Option<usize> {
    h.get(header::CONTENT_LENGTH)?.to_str().ok()?.parse().ok()
}

/// Headers que no deben guardarse ni reenviarse desde caché.
pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "set-cookie"
            | "date"
            | "age"
            | "content-length"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(url: &str) -> String {
        let cfg = Config::default();
        let n = KeyNormalizer::new(&cfg).unwrap();
        let req = Request::get(url).body(()).unwrap();
        n.normalize(&AbsUrl::from_request(&req).unwrap())
    }

    #[test]
    fn quita_tracking_y_ordena_query() {
        assert_eq!(
            norm("https://CDN.Example.com/a.js?v=2&utm_source=x&b=1&fbclid=z"),
            "https://cdn.example.com/a.js?b=1&v=2"
        );
    }

    #[test]
    fn store_id_unifica_espejos() {
        assert_eq!(norm("https://kent.dl.sourceforge.net/x/y.iso"), norm("https://netix.dl.sourceforge.net/x/y.iso"));
    }

    #[test]
    fn sufijos() {
        assert!(matches_suffix("a.cdn.jsdelivr.net", "cdn.jsdelivr.net"));
        assert!(!matches_suffix("evilcdn.jsdelivr.net.attacker.com", "cdn.jsdelivr.net"));
        assert!(!matches_suffix("notjsdelivr.net", "jsdelivr.net"));
    }
}
