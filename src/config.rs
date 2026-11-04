//! Configuración cargada desde `config.toml`.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Dirección donde escucha el proxy (configúralo como proxy HTTP/HTTPS en el navegador o SO).
    pub listen: String,
    /// IPs o subredes (CIDR) que pueden usar el proxy. Para abrirlo a la red, agrega su subred
    /// aquí y cambia `listen`; el proxy no arranca si eso lo dejaría abierto a cualquiera.
    pub allowed_clients: Vec<String>,
    /// Peticiones por minuto que se aceptan de cada IP (0 = sin límite).
    pub rate_limit_per_minute: u32,
    /// Redes internas que los clientes SÍ pueden alcanzar a través del proxy, como una intranet.
    /// Todas las demás, incluidos este equipo y la red local, están bloqueadas.
    pub allowed_internal_networks: Vec<String>,
    /// Memoria total para objetos en RAM. Lo que no quepa se atiende en streaming, sin caché.
    pub max_buffered_bytes: u64,
    /// Segundos que una petición espera a otra igual que ya fue al origen (0 = no esperar).
    pub coalesce_wait_secs: u64,
    /// Carpeta donde se guardan objetos (por hash de contenido) y metadatos.
    pub data_dir: PathBuf,
    /// Certificado y llave de la CA local. Si no existen, se generan al arrancar.
    pub ca_cert: PathBuf,
    pub ca_key: PathBuf,
    /// Tamaño máximo de un objeto cacheable (bytes). Lo que supere esto pasa sin cachear.
    pub max_object_bytes: usize,
    /// TTL por defecto cuando el origen no envía `max-age`.
    pub default_ttl_secs: u64,
    /// Entradas máximas del índice en memoria (el disco conserva el resto).
    pub mem_index_entries: u64,
    /// Cachear también tráfico HTTP plano (sin TLS).
    pub cache_plain_http: bool,
    /// Sufijos de dominio cuyo TLS SÍ se descifra para cachear. Todo lo demás va en passthrough.
    pub intercept_domains: Vec<String>,
    /// Sufijos que NUNCA se interceptan ni se cachean, aunque coincidan con la lista anterior
    /// o lleguen por HTTP plano (bancos, apps con certificate pinning, servicios sensibles).
    pub never_intercept: Vec<String>,
    /// Parámetros de query que se eliminan antes de calcular la clave (tracking, cache-busters).
    pub strip_query_params: Vec<String>,
    /// Prefijos de parámetros a eliminar (p. ej. "utm_").
    pub strip_query_prefixes: Vec<String>,
    /// Reglas tipo Store-ID: normalizan URLs distintas que apuntan al mismo contenido.
    pub store_id: Vec<StoreIdRule>,
    /// Host virtual que devuelve estadísticas en JSON: http://rayo.stats/
    pub stats_host: String,
    /// CAs adicionales en las que confiar al conectar con orígenes (intranet, laboratorio).
    pub upstream_extra_ca: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreIdRule {
    /// La regla aplica si el host termina en este sufijo.
    pub host_suffix: String,
    /// Expresión regular sobre la URL normalizada.
    pub pattern: String,
    /// Reemplazo (admite $1, $2...).
    pub replace: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:3128".into(),
            allowed_clients: vec!["127.0.0.1/32".into(), "::1/128".into()],
            rate_limit_per_minute: 6000,
            allowed_internal_networks: vec![],
            max_buffered_bytes: 512 * 1024 * 1024,
            coalesce_wait_secs: 10,
            data_dir: "./data".into(),
            ca_cert: "./ca/rayo-ca.crt".into(),
            ca_key: "./ca/rayo-ca.key".into(),
            max_object_bytes: 64 * 1024 * 1024,
            default_ttl_secs: 3600,
            mem_index_entries: 200_000,
            cache_plain_http: true,
            intercept_domains: vec![
                // Ejemplos de contenido público y pesado. Ajusta a tu red.
                "download.mozilla.org".into(),
                "cdn.jsdelivr.net".into(),
                "cdnjs.cloudflare.com".into(),
                "fonts.gstatic.com".into(),
                "upload.wikimedia.org".into(),
            ],
            never_intercept: vec![
                "bcp.com.pe".into(),
                "interbank.pe".into(),
                "bbva.pe".into(),
                "accounts.google.com".into(),
                "login.microsoftonline.com".into(),
            ],
            strip_query_params: vec!["fbclid".into(), "gclid".into(), "_".into()],
            strip_query_prefixes: vec!["utm_".into()],
            store_id: vec![StoreIdRule {
                // Ejemplo: espejos numerados de un mismo CDN → una sola clave.
                host_suffix: "dl.sourceforge.net".into(),
                pattern: r"^https?://[^/]+\.dl\.sourceforge\.net/(.*)$".into(),
                replace: "https://dl.sourceforge.net.rayo/$1".into(),
            }],
            stats_host: "rayo.stats".into(),
            upstream_extra_ca: vec![],
        }
    }
}

impl Config {
    /// Carga la configuración; si el archivo no existe, escribe uno por defecto.
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let raw = std::fs::read_to_string(path)?;
            Ok(toml::from_str(&raw)?)
        } else {
            let cfg = Self::default();
            std::fs::write(path, toml::to_string_pretty(&cfg)?)?;
            tracing::info!("config por defecto escrita en {}", path.display());
            Ok(cfg)
        }
    }

    pub fn should_intercept(&self, host: &str) -> bool {
        if self.is_never_intercept(host) {
            return false;
        }
        let host = canonical_host(host);
        self.intercept_domains.iter().any(|s| matches_suffix(&host, s))
    }

    /// Dominios protegidos: no se descifran ni se cachean, tampoco por HTTP plano.
    pub fn is_never_intercept(&self, host: &str) -> bool {
        let host = canonical_host(host);
        self.never_intercept.iter().any(|s| matches_suffix(&host, s))
    }
}

fn canonical_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// `a.b.example.com` coincide con `example.com`, pero `badexample.com` no.
pub fn matches_suffix(host: &str, suffix: &str) -> bool {
    let suffix = suffix.trim_start_matches('.').to_ascii_lowercase();
    host == suffix || host.ends_with(&format!(".{suffix}"))
}
