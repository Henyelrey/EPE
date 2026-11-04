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
    /// Host virtual con el aviso de transparencia para los usuarios: http://rayo.aviso/
    pub notice_host: String,
    /// Cómo contactar a quien administra el proxy. Se muestra en el aviso.
    pub operator_contact: String,
    /// CAs adicionales en las que confiar al conectar con orígenes (intranet, laboratorio).
    pub upstream_extra_ca: Vec<PathBuf>,
    /// Puerto de administración con /metrics, protegido por token. Vacío = desactivado.
    pub admin_listen: String,
    /// Archivo con el token de administración. Si no existe, se genera al arrancar.
    pub admin_token_file: PathBuf,
    /// Espacio máximo de la caché en disco. Al llegar a él se borra lo usado hace más tiempo (0 = sin límite).
    pub max_disk_bytes: u64,
    /// Cada cuántos segundos se guardan los contadores y se evalúan las alertas.
    pub maintenance_interval_secs: u64,
    /// Alerta si el volumen de la caché tiene menos de este porcentaje libre.
    pub alert_disk_free_percent: u64,
    /// Alerta cuando a la CA le queden estos días o menos.
    pub alert_ca_days: u64,
    /// Alerta si este porcentaje de las peticiones recientes no pudo contactar al origen.
    pub alert_origin_error_percent: u64,
    /// Totales por cliente en memoria, visibles solo con el token. Apagado por defecto:
    /// son datos sobre personas. El aviso de transparencia indica si está activo.
    pub client_stats_enabled: bool,
    /// Log de acceso por petición. Apagado por defecto: registra actividad de personas, y
    /// activarlo debe ser una decisión deliberada. El aviso de transparencia indica si está activo.
    pub access_log_enabled: bool,
    /// Carpeta del log de acceso: un archivo por día.
    pub access_log_dir: PathBuf,
    /// Días que se conserva el log de acceso, contando el de hoy.
    pub access_log_retention_days: u64,
    /// Qué se anota sobre el cliente. La IP real no es una opción.
    pub access_log_client_ip: ClientIpMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientIpMode {
    /// Identificador calculado con una clave que cambia cada día y solo vive en memoria.
    Pseudonym,
    /// Nada que permita distinguir a un cliente de otro.
    None,
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
            notice_host: "rayo.aviso".into(),
            operator_contact: String::new(),
            upstream_extra_ca: vec![],
            admin_listen: "127.0.0.1:9128".into(),
            admin_token_file: "./ca/admin.token".into(),
            max_disk_bytes: 10 * 1024 * 1024 * 1024,
            maintenance_interval_secs: 60,
            alert_disk_free_percent: 10,
            alert_ca_days: 30,
            alert_origin_error_percent: 20,
            client_stats_enabled: false,
            access_log_enabled: false,
            access_log_dir: "./logs".into(),
            access_log_retention_days: 7,
            access_log_client_ip: ClientIpMode::Pseudonym,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_configuracion_por_defecto_se_puede_escribir_y_releer() {
        let text = toml::to_string_pretty(&Config::default()).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back.access_log_client_ip, ClientIpMode::Pseudonym);
        assert!(text.contains("access_log_client_ip = \"pseudonym\""));
    }

    #[test]
    fn una_configuracion_anterior_no_activa_el_log_de_acceso() {
        let old: Config = toml::from_str("listen = \"127.0.0.1:3128\"").unwrap();
        assert!(!old.access_log_enabled);
        assert!(!old.client_stats_enabled);
        assert_eq!(old.access_log_retention_days, 7);
    }

    #[test]
    fn la_ip_real_no_es_una_opcion() {
        assert!(toml::from_str::<Config>("access_log_client_ip = \"none\"").is_ok());
        assert!(toml::from_str::<Config>("access_log_client_ip = \"real\"").is_err());
    }
}
