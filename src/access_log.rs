//! Log de acceso: un archivo JSONL por día (UTC), con retención limitada y datos reducidos al mínimo.
//!
//! Nunca incluye parámetros de la URL, cookies, credenciales ni cuerpos. La IP se reemplaza por un
//! seudónimo calculado con una clave que solo vive en memoria y cambia cada día: dentro de un día se
//! puede seguir a un mismo dispositivo, pero no volver a la IP ni relacionar días distintos.
//!
//! Escribir nunca retrasa una petición: las líneas pasan por una cola y, si se llena, se descartan y se cuentan.
//! Si cambia lo que se registra aquí, hay que actualizar notice.rs y docs/AVISO.md.

use crate::config::{ClientIpMode, Config};
use crate::secure::{random_bytes, restrict_to_owner};
use crate::stats::{Outcome, Stats};
use crate::store::now;
use anyhow::{bail, Context};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;

const SECS_PER_DAY: u64 = 86_400;
const QUEUE_LINES: usize = 10_000;
/// Las rutas absurdamente largas se recortan: no aportan nada y permitirían llenar el disco más rápido.
const MAX_FIELD_CHARS: usize = 512;
const PURGE_EVERY: Duration = Duration::from_secs(3600);

/// Fecha UTC (año, mes, día) de un número de días desde 1970. Algoritmo de "days from civil", de H. Hinnant.
fn civil_date(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

fn date_string(days: u64) -> String {
    let (y, m, d) = civil_date(days);
    format!("{y:04}-{m:02}-{d:02}")
}

fn timestamp(secs: u64) -> String {
    let rest = secs % SECS_PER_DAY;
    format!("{}T{:02}:{:02}:{:02}Z", date_string(secs / SECS_PER_DAY), rest / 3600, rest % 3600 / 60, rest % 60)
}

fn file_name(days: u64) -> String {
    format!("access-{}.jsonl", date_string(days))
}

/// Archivos de esta carpeta cuya fecha ya venció. Solo considera nombres con el formato exacto del
/// log: cualquier otro archivo que haya en la carpeta nunca se toca.
fn expired_files<'a>(names: impl Iterator<Item = &'a str>, today: u64, retention_days: u64) -> Vec<&'a str> {
    let oldest_kept = file_name(today.saturating_sub(retention_days.saturating_sub(1)));
    names.filter(|name| is_log_name(name) && *name < oldest_kept.as_str()).collect()
}

fn is_log_name(name: &str) -> bool {
    let Some(date) = name.strip_prefix("access-").and_then(|n| n.strip_suffix(".jsonl")) else {
        return false;
    };
    date.len() == 10
        && date.bytes().enumerate().all(|(i, b)| match i {
            4 | 7 => b == b'-',
            _ => b.is_ascii_digit(),
        })
}

/// Seudónimos por IP, con una clave distinta cada día que nunca se escribe en disco.
struct Pseudonyms {
    key: Mutex<(u64, [u8; 32])>,
}

impl Pseudonyms {
    fn new() -> Self {
        Self { key: Mutex::new((0, [0; 32])) }
    }

    fn pseudonym(&self, ip: IpAddr, day: u64) -> String {
        let key = {
            let mut current = self.key.lock().expect("la clave de seudónimos no se envenena");
            if current.0 != day {
                *current = (day, random_bytes());
            }
            current.1
        };
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(ip.to_canonical().to_string().as_bytes());
        hex::encode(&hasher.finalize()[..8])
    }
}

/// Lo que se sabe de una petición al terminar.
pub struct Record<'a> {
    pub client: IpAddr,
    pub method: &'a str,
    pub scheme: Option<&'a str>,
    pub host: &'a str,
    pub port: Option<u16>,
    /// Solo la ruta: los parámetros nunca llegan hasta aquí.
    pub path: Option<&'a str>,
    pub outcome: Outcome,
    pub status: Option<u16>,
    /// `None` si no se puede saber, como en un túnel.
    pub bytes: Option<u64>,
    pub elapsed: Duration,
}

#[derive(Serialize)]
struct Line<'a> {
    ts: String,
    client: Option<String>,
    method: &'a str,
    scheme: Option<&'a str>,
    host: &'a str,
    port: Option<u16>,
    path: Option<&'a str>,
    result: &'a str,
    status: Option<u16>,
    bytes: Option<u64>,
    ms: u64,
}

fn clip(text: &str) -> &str {
    match text.char_indices().nth(MAX_FIELD_CHARS) {
        Some((end, _)) => &text[..end],
        None => text,
    }
}

pub struct AccessLog {
    queue: Option<mpsc::Sender<String>>,
    /// `None` si el registro no debe incluir nada sobre el cliente.
    pseudonyms: Option<Pseudonyms>,
    stats: Arc<Stats>,
}

impl AccessLog {
    /// Prepara la carpeta y lanza la tarea que escribe. Si está desactivado, `record` no hace nada.
    pub fn start(cfg: &Config, stats: Arc<Stats>) -> anyhow::Result<Self> {
        if !cfg.access_log_enabled {
            return Ok(Self { queue: None, pseudonyms: None, stats });
        }
        if cfg.access_log_retention_days == 0 {
            bail!("access_log_retention_days debe ser al menos 1");
        }
        std::fs::create_dir_all(&cfg.access_log_dir)
            .with_context(|| format!("creando {}", cfg.access_log_dir.display()))?;
        let (tx, rx) = mpsc::channel(QUEUE_LINES);
        tokio::spawn(write_loop(rx, cfg.access_log_dir.clone(), cfg.access_log_retention_days, stats.clone()));
        let pseudonyms = match cfg.access_log_client_ip {
            ClientIpMode::Pseudonym => Some(Pseudonyms::new()),
            ClientIpMode::None => None,
        };
        Ok(Self { queue: Some(tx), pseudonyms, stats })
    }

    pub fn record(&self, r: Record<'_>) {
        let Some(queue) = &self.queue else {
            return;
        };
        let secs = now();
        let line = Line {
            ts: timestamp(secs),
            client: self.pseudonyms.as_ref().map(|p| p.pseudonym(r.client, secs / SECS_PER_DAY)),
            method: clip(r.method),
            scheme: r.scheme,
            host: clip(r.host),
            port: r.port,
            path: r.path.filter(|_| r.outcome.is_public_copy()).map(clip),
            result: r.outcome.label(),
            status: r.status,
            bytes: r.bytes,
            ms: r.elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
        };
        let Ok(mut text) = serde_json::to_string(&line) else {
            return;
        };
        text.push('\n');
        if queue.try_send(text).is_err() {
            Stats::inc(&self.stats.access_log_dropped);
        }
    }
}

async fn write_loop(mut rx: mpsc::Receiver<String>, dir: PathBuf, retention_days: u64, stats: Arc<Stats>) {
    let mut current: Option<(u64, BufWriter<tokio::fs::File>)> = None;
    // El primer tick es inmediato, y sigue purgando aunque no haya tráfico: la retención es una promesa.
    let mut purge = tokio::time::interval(PURGE_EVERY);
    loop {
        tokio::select! {
            _ = purge.tick() => purge_expired(&dir, retention_days).await,
            line = rx.recv() => {
                let Some(line) = line else { break };
                write_line(&mut current, &dir, &line, &stats).await;
                while let Ok(line) = rx.try_recv() {
                    write_line(&mut current, &dir, &line, &stats).await;
                }
                if let Some((_, file)) = &mut current {
                    if let Err(e) = file.flush().await {
                        Stats::inc(&stats.access_log_errors);
                        tracing::warn!(error = %e, "no se pudo escribir el log de acceso");
                    }
                }
            }
        }
    }
}

async fn write_line(current: &mut Option<(u64, BufWriter<tokio::fs::File>)>, dir: &Path, line: &str, stats: &Stats) {
    let today = now() / SECS_PER_DAY;
    if current.as_ref().is_none_or(|(day, _)| *day != today) {
        if let Some((_, mut old)) = current.take() {
            let _ = old.flush().await;
        }
        match open_for_day(dir, today).await {
            Ok(file) => *current = Some((today, BufWriter::new(file))),
            Err(e) => {
                Stats::inc(&stats.access_log_errors);
                tracing::warn!(error = %e, "no se pudo abrir el log de acceso");
                return;
            }
        }
    }
    if let Some((_, file)) = current {
        if let Err(e) = file.write_all(line.as_bytes()).await {
            Stats::inc(&stats.access_log_errors);
            tracing::warn!(error = %e, "no se pudo escribir el log de acceso");
        }
    }
}

async fn open_for_day(dir: &Path, day: u64) -> anyhow::Result<tokio::fs::File> {
    let path = dir.join(file_name(day));
    let file = tokio::fs::OpenOptions::new().create(true).append(true).open(&path).await?;
    // Se protege antes de escribir la primera línea.
    let to_protect = path.clone();
    tokio::task::spawn_blocking(move || restrict_to_owner(&to_protect)).await??;
    Ok(file)
}

async fn purge_expired(dir: &Path, retention_days: u64) {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    let mut names = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Ok(name) = entry.file_name().into_string() {
            names.push(name);
        }
    }
    for name in expired_files(names.iter().map(String::as_str), now() / SECS_PER_DAY, retention_days) {
        if let Err(e) = tokio::fs::remove_file(dir.join(name)).await {
            tracing::warn!(error = %e, "no se pudo borrar el log vencido {name}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn fechas_utc() {
        assert_eq!(date_string(0), "1970-01-01");
        assert_eq!(date_string(11_016), "2000-02-29");
        assert_eq!(date_string(20_760), "2026-11-03");
        assert_eq!(timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(timestamp(1_793_755_022), "2026-11-04T01:17:02Z");
    }

    #[test]
    fn el_seudonimo_es_estable_en_el_dia_y_no_revela_la_ip() {
        let p = Pseudonyms::new();
        let a = p.pseudonym(ip("192.168.1.10"), 100);
        assert_eq!(a, p.pseudonym(ip("192.168.1.10"), 100));
        assert_eq!(a, p.pseudonym(ip("::ffff:192.168.1.10"), 100));
        assert_ne!(a, p.pseudonym(ip("192.168.1.11"), 100));
        assert_eq!(a.len(), 16);
        assert!(!a.contains("192"));
    }

    #[test]
    fn el_seudonimo_cambia_de_un_dia_a_otro() {
        let p = Pseudonyms::new();
        assert_ne!(p.pseudonym(ip("192.168.1.10"), 100), p.pseudonym(ip("192.168.1.10"), 101));
    }

    #[test]
    fn la_clave_no_es_la_misma_en_dos_arranques() {
        assert_ne!(Pseudonyms::new().pseudonym(ip("10.0.0.1"), 100), Pseudonyms::new().pseudonym(ip("10.0.0.1"), 100));
    }

    #[test]
    fn la_retencion_solo_borra_logs_vencidos() {
        let today = 20_760; // 2026-11-03
        let names = [
            "access-2026-11-03.jsonl",
            "access-2026-10-28.jsonl", // 7.º día: se conserva
            "access-2026-10-27.jsonl", // 8.º día: vencido
            "access-2020-01-01.jsonl",
            "access-2020-01-01.jsonl.bak",
            "access-viejo.jsonl",
            "notas.txt",
        ];
        assert_eq!(
            expired_files(names.iter().copied(), today, 7),
            ["access-2026-10-27.jsonl", "access-2020-01-01.jsonl"]
        );
        assert!(expired_files(names.iter().copied(), today, 1).contains(&"access-2026-10-28.jsonl"));
    }

    #[test]
    fn recorta_campos_enormes_sin_romper_caracteres() {
        let long = "ñ".repeat(MAX_FIELD_CHARS + 5);
        assert_eq!(clip(&long).chars().count(), MAX_FIELD_CHARS);
        assert_eq!(clip("corto"), "corto");
    }

    #[tokio::test]
    async fn escribe_una_linea_json_por_peticion() {
        let dir = std::env::temp_dir().join(format!("rayo-log-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config { access_log_enabled: true, access_log_dir: dir.clone(), ..Config::default() };
        let log = AccessLog::start(&cfg, Arc::new(Stats::default())).unwrap();
        let request = |outcome| Record {
            client: ip("192.168.1.10"),
            method: "GET",
            scheme: Some("https"),
            host: "cdn.example.com",
            port: None,
            path: Some("/a.js"),
            outcome,
            status: Some(200),
            bytes: Some(10),
            elapsed: Duration::from_millis(3),
        };
        log.record(request(Outcome::Hit));
        log.record(request(Outcome::Bypass));

        let path = dir.join(file_name(now() / SECS_PER_DAY));
        let mut text = String::new();
        for _ in 0..100 {
            text = std::fs::read_to_string(&path).unwrap_or_default();
            if text.lines().count() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let lines: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines[0]["result"], "hit");
        assert_eq!(lines[0]["path"], "/a.js");
        assert_eq!(lines[0]["ms"], 3);
        assert_eq!(lines[0]["client"].as_str().unwrap().len(), 16);
        assert_eq!(lines[1]["result"], "bypass");
        assert!(lines[1]["path"].is_null(), "la ruta de un contenido no público no se registra");
        assert!(!text.contains("192.168"));
        drop(log);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn desactivado_no_crea_nada() {
        let dir = std::env::temp_dir().join(format!("rayo-log-off-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config { access_log_dir: dir.clone(), ..Config::default() };
        assert!(!cfg.access_log_enabled, "el log de acceso debe venir apagado");
        let log = AccessLog::start(&cfg, Arc::new(Stats::default())).unwrap();
        log.record(Record {
            client: ip("10.0.0.1"),
            method: "GET",
            scheme: None,
            host: "x",
            port: None,
            path: None,
            outcome: Outcome::Tunnel,
            status: None,
            bytes: None,
            elapsed: Duration::ZERO,
        });
        assert!(!dir.exists());
    }
}
