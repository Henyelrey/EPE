//! Almacén direccionado por contenido (la idea de ThunderCache 7.1: identificar por QUÉ es, no por la URL).
//!
//! data/objects/ab/abcdef...   → bytes del cuerpo, nombrados por SHA-256 (deduplicación automática)
//! data/meta/cd/cdef01...json  → metadatos por clave (URL normalizada + encoding)
//!
//! El índice caliente vive en memoria (moka); el disco persiste entre reinicios.

use crate::stats::Stats;
use bytes::Bytes;
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub url: String,
    pub key: String,
    pub object: String,
    pub size: u64,
    pub headers: Vec<(String, String)>,
    pub stored_at: u64,
    pub expires_at: u64,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl Meta {
    pub fn is_fresh(&self) -> bool {
        now() < self.expires_at
    }
}

pub struct Store {
    root: PathBuf,
    index: Cache<String, Arc<Meta>>,
    stats: Arc<Stats>,
}

pub enum PutOutcome {
    New,
    Deduplicated,
}

impl Store {
    pub async fn open(root: &Path, mem_entries: u64, stats: Arc<Stats>) -> anyhow::Result<Self> {
        tokio::fs::create_dir_all(root.join("objects")).await?;
        tokio::fs::create_dir_all(root.join("meta")).await?;
        Ok(Self {
            root: root.to_path_buf(),
            index: Cache::builder().max_capacity(mem_entries).build(),
            stats,
        })
    }

    pub fn key_hash(key: &str) -> String {
        hex::encode(Sha256::digest(key.as_bytes()))
    }

    fn sharded(&self, dir: &str, hash: &str, ext: &str) -> PathBuf {
        self.root.join(dir).join(&hash[..2]).join(format!("{hash}{ext}"))
    }

    /// Busca primero en memoria; si no está, en disco (sobrevive reinicios).
    pub async fn get(&self, key_hash: &str) -> Option<Arc<Meta>> {
        if let Some(m) = self.index.get(key_hash).await {
            return Some(m);
        }
        let raw = tokio::fs::read(self.sharded("meta", key_hash, ".json")).await.ok()?;
        let meta: Arc<Meta> = Arc::new(serde_json::from_slice(&raw).ok()?);
        self.index.insert(key_hash.to_owned(), meta.clone()).await;
        Some(meta)
    }

    pub async fn read_object(&self, meta: &Meta) -> Option<Bytes> {
        let path = self.sharded("objects", &meta.object, "");
        let bytes = tokio::fs::read(&path).await.ok()?;
        // Verificación de integridad: si el archivo fue alterado, no se sirve y se borra,
        // para que `put` lo escriba de nuevo en vez de tomarlo por un duplicado válido.
        if hex::encode(Sha256::digest(&bytes)) != meta.object {
            Stats::inc(&self.stats.corrupt_objects);
            tracing::error!("objeto corrupto {}, se descarta", meta.object);
            if let Err(e) = tokio::fs::remove_file(&path).await {
                tracing::warn!(error = %e, "no se pudo borrar el objeto corrupto {}", meta.object);
            }
            return None;
        }
        Some(Bytes::from(bytes))
    }

    /// Guarda cuerpo + metadatos. Si el mismo contenido ya existe (otra URL), no se duplica.
    pub async fn put(&self, key_hash: &str, mut meta: Meta, body: &Bytes) -> anyhow::Result<PutOutcome> {
        let object = hex::encode(Sha256::digest(body));
        meta.object = object.clone();
        meta.size = body.len() as u64;

        let obj_path = self.sharded("objects", &object, "");
        let outcome = if tokio::fs::try_exists(&obj_path).await.unwrap_or(false) {
            PutOutcome::Deduplicated
        } else {
            write_atomic(&obj_path, body).await?;
            PutOutcome::New
        };
        self.write_meta(key_hash, &meta).await?;
        self.index.insert(key_hash.to_owned(), Arc::new(meta)).await;
        Ok(outcome)
    }

    /// Tras un 304 del origen: el contenido sigue válido, solo se extiende la vigencia.
    pub async fn refresh(&self, key_hash: &str, meta: &Meta, ttl: u64) -> anyhow::Result<()> {
        let mut m = meta.clone();
        m.expires_at = now() + ttl;
        self.write_meta(key_hash, &m).await?;
        self.index.insert(key_hash.to_owned(), Arc::new(m)).await;
        Ok(())
    }

    async fn write_meta(&self, key_hash: &str, meta: &Meta) -> anyhow::Result<()> {
        let path = self.sharded("meta", key_hash, ".json");
        write_atomic(&path, &serde_json::to_vec(meta)?).await
    }
}

/// Escribe en un temporal y renombra: nunca queda un archivo a medias si el proceso cae.
async fn write_atomic(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir).await?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    tokio::fs::write(&tmp, data).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Bytes y cantidad de archivos bajo una carpeta. Lo que no se pueda leer no se cuenta.
fn directory_usage(dir: &Path) -> (u64, u64) {
    let (mut bytes, mut files) = (0, 0);
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                pending.push(entry.path());
            } else {
                bytes += metadata.len();
                files += 1;
            }
        }
    }
    (bytes, files)
}

/// Mide el disco en segundo plano: recorrer los archivos es demasiado lento para hacerlo al pedir métricas.
pub fn watch_disk(root: PathBuf, stats: Arc<Stats>, every: Duration) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        loop {
            tick.tick().await;
            let dir = root.clone();
            let measured = tokio::task::spawn_blocking(move || {
                let (object_bytes, objects) = directory_usage(&dir.join("objects"));
                let (meta_bytes, _) = directory_usage(&dir.join("meta"));
                (object_bytes + meta_bytes, objects)
            })
            .await;
            if let Ok((bytes, objects)) = measured {
                stats.disk_used_bytes.store(bytes, Relaxed);
                stats.disk_objects.store(objects, Relaxed);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> Meta {
        Meta {
            url: "https://cdn.example.com/a.js".into(),
            key: "k".into(),
            object: String::new(),
            size: 0,
            headers: vec![],
            stored_at: now(),
            expires_at: now() + 60,
            etag: None,
            last_modified: None,
        }
    }

    #[tokio::test]
    async fn objeto_corrupto_se_borra_y_se_repara() {
        let root = std::env::temp_dir().join(format!("rayo-store-test-{}", std::process::id()));
        let stats = Arc::new(Stats::default());
        let store = Store::open(&root, 10, stats.clone()).await.unwrap();
        let body = Bytes::from_static(b"contenido");
        let key = Store::key_hash("k");

        assert!(matches!(store.put(&key, meta(), &body).await.unwrap(), PutOutcome::New));
        let saved = store.get(&key).await.unwrap();
        assert_eq!(store.read_object(&saved).await.unwrap(), body);
        assert_eq!(stats.corrupt_objects.load(Relaxed), 0);

        let (bytes, objects) = directory_usage(&root.join("objects"));
        assert_eq!((bytes, objects), (body.len() as u64, 1));

        let path = store.sharded("objects", &saved.object, "");
        tokio::fs::write(&path, b"alterado").await.unwrap();
        assert!(store.read_object(&saved).await.is_none());
        assert!(!path.exists());
        assert_eq!(stats.corrupt_objects.load(Relaxed), 1);

        assert!(matches!(store.put(&key, meta(), &body).await.unwrap(), PutOutcome::New));
        assert_eq!(store.read_object(&saved).await.unwrap(), body);

        tokio::fs::remove_dir_all(&root).await.unwrap();
    }
}
