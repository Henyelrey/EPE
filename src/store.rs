//! Almacén direccionado por contenido (la idea de ThunderCache 7.1: identificar por QUÉ es, no por la URL).
//!
//! data/objects/ab/abcdef...   → bytes del cuerpo, nombrados por SHA-256 (deduplicación automática)
//! data/meta/cd/cdef01...json  → metadatos por clave (URL normalizada + encoding)
//!
//! El índice caliente vive en memoria (moka); el disco persiste entre reinicios.
//!
//! `DiskIndex` lleva la cuenta de lo que hay en disco para no pasar de `max_disk_bytes`. Al llegar al
//! límite se borran las entradas usadas hace más tiempo, y un objeto solo cuando ninguna URL lo usa.
//!
//! El índice decide cuánto borrar, pero el archivo manda sobre si un objeto existe. Si un borrado se cruza
//! con una escritura y se pierde un archivo, `read_object` no lo encuentra, se pide de nuevo al origen y
//! `put` lo vuelve a escribir.

use crate::stats::Stats;
use bytes::Bytes;
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

/// Al pasar del límite se libera hasta quedar en este porcentaje, para no expulsar en cada escritura.
const EVICT_TARGET_PERCENT: u64 = 90;

type Hash = [u8; 32];

fn parse_hash(text: &str) -> Option<Hash> {
    let mut hash = [0; 32];
    hex::decode_to_slice(text, &mut hash).ok()?;
    Some(hash)
}

/// La URL no incluye los parámetros: pueden contener tokens y aquí no hacen falta,
/// porque el archivo se encuentra por el hash de la clave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub url: String,
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

struct DiskEntry {
    object: Hash,
    last_used: u64,
    meta_bytes: u64,
}

struct DiskObject {
    size: u64,
    /// Cuántas entradas apuntan a este contenido.
    refs: u32,
}

/// Lo que se liberó al quitar una entrada.
struct Removed {
    key: Hash,
    /// El objeto, si ya ninguna entrada lo usa y hay que borrarlo.
    orphan: Option<Hash>,
    bytes: u64,
}

/// Qué hay en disco y en qué orden se usó. Los tiempos están en segundos: dentro de un
/// mismo segundo, el orden de expulsión es arbitrario.
#[derive(Default)]
struct DiskIndex {
    entries: HashMap<Hash, DiskEntry>,
    objects: HashMap<Hash, DiskObject>,
    by_use: BTreeSet<(u64, Hash)>,
    used: u64,
}

impl DiskIndex {
    /// Marca una entrada como recién usada.
    fn touch(&mut self, key: &Hash, now: u64) {
        if let Some(entry) = self.entries.get_mut(key) {
            if entry.last_used < now {
                self.by_use.remove(&(entry.last_used, *key));
                entry.last_used = now;
                self.by_use.insert((now, *key));
            }
        }
    }

    /// Registra una entrada. Si reemplaza a otra, devuelve el objeto anterior cuando ya nadie lo usa.
    fn insert(&mut self, key: Hash, object: Hash, size: u64, meta_bytes: u64, last_used: u64) -> Option<Hash> {
        let replaced = self.remove(&key);
        let target = self.objects.entry(object).or_insert_with(|| {
            self.used += size;
            DiskObject { size, refs: 0 }
        });
        target.refs += 1;
        self.used += meta_bytes;
        self.entries.insert(key, DiskEntry { object, last_used, meta_bytes });
        self.by_use.insert((last_used, key));
        // Si el contenido no cambió, el objeto volvió a quedar en uso y no hay nada que borrar.
        replaced.and_then(|r| r.orphan).filter(|old| *old != object)
    }

    fn remove(&mut self, key: &Hash) -> Option<Removed> {
        let entry = self.entries.remove(key)?;
        self.by_use.remove(&(entry.last_used, *key));
        let mut bytes = entry.meta_bytes;
        let mut orphan = None;
        if let Some(object) = self.objects.get_mut(&entry.object) {
            object.refs -= 1;
            if object.refs == 0 {
                bytes += object.size;
                self.objects.remove(&entry.object);
                orphan = Some(entry.object);
            }
        }
        self.used -= bytes;
        Some(Removed { key: *key, orphan, bytes })
    }

    fn remove_oldest(&mut self) -> Option<Removed> {
        let &(_, key) = self.by_use.first()?;
        self.remove(&key)
    }
}

/// Reconstruye el índice desde el disco y limpia lo que no sirve: metadatos ilegibles o sin objeto,
/// objetos sin metadatos y temporales de un corte. Solo toca archivos con los nombres exactos que usa
/// el proxy. Requiere que ningún otro proceso use la misma carpeta.
fn scan_disk(root: &Path) -> DiskIndex {
    let mut index = DiskIndex::default();
    for path in files_under(&root.join("meta")) {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if is_leftover_temp(name) {
            remove_if_possible(&path);
            continue;
        }
        let Some(key) = name.strip_suffix(".json").and_then(parse_hash) else {
            continue;
        };
        match load_entry(root, &path) {
            Some((object, size, meta_bytes, last_used)) => {
                index.insert(key, object, size, meta_bytes, last_used);
            }
            None => remove_if_possible(&path),
        }
    }
    for path in files_under(&root.join("objects")) {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let orphan = parse_hash(name).is_some_and(|hash| !index.objects.contains_key(&hash));
        if orphan || is_leftover_temp(name) {
            remove_if_possible(&path);
        }
    }
    index
}

/// Lee una entrada para el índice. Las escritas por versiones anteriores se reescriben sin parámetros.
/// Tras un reinicio, el último uso se aproxima con la fecha del archivo.
fn load_entry(root: &Path, path: &Path) -> Option<(Hash, u64, u64, u64)> {
    let raw = std::fs::read(path).ok()?;
    let mut meta: Meta = serde_json::from_slice(&raw).ok()?;
    let object = parse_hash(&meta.object)?;
    let size = std::fs::metadata(sharded_path(root, "objects", &meta.object, "")).ok()?.len();
    let metadata = std::fs::metadata(path).ok()?;
    let mut meta_bytes = metadata.len();
    let last_used = metadata.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs());

    if meta.url.contains('?') || raw.windows(6).any(|w| w == b"\"key\":") {
        meta.url.truncate(meta.url.find('?').unwrap_or(meta.url.len()));
        let clean = serde_json::to_vec(&meta).ok()?;
        if std::fs::write(path, &clean).is_ok() {
            meta_bytes = clean.len() as u64;
        }
    }
    Some((object, size, meta_bytes, last_used))
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => pending.push(entry.path()),
                Ok(kind) if kind.is_file() => files.push(entry.path()),
                _ => {}
            }
        }
    }
    files
}

/// `<hash>.tmp<pid>`, el nombre que usa `write_atomic`.
fn is_leftover_temp(name: &str) -> bool {
    name.split_once(".tmp").is_some_and(|(hash, pid)| {
        parse_hash(hash).is_some() && !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit())
    })
}

fn remove_if_possible(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        tracing::warn!(error = %e, "no se pudo borrar {}", path.display());
    }
}

async fn remove_quietly(path: &Path) {
    if let Err(e) = tokio::fs::remove_file(path).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(error = %e, "no se pudo borrar {}", path.display());
        }
    }
}

fn sharded_path(root: &Path, dir: &str, hash: &str, ext: &str) -> PathBuf {
    root.join(dir).join(&hash[..2]).join(format!("{hash}{ext}"))
}

fn lock(disk: &Mutex<DiskIndex>) -> MutexGuard<'_, DiskIndex> {
    disk.lock().expect("el índice de disco no se envenena")
}

fn publish_usage(index: &DiskIndex, stats: &Stats) {
    stats.disk_used_bytes.store(index.used, Relaxed);
    stats.disk_objects.store(index.objects.len() as u64, Relaxed);
}

/// Borra lo usado hace más tiempo cuando se pasa del límite. Corre aparte para no retrasar a los clientes.
async fn evict_loop(
    root: PathBuf,
    cache: Cache<String, Arc<Meta>>,
    disk: Arc<Mutex<DiskIndex>>,
    limit: u64,
    wake: Arc<Notify>,
    stats: Arc<Stats>,
) {
    let target = limit / 100 * EVICT_TARGET_PERCENT;
    loop {
        wake.notified().await;
        loop {
            let removed = {
                let mut index = lock(&disk);
                let removed = if index.used > target { index.remove_oldest() } else { None };
                publish_usage(&index, &stats);
                removed
            };
            let Some(removed) = removed else {
                break;
            };
            let key = hex::encode(removed.key);
            cache.invalidate(&key).await;
            remove_quietly(&sharded_path(&root, "meta", &key, ".json")).await;
            if let Some(object) = removed.orphan {
                remove_quietly(&sharded_path(&root, "objects", &hex::encode(object), "")).await;
            }
            Stats::inc(&stats.evicted_entries);
            Stats::add(&stats.evicted_bytes, removed.bytes);
        }
    }
}

pub struct Store {
    root: PathBuf,
    index: Cache<String, Arc<Meta>>,
    disk: Arc<Mutex<DiskIndex>>,
    /// Bytes máximos en disco (0 = sin límite).
    limit: u64,
    evict: Arc<Notify>,
    stats: Arc<Stats>,
}

pub enum PutOutcome {
    New,
    Deduplicated,
}

impl Store {
    pub async fn open(root: &Path, mem_entries: u64, limit: u64, stats: Arc<Stats>) -> anyhow::Result<Self> {
        tokio::fs::create_dir_all(root.join("objects")).await?;
        tokio::fs::create_dir_all(root.join("meta")).await?;

        let dir = root.to_path_buf();
        let scanned = tokio::task::spawn_blocking(move || scan_disk(&dir)).await?;
        tracing::info!(entradas = scanned.entries.len(), objetos = scanned.objects.len(), bytes = scanned.used, "caché en disco revisada");
        publish_usage(&scanned, &stats);
        stats.disk_limit_bytes.store(limit, Relaxed);

        let over_limit = limit > 0 && scanned.used > limit;
        let store = Self {
            root: root.to_path_buf(),
            index: Cache::builder().max_capacity(mem_entries).build(),
            disk: Arc::new(Mutex::new(scanned)),
            limit,
            evict: Arc::new(Notify::new()),
            stats,
        };
        if limit > 0 {
            tokio::spawn(evict_loop(
                store.root.clone(),
                store.index.clone(),
                store.disk.clone(),
                limit,
                store.evict.clone(),
                store.stats.clone(),
            ));
        }
        if over_limit {
            store.evict.notify_one();
        }
        Ok(store)
    }

    pub fn key_hash(key: &str) -> String {
        hex::encode(Sha256::digest(key.as_bytes()))
    }

    fn sharded(&self, dir: &str, hash: &str, ext: &str) -> PathBuf {
        sharded_path(&self.root, dir, hash, ext)
    }

    /// Busca primero en memoria; si no está, en disco (sobrevive reinicios).
    pub async fn get(&self, key_hash: &str) -> Option<Arc<Meta>> {
        let meta = match self.index.get(key_hash).await {
            Some(meta) => meta,
            None => {
                let raw = tokio::fs::read(self.sharded("meta", key_hash, ".json")).await.ok()?;
                let meta: Arc<Meta> = Arc::new(serde_json::from_slice(&raw).ok()?);
                self.index.insert(key_hash.to_owned(), meta.clone()).await;
                meta
            }
        };
        if let Some(key) = parse_hash(key_hash) {
            lock(&self.disk).touch(&key, now());
        }
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
        let meta_bytes = self.write_meta(key_hash, &meta).await?;
        let size = meta.size;
        self.index.insert(key_hash.to_owned(), Arc::new(meta)).await;

        let orphan = match (parse_hash(key_hash), parse_hash(&object)) {
            (Some(key), Some(hash)) => {
                let mut index = lock(&self.disk);
                let orphan = index.insert(key, hash, size, meta_bytes, now());
                publish_usage(&index, &self.stats);
                if self.limit > 0 && index.used > self.limit {
                    self.evict.notify_one();
                }
                orphan
            }
            _ => None,
        };
        // El contenido de esta URL cambió y ninguna otra usaba el anterior.
        if let Some(old) = orphan {
            remove_quietly(&self.sharded("objects", &hex::encode(old), "")).await;
        }
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

    /// Devuelve cuánto ocupa el archivo escrito.
    async fn write_meta(&self, key_hash: &str, meta: &Meta) -> anyhow::Result<u64> {
        let path = self.sharded("meta", key_hash, ".json");
        let data = serde_json::to_vec(meta)?;
        write_atomic(&path, &data).await?;
        Ok(data.len() as u64)
    }
}

/// Escribe en un temporal y renombra: nunca queda un archivo a medias si el proceso cae.
pub async fn write_atomic(path: &Path, data: &[u8]) -> anyhow::Result<()> {
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

/// Espacio disponible y total, en bytes, del volumen donde está esa carpeta.
#[cfg(windows)]
pub fn disk_space(path: &Path) -> Option<(u64, u64)> {
    use std::os::windows::ffi::OsStrExt;
    extern "system" {
        fn GetDiskFreeSpaceExW(directory: *const u16, available: *mut u64, total: *mut u64, total_free: *mut u64) -> i32;
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let (mut available, mut total, mut total_free) = (0, 0, 0);
    // SAFETY: la ruta termina en cero y los punteros son variables locales válidas durante la llamada.
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut available, &mut total, &mut total_free) };
    (ok != 0).then_some((available, total))
}

/// Espacio disponible y total, en bytes, del volumen donde está esa carpeta.
#[cfg(unix)]
pub fn disk_space(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs es una estructura de datos planos, y una de ceros es válida como destino.
    let mut info: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: la ruta termina en cero e `info` es válida durante la llamada.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut info) } != 0 {
        return None;
    }
    let block = info.f_frsize as u64;
    Some((info.f_bavail as u64 * block, info.f_blocks as u64 * block))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn meta() -> Meta {
        Meta {
            url: "https://cdn.example.com/a.js".into(),
            object: String::new(),
            size: 0,
            headers: vec![],
            stored_at: now(),
            expires_at: now() + 60,
            etag: None,
            last_modified: None,
        }
    }

    fn hash(n: u8) -> Hash {
        [n; 32]
    }

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("rayo-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn un_objeto_compartido_solo_se_libera_con_su_ultima_referencia() {
        let mut index = DiskIndex::default();
        assert_eq!(index.insert(hash(1), hash(9), 100, 10, 1), None);
        assert_eq!(index.insert(hash(2), hash(9), 100, 10, 2), None);
        assert_eq!(index.used, 120);
        assert_eq!(index.objects.len(), 1);

        let first = index.remove_oldest().unwrap();
        assert_eq!((first.key, first.orphan, first.bytes), (hash(1), None, 10));
        assert_eq!(index.used, 110);

        let second = index.remove_oldest().unwrap();
        assert_eq!((second.key, second.orphan, second.bytes), (hash(2), Some(hash(9)), 110));
        assert_eq!(index.used, 0);
        assert!(index.remove_oldest().is_none());
    }

    #[test]
    fn expulsa_primero_lo_usado_hace_mas_tiempo() {
        let mut index = DiskIndex::default();
        index.insert(hash(1), hash(11), 1, 0, 10);
        index.insert(hash(2), hash(12), 1, 0, 20);
        index.insert(hash(3), hash(13), 1, 0, 30);
        index.touch(&hash(1), 40);
        index.touch(&hash(9), 40); // una entrada desconocida no cambia nada
        assert_eq!(index.remove_oldest().unwrap().key, hash(2));
        assert_eq!(index.remove_oldest().unwrap().key, hash(3));
        assert_eq!(index.remove_oldest().unwrap().key, hash(1));
    }

    #[test]
    fn reemplazar_una_entrada_avisa_si_su_objeto_quedo_sin_uso() {
        let mut index = DiskIndex::default();
        index.insert(hash(1), hash(11), 100, 10, 1);
        // Mismo contenido: nada que borrar y no se cuenta dos veces.
        assert_eq!(index.insert(hash(1), hash(11), 100, 12, 2), None);
        assert_eq!(index.used, 112);
        // Contenido nuevo: el anterior queda sin uso.
        assert_eq!(index.insert(hash(1), hash(12), 50, 12, 3), Some(hash(11)));
        assert_eq!(index.used, 62);
        assert_eq!(index.objects.len(), 1);
        // Si otra entrada lo usa, el objeto se conserva.
        index.insert(hash(2), hash(12), 50, 12, 4);
        assert_eq!(index.insert(hash(1), hash(13), 7, 12, 5), None);
        assert_eq!(index.objects.len(), 2);
    }

    #[test]
    fn reconoce_solo_los_temporales_propios() {
        let name = "ab".repeat(32);
        assert!(is_leftover_temp(&format!("{name}.tmp1234")));
        assert!(!is_leftover_temp(&format!("{name}.tmp")));
        assert!(!is_leftover_temp(&format!("{name}.tmpx")));
        assert!(!is_leftover_temp("notas.tmp1234"));
    }

    #[test]
    fn mide_el_espacio_del_volumen() {
        let (free, total) = disk_space(&std::env::temp_dir()).unwrap();
        assert!(total > 0);
        assert!(free <= total);
        assert!(disk_space(Path::new("./esta/carpeta/no/existe")).is_none());
    }

    #[tokio::test]
    async fn objeto_corrupto_se_borra_y_se_repara() {
        let root = temp_root("corrupt");
        let stats = Arc::new(Stats::default());
        let store = Store::open(&root, 10, 0, stats.clone()).await.unwrap();
        let body = Bytes::from_static(b"contenido");
        let key = Store::key_hash("k");

        assert!(matches!(store.put(&key, meta(), &body).await.unwrap(), PutOutcome::New));
        let saved = store.get(&key).await.unwrap();
        assert_eq!(store.read_object(&saved).await.unwrap(), body);
        assert_eq!(stats.corrupt_objects.load(Relaxed), 0);

        let path = store.sharded("objects", &saved.object, "");
        tokio::fs::write(&path, b"alterado").await.unwrap();
        assert!(store.read_object(&saved).await.is_none());
        assert!(!path.exists());
        assert_eq!(stats.corrupt_objects.load(Relaxed), 1);

        assert!(matches!(store.put(&key, meta(), &body).await.unwrap(), PutOutcome::New));
        assert_eq!(store.read_object(&saved).await.unwrap(), body);

        drop(store);
        tokio::fs::remove_dir_all(&root).await.unwrap();
    }

    #[tokio::test]
    async fn al_cambiar_el_contenido_se_borra_el_objeto_anterior() {
        let root = temp_root("replace");
        let store = Store::open(&root, 10, 0, Arc::new(Stats::default())).await.unwrap();
        let (a, b) = (Store::key_hash("a"), Store::key_hash("b"));
        store.put(&a, meta(), &Bytes::from_static(b"uno")).await.unwrap();
        store.put(&b, meta(), &Bytes::from_static(b"uno")).await.unwrap();
        let shared = store.get(&a).await.unwrap().object.clone();
        let path = store.sharded("objects", &shared, "");

        store.put(&a, meta(), &Bytes::from_static(b"dos")).await.unwrap();
        assert!(path.exists(), "la otra URL todavía lo usa");
        store.put(&b, meta(), &Bytes::from_static(b"tres")).await.unwrap();
        assert!(!path.exists(), "ya nadie lo usa");

        drop(store);
        tokio::fs::remove_dir_all(&root).await.unwrap();
    }

    #[tokio::test]
    async fn al_abrir_limpia_lo_que_sobra_y_respeta_lo_ajeno() {
        let root = temp_root("scan");
        let body = Bytes::from_static(b"contenido");
        let key = Store::key_hash("k");
        let object = {
            let store = Store::open(&root, 10, 0, Arc::new(Stats::default())).await.unwrap();
            store.put(&key, meta(), &body).await.unwrap();
            store.get(&key).await.unwrap().object.clone()
        };

        let orphan = root.join("objects").join("cc").join("cc".repeat(32));
        let dangling = root.join("meta").join("dd").join(format!("{}.json", "dd".repeat(32)));
        let unreadable = root.join("meta").join("ee").join(format!("{}.json", "ee".repeat(32)));
        let temp = root.join("objects").join("ff").join(format!("{}.tmp77", "ff".repeat(32)));
        let foreign_object = root.join("objects").join("cc").join("notas.txt");
        let foreign_meta = root.join("meta").join("dd").join("notas.json");
        for path in [&orphan, &dangling, &unreadable, &temp, &foreign_object, &foreign_meta] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        }
        std::fs::write(&orphan, b"huerfano").unwrap();
        std::fs::write(&dangling, serde_json::to_vec(&Meta { object: "ab".repeat(32), ..meta() }).unwrap()).unwrap();
        std::fs::write(&unreadable, b"{no es json").unwrap();
        std::fs::write(&temp, b"a medias").unwrap();
        std::fs::write(&foreign_object, b"mio").unwrap();
        std::fs::write(&foreign_meta, b"mio").unwrap();

        let stats = Arc::new(Stats::default());
        let store = Store::open(&root, 10, 0, stats.clone()).await.unwrap();
        for gone in [&orphan, &dangling, &unreadable, &temp] {
            assert!(!gone.exists(), "{} debía borrarse", gone.display());
        }
        assert!(foreign_object.exists() && foreign_meta.exists());
        let saved = store.get(&key).await.unwrap();
        assert_eq!(saved.object, object);
        assert_eq!(store.read_object(&saved).await.unwrap(), body);
        assert_eq!(stats.disk_objects.load(Relaxed), 1);
        assert!(stats.disk_used_bytes.load(Relaxed) > body.len() as u64);

        drop(store);
        tokio::fs::remove_dir_all(&root).await.unwrap();
    }

    #[tokio::test]
    async fn al_abrir_quita_los_parametros_de_entradas_antiguas() {
        let root = temp_root("legacy");
        let key = Store::key_hash("k");
        let store = Store::open(&root, 10, 0, Arc::new(Stats::default())).await.unwrap();
        store.put(&key, meta(), &Bytes::from_static(b"x")).await.unwrap();
        drop(store);

        let path = sharded_path(&root, "meta", &key, ".json");
        let mut old: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        old["url"] = "https://cdn.example.com/a.js?token=secreto".into();
        old["key"] = "https://cdn.example.com/a.js?token=secreto|gzip".into();
        std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();

        let store = Store::open(&root, 10, 0, Arc::new(Stats::default())).await.unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("secreto"));
        assert!(!text.contains("\"key\""));
        assert_eq!(store.get(&key).await.unwrap().url, "https://cdn.example.com/a.js");

        drop(store);
        tokio::fs::remove_dir_all(&root).await.unwrap();
    }

    #[tokio::test]
    async fn un_limite_menor_expulsa_lo_mas_antiguo_al_arrancar() {
        let root = temp_root("evict");
        let keys: Vec<String> = (0..4).map(|n| Store::key_hash(&format!("k{n}"))).collect();
        let store = Store::open(&root, 10, 0, Arc::new(Stats::default())).await.unwrap();
        for (n, key) in keys.iter().enumerate() {
            store.put(key, meta(), &Bytes::from(vec![n as u8; 800])).await.unwrap();
            // Tras un reinicio, el orden sale de la fecha de los archivos.
            let age = Duration::from_secs(1000 - n as u64);
            std::fs::File::options()
                .write(true)
                .open(sharded_path(&root, "meta", key, ".json"))
                .unwrap()
                .set_modified(SystemTime::now() - age)
                .unwrap();
        }
        drop(store);

        let stats = Arc::new(Stats::default());
        let store = Store::open(&root, 10, 2000, stats.clone()).await.unwrap();
        for _ in 0..200 {
            if stats.disk_used_bytes.load(Relaxed) <= 1800 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(stats.disk_used_bytes.load(Relaxed) <= 1800);
        assert!(stats.evicted_entries.load(Relaxed) > 0);
        assert!(stats.evicted_bytes.load(Relaxed) >= 800);
        assert!(store.get(&keys[0]).await.is_none(), "la más antigua debía salir");
        let newest = store.get(&keys[3]).await.expect("la más reciente debía quedar");
        assert!(store.read_object(&newest).await.is_some());

        drop(store);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tokio::fs::remove_dir_all(&root).await;
    }
}
