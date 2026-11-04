# rayo-cache

Proxy de caché HTTP/HTTPS **local**, escrito en Rust con **Hudsucker + rustls + Hyper + Tokio**.
Es la versión honesta de la idea del *HTTPS Reflector*: en vez de rebajar HTTPS a HTTP, descifra
TLS solo para los dominios que tú eliges, usando una CA que **tú instalas en tus propios dispositivos**.

> Nombre provisional. "ThunderCache" ya es una marca comercial de BMSoftware.

## Glosario

| Término | Qué significa aquí |
|---|---|
| **MITM con CA local** | El proxy genera certificados al vuelo firmados por su propia CA. Solo funciona en equipos donde instalaste esa CA: ese es el consentimiento. |
| **Intercepción selectiva** | Solo se descifra TLS de los dominios en `intercept_domains`. Todo lo demás pasa cifrado (*passthrough*), sin que el proxy vea nada. |
| **Passthrough** | El proxy abre un túnel TCP y reenvía bytes cifrados sin tocarlos. |
| **Store-ID** | Normalizar URLs distintas que apuntan al mismo contenido para que compartan una clave (idea de los plugins de ThunderCache 3.x). |
| **Content-addressed storage** | Cada cuerpo se guarda con el nombre de su SHA-256. Dos URLs con el mismo contenido ocupan espacio una sola vez (idea de ThunderCache 7.1). |
| **Revalidación (304)** | Al vencer una copia, el proxy pregunta al origen con `If-None-Match`. Si responde `304`, se sirve la copia local sin volver a descargar el cuerpo. |
| **TTL** | Tiempo de vida de una copia. Se toma de `Cache-Control: max-age`/`s-maxage`; `no-cache` → TTL 0 (guardar y revalidar siempre). |

## Qué hace

```
Navegador ──CONNECT host:443──▶ rayo-cache
                                  │ ¿host en intercept_domains y no en never_intercept?
                                  ├─ NO  → túnel cifrado (passthrough)
                                  └─ SÍ  → TLS con cert de la CA local
                                           │ GET anónimo, sin Range, sin Authorization
                                           ├─ fresco en caché  → HIT (disco, verificado por hash)
                                           ├─ vencido + ETag   → If-None-Match → 304 → REVALIDATED
                                           └─ no está          → origen → ¿cacheable? → guardar → MISS
```

Reglas de seguridad incluidas:
- Nunca guarda respuestas con `Set-Cookie`, `Cache-Control: private/no-store` ni `Vary` distinto de `Accept-Encoding`.
- Nunca guarda ni sirve desde caché peticiones con `Authorization`, `Cookie` o cabeceras como `X-Forwarded-Host`, que permitirían envenenar la copia compartida. Esa lista no cubre cualquier cabecera que un origen pueda reflejar.
- `never_intercept` también vale para HTTP plano: esos dominios no se descifran ni se cachean.
- Doble filtro de intercepción: en el `CONNECT` y sobre el SNI real del `ClientHello`.
- Cada objeto se verifica contra su SHA-256 antes de servirse; si el disco fue alterado, se borra y se vuelve a descargar.
- Escrituras atómicas (temporal + rename): un corte de luz no deja objetos a medias.
- Objetos más grandes que `max_object_bytes` pasan en streaming sin cargar todo en memoria.

## Compilar

```bash
cargo build --release
# binario: target/release/rayo-cache
```

## Usar

1. **Arranca** (crea `config.toml` y la CA en `ca/` si no existen):
   ```bash
   ./target/release/rayo-cache            # o: rayo-cache ruta/config.toml
   ```
2. **Edita `config.toml`**: pon en `intercept_domains` solo contenido público y pesado (CDNs, descargas, fuentes). Mantén bancos y logins en `never_intercept`.
3. **Instala `ca/rayo-ca.crt`** en tus dispositivos:
   - **CachyOS / Arch:** `sudo trust anchor --store ca/rayo-ca.crt`
   - **Debian / Ubuntu:** `sudo cp ca/rayo-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`
   - **Windows (PowerShell admin):** `certutil -addstore -f ROOT ca\rayo-ca.crt`
   - **Firefox** usa su propio almacén: Ajustes → Privacidad y seguridad → Certificados → Importar.
4. **Configura el proxy** `127.0.0.1:3128` para HTTP y HTTPS (navegador o sistema).
5. **Mira las estadísticas** en `http://rayo.stats/` (con el proxy activo).

`RUST_LOG=rayo_cache=debug` muestra cada decisión de intercepción.

### Cómo leer las estadísticas

- Sin peticiones en curso, `requests` = `hits` + `misses` + `revalidated_304` + `bypass` + `origin_errors` + `cache_errors`.
- `byte_hit_ratio` = `bytes_from_cache` / (`bytes_from_cache` + `bytes_from_origin` + `bytes_bypass`).
- El tráfico en passthrough no entra en ese ratio: Hudsucker no expone sus bytes. Solo se cuentan las conexiones, en `tls_passthrough`.

## Probar

```bash
cargo test                       # claves, reglas de caché, integridad del almacén y contadores
cargo build --release
./e2e/run.sh                     # origen de laboratorio + proxy; termina con error si algo falla
```

El e2e requiere bash, `openssl`, `python3` y `curl`, y usa los puertos 3129, 8080 y 8443. En Windows se ejecuta desde Git Bash.

Resultado verificado en el entorno de desarrollo: HIT/MISS correctos, deduplicación entre URLs y entre
HTTP/HTTPS, revalidación 304, persistencia tras reinicio (HIT desde disco) y 400 peticiones concurrentes
con 1 sola descarga al origen (byte hit ratio 99.7 %).

## Uso responsable

La CA permite leer el tráfico de los dominios listados. Úsala **solo en tus equipos o en una red de
laboratorio donde todos los usuarios lo sepan y lo acepten**. La llave `ca/rayo-ca.key` nunca debe
salir de la máquina del proxy. Las apps con *certificate pinning* (bancos, muchas apps móviles)
fallarán si se interceptan: van en `never_intercept`.

## Mejoras siguientes (en orden de impacto)

1. **Coalescencia de peticiones**: si 40 clientes piden el mismo objeto que aún no está, que solo uno vaya al origen.
2. **Soporte de `Range`** para segmentos de video y descargas reanudables (servir rebanadas del objeto completo).
3. **Recolector de disco LRU** con un tope `max_disk_bytes` (hoy el disco crece sin límite).
4. **Modo transparente**: `iptables -t nat ... REDIRECT` hacia el proxy; el filtro por SNI ya está implementado. Bloquear UDP/443 para que el tráfico no se escape por QUIC.
5. **Prefetch nocturno predictivo** a partir de los logs (qué se repite y cuándo).
6. **Métricas Prometheus** y panel de ahorro.
7. **Modo cooperativo**: manifiestos firmados por sitios aliados para cachear contenido semidinámico sin CA local.
