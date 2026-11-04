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
- Solo los clientes de `allowed_clients` pueden usar el proxy, con un máximo de `rate_limit_per_minute` peticiones por IP.
- Los clientes no alcanzan este equipo ni la red local a través del proxy, salvo las redes de `allowed_internal_networks`.
- Los túneles solo se abren a los puertos de `allowed_connect_ports`, por defecto 80 y 443.
- La CA solo puede firmar para los dominios configurados al generarla, y su llave solo la puede leer el usuario que ejecuta el proxy.
- Si un objeto no cabe en `max_buffered_bytes`, se atiende en streaming, sin caché.
- Si varios clientes piden a la vez un objeto que no está, solo uno va al origen y los demás esperan hasta `coalesce_wait_secs`.
- La caché no pasa de `max_disk_bytes`: se borran las entradas usadas hace más tiempo, y un objeto solo cuando ninguna URL lo usa.
- En el registro y en los metadatos del disco, las URLs se guardan sin parámetros, porque pueden contener tokens.

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
5. **Mira las estadísticas** en `http://rayo.stats/` y el aviso para usuarios en `http://rayo.aviso/` (con el proxy activo). Escribe `http://` completo: los navegadores tratan esos nombres como búsquedas y no existen por HTTPS.

`RUST_LOG=rayo_cache=debug` muestra cada decisión de intercepción. Ese modo y filtros como `RUST_LOG=info` pueden escribir en el registro la IP de los clientes y los dominios a los que se conectan; si los usas, el aviso de `http://rayo.aviso/` lo indica. El registro nunca incluye los parámetros de las URLs, porque pueden contener tokens.

### Usarlo en una red compartida

Por defecto solo acepta conexiones de este mismo equipo. Para abrirlo a tu red:

1. **Define `intercept_domains` antes de generar la CA.** La CA queda limitada a esa lista. Para agregar un dominio fuera de ella hay que generar otra CA y reinstalarla en todos los dispositivos. Si el dominio no está cubierto, el proxy no arranca y lo explica.
2. **Abre el acceso** en `config.toml`, con la subred real de tu red:
   ```toml
   listen = "0.0.0.0:3128"
   allowed_clients = ["192.168.1.0/24"]
   ```
   El proxy no arranca si `listen` no es local y `allowed_clients` solo permite este equipo, ni si incluye a todo Internet (`0.0.0.0/0`). La IP no identifica a una persona: cualquiera dentro de la subred puede usarlo.
3. **Si necesitan llegar a una intranet** a través del proxy, agrega sus redes a `allowed_internal_networks`. Todo lo interno está bloqueado por defecto.
4. **Si generaste una CA con una versión anterior,** el proxy avisa al arrancar de que no tiene límites. Bórrala de cada dispositivo (en Windows: `certutil -delstore ROOT "Rayo Cache Local CA"`), borra `ca/`, arranca para generar otra y reinstálala.
5. **Avisa a los usuarios antes de que instalen la CA.** Completa `operator_contact` en `config.toml` y entrega la plantilla [docs/AVISO.md](docs/AVISO.md). Cualquier cliente permitido puede comprobar en `http://rayo.aviso/` los dominios que se descifran, qué registros están activos y la huella del certificado. La página se genera con la configuración real al arrancar.

**Puertos.** Un túnel a un puerto que no esté en `allowed_connect_ports` recibe un 403. Si alguien necesita otro, como el 8443 o el 22, agrégalo a la lista; dejarla vacía permite cualquier puerto y el proxy lo advierte al arrancar. El límite solo aplica a `CONNECT`: una petición `http://` sin cifrar puede seguir dirigiéndose a cualquier puerto público.

### Cómo leer las estadísticas

- Sin peticiones en curso, `requests` = `hits` + `misses` + `revalidated_304` + `bypass` + `origin_errors` + `cache_errors`.
- `byte_hit_ratio` = `bytes_from_cache` / (`bytes_from_cache` + `bytes_from_origin` + `bytes_bypass`).
- El tráfico en passthrough no entra en ese ratio: Hudsucker no expone sus bytes. Solo se cuentan las conexiones, en `tls_passthrough`.
- `denied_clients`, `rate_limited` y `blocked_destinations` cuentan rechazos. Un rechazo no suma en `requests`, salvo un nombre que resuelve a una IP interna, que además cuenta como `origin_errors`.
- `over_budget` cuenta las veces que no hubo memoria disponible y `coalesced` las peticiones que esperaron a otra igual.

Los contadores se guardan en `data_dir/stats.json` cada `maintenance_interval_secs` y al cerrar el proxy con Ctrl+C. Si el proceso se cae, se pierde lo ocurrido desde la última vez. Por eso, tras una caída la suma de arriba puede no cuadrar por unas pocas peticiones. Para empezar de cero, borra ese archivo con el proxy apagado. Los tiempos de respuesta no se guardan.

### Límite de disco

La caché ocupa como máximo `max_disk_bytes` (por defecto 10 GiB; `0` = sin límite). Al pasarse, libera hasta quedar en el 90 %, empezando por lo usado hace más tiempo. Con el límite lleno, esto es lo normal y no genera ninguna alerta.

- Cuenta el tamaño de los archivos, no lo que ocupan según el sistema de archivos, así que el espacio real puede ser algo mayor.
- Al arrancar revisa la carpeta: borra objetos sin metadatos, metadatos ilegibles o sin objeto, y temporales de un corte. No toca archivos con otros nombres. **No uses la misma `data_dir` en dos procesos.**
- Tras un reinicio, el orden de uso se aproxima con la fecha de los archivos.
- Si bajas el límite o actualizas desde una versión sin límite con una caché más grande, lo que sobre se borra al arrancar.

### Panel

El proxy abre un puerto de administración en `admin_listen` (por defecto `127.0.0.1:9128`; vacío lo desactiva). Si no puede abrirlo, no arranca.

Abre `http://127.0.0.1:9128/` y pega el token. El panel muestra la descarga evitada, los ratios, el reparto de peticiones, el disco y las alertas, y se actualiza cada 5 segundos.

Sin token, la página se sirve vacía: **todos los datos lo exigen**. El token se crea al arrancar en `admin_token_file` (`ca/admin.token`), con acceso solo para el usuario que ejecuta el proxy. Para cambiarlo, bórralo y reinicia. El panel lo guarda solo en esa pestaña y lo olvida al pulsar «Salir». Si escuchas fuera de `127.0.0.1`, el token viaja sin cifrar por esa red: el proxy lo advierte al arrancar.

**Por cliente.** Con `client_stats_enabled = true`, el panel lista cada IP con sus peticiones, bytes, túneles y rechazos, pero no qué sitios visitó. Viene apagado porque son datos sobre personas, y el aviso de `http://rayo.aviso/` indica si está activo. Solo vive en memoria y se olvida tras un día sin actividad o al reiniciar. Guarda hasta 4096 clientes: los que no quepan no se cuentan hasta que se olvide alguno.

### Alertas

Se evalúan cada `maintenance_interval_secs` (por defecto 60). Se ven en el panel y como `rayo_alert{name="..."}` en `/metrics`, y dejan una línea en el registro al activarse y al apagarse. El proxy no envía avisos por su cuenta: para recibirlos, configura una regla en Prometheus.

| `name` | Se activa cuando |
|---|---|
| `disk_space` | El volumen de la caché tiene menos de `alert_disk_free_percent` libre (10 %). |
| `disk_limit` | La caché pasa de su límite en más de un 10 %: no se están pudiendo borrar copias. |
| `ca_expiry` | A la CA le quedan `alert_ca_days` días o menos (30), o ya venció. |
| `origin_errors` | En las últimas 5 pasadas, al menos `alert_origin_error_percent` (20 %) de las peticiones no pudo contactar al origen, con un mínimo de 10 peticiones. |
| `corrupt_objects` | Se descartó algún objeto corrupto en las últimas 5 pasadas. |
| `store_writes` | Alguna respuesta no se pudo guardar en las últimas 5 pasadas. |
| `detections` | Hubo algún aviso de actividad inusual en las últimas 5 pasadas. La línea del registro no incluye la IP. |

### Detecciones

Avisan de actividad inusual por IP, pero no bloquean nada: la IP señala un equipo y no a una persona, y un volumen alto puede ser una actualización legítima. Vienen activas (`detections_enabled`), y el aviso de `http://rayo.aviso/` lo indica.

| Aviso | Se anota cuando | Umbral |
|---|---|---|
| Volumen alto | Una IP llega al umbral de peticiones o de bytes en un minuto. | `detect_requests_per_minute` (3000), `detect_bytes_per_minute` (1 GiB) |
| Muchos rechazos | Una IP recibe demasiadas respuestas 403 o 404 en un minuto, del origen o del proxy. | `detect_denied_per_minute` (100) |
| Puerto no permitido | Se pide un túnel a un puerto fuera de `allowed_connect_ports`. | Cada intento |
| Nombre que no coincide | El SNI difiere del `CONNECT`, o el `Host` difiere del destino de la petición. | Cada vez |

Un umbral en `0` desactiva esa regla. El panel muestra la IP, el tipo de aviso, cuántas veces ocurrió, cuándo y el último puerto, pero nunca qué sitios. Solo vive en memoria y se olvida tras un día o al reiniciar; lo único que se conserva son los totales por tipo, sin IP. Guarda hasta 256 avisos: al llenarse, descarta el más antiguo.

Lo que no pueden ver:

- **Túneles sin interceptar:** Hudsucker no expone sus bytes ni lee su SNI, así que no cuentan para el volumen en bytes ni para los nombres que no coinciden.
- **Ráfagas entre dos minutos:** se cuenta por minuto de reloj, así que una ráfaga repartida entre dos minutos puede no llegar al umbral.
- **Muchas direcciones:** en cada minuto se siguen hasta 4096 IPs; las que no quepan no se cuentan hasta el minuto siguiente.

Un `Host` falso no cambia el destino ni la clave de caché, que salen de la URI. Para llevar esto a un SIEM, usa `rayo_detections_total` en `/metrics` y el log de acceso en JSONL, que registra los túneles rechazados con su puerto.

### Métricas para Prometheus

```bash
curl http://127.0.0.1:9128/healthz                                        # sin token: solo dice si está vivo
curl -H "Authorization: Bearer $(cat ca/admin.token)" http://127.0.0.1:9128/metrics
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: rayo-cache
    authorization:
      credentials_file: /ruta/a/ca/admin.token
    static_configs:
      - targets: ["127.0.0.1:9128"]
```

Además de los contadores de arriba, `/metrics` incluye lo que no se publica en `http://rayo.stats/`:

| Métrica | Qué mide |
|---|---|
| `rayo_request_hit_ratio`, `rayo_byte_hit_ratio` | Parte de las peticiones y de los bytes servidos desde una copia. |
| `rayo_request_duration_seconds{result}` | Histograma del tiempo hasta tener lista la respuesta, desde el último arranque. En `hit`, `miss` y `revalidated` incluye leer o descargar el cuerpo, pero no enviarlo al cliente. En `bypass` termina al empezar a reenviar, así que no mide la descarga. |
| `rayo_corrupt_objects_total`, `rayo_store_write_errors_total` | Objetos descartados por no coincidir con su hash y respuestas que no se pudieron guardar. |
| `rayo_disk_used_bytes`, `rayo_disk_limit_bytes`, `rayo_disk_objects` | Lo que ocupa la caché, su límite y cuántos objetos tiene. |
| `rayo_disk_free_bytes`, `rayo_disk_total_bytes` | Espacio del volumen, medido cada `maintenance_interval_secs`. |
| `rayo_evicted_entries_total`, `rayo_evicted_bytes_total` | Lo expulsado por el límite de disco. |
| `rayo_detections_total{kind}` | Avisos de actividad inusual por tipo (`volume`, `denied`, `rare_port`, `host_mismatch`), sin IP. |
| `rayo_rejections_total{reason="port"}` | Túneles rechazados por pedir un puerto no permitido. No se publica en `http://rayo.stats/`. |
| `rayo_alert{name}`, `rayo_ca_not_after_seconds` | Si cada alerta está activa, y cuándo vence la CA. |
| `rayo_access_log_dropped_total`, `rayo_access_log_errors_total` | Líneas perdidas del log de acceso y errores al escribirlo. |
| `rayo_uptime_seconds` | Tiempo desde el arranque. |

### Log de acceso

Viene **apagado**: anota qué dominios visita cada dispositivo. Antes de activarlo, avisa a los usuarios: `http://rayo.aviso/` lo muestra por sí solo, pero también hay que actualizar la hoja de [docs/AVISO.md](docs/AVISO.md).

```toml
access_log_enabled = true
access_log_dir = "./logs"
access_log_retention_days = 7        # contando el día de hoy
access_log_client_ip = "pseudonym"   # o "none"
```

Escribe un archivo JSONL por día (UTC), `access-AAAA-MM-DD.jsonl`, que solo puede leer el usuario que ejecuta el proxy, y borra los vencidos al arrancar y cada hora:

```json
{"ts":"2026-11-03T15:04:05Z","client":"9f3ab1c27d10e845","method":"GET","scheme":"https","host":"cdn.example.com","port":null,"path":"/app.js","result":"hit","status":200,"bytes":4096,"ms":2}
```

- **`result`:** `hit`, `revalidated`, `miss`, `bypass`, `origin_error`, `cache_error`, `blocked` o `tunnel`.
- **`client`:** seudónimo calculado con una clave que solo vive en memoria y cambia cada día o al reiniciar. No se puede volver a la IP ni relacionar días distintos, pero dentro de un día sí se puede seguir a un dispositivo. La IP real no es una opción de configuración.
- **`path`:** solo en `hit`, `revalidated` y `miss`. En el resto puede ser personal, como un enlace para cambiar la contraseña.
- **`ms`:** el mismo tiempo que mide el histograma.
- **`bytes`:** lo que el proxy envió. Si el cliente se desconecta a medias, puede ser más de lo que recibió. Es `null` si no se puede saber, como en los túneles.
- **Nunca incluye** parámetros de la URL, cookies, credenciales ni cuerpos.
- **Túneles:** se anota que se abrió uno, con su dominio y puerto. Hudsucker no expone cuántos bytes pasan ni cuánto dura.
- **No se anotan** los clientes rechazados o limitados: solo se cuentan. Tampoco las visitas a `rayo.stats` y `rayo.aviso`.

Escribir nunca retrasa una petición: si el disco no da abasto, se pierden líneas y `rayo_access_log_dropped_total` lo indica. Puedes enviar estos archivos a un SIEM con cualquier agente que lea JSONL.

## Probar

```bash
cargo test                       # reglas de caché, acceso, CA, memoria, coalescencia y contadores
cargo build --release
./e2e/run.sh                     # origen de laboratorio + proxy; termina con error si algo falla
```

El e2e requiere bash, `openssl`, `python3` y `curl`, y usa los puertos 3129-3137, 3139, 3146-3153, 8080 y 8443. En Windows se ejecuta desde Git Bash.

El e2e verifica, entre otras cosas, que 20 peticiones simultáneas a un objeto nuevo causan 1 sola descarga al origen. No prueba clientes en otras máquinas ni navegadores: conviene probar la CA limitada en los navegadores de tu red antes de repartirla.

## Uso responsable

La CA permite leer el tráfico de los dominios listados. Úsala **solo en tus equipos o en una red de
laboratorio donde todos los usuarios lo sepan y lo acepten**. La llave `ca/rayo-ca.key` nunca debe
salir de la máquina del proxy. Las apps con *certificate pinning* (bancos, muchas apps móviles)
fallarán si se interceptan: van en `never_intercept`.

## Mejoras siguientes (en orden de impacto)

1. **Soporte de `Range`** para segmentos de video y descargas reanudables (servir rebanadas del objeto completo).
2. **Modo transparente**: `iptables -t nat ... REDIRECT` hacia el proxy; el filtro por SNI ya está implementado. Bloquear UDP/443 para que el tráfico no se escape por QUIC.
3. **Prefetch nocturno predictivo** a partir de los logs (qué se repite y cuándo).
4. **Modo cooperativo**: manifiestos firmados por sitios aliados para cachear contenido semidinámico sin CA local.
