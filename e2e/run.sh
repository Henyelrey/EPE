#!/usr/bin/env bash
# Prueba de punta a punta: origen de laboratorio (HTTP :8080 / HTTPS :8443) + varios proxies en :3129-3137, :3139 y :3146-3149.
# Requiere: openssl, python3 y curl. No hace falta tocar el archivo hosts: usa localhost (se intercepta)
# y 127.0.0.1 (no se intercepta). Sale con código 1 si alguna verificación falla.
#
# Uso:  ./e2e/run.sh                         prueba target/release/rayo-cache
#       RAYO_BIN=ruta/al/binario ./e2e/run.sh  prueba otro binario
cd "$(dirname "$0")" || exit 1
BIN="${RAYO_BIN:-../target/release/rayo-cache}"
PX=http://127.0.0.1:3129
ORIGIN_HTTP=http://127.0.0.1:8080
L=https://localhost:8443

# En Windows, Git Bash convertiría -subj "/CN=..." en una ruta. Se desactiva solo aquí: exportarlo
# rompería `curl -o /dev/null`, que necesita esa conversión.
openssl_literal() { MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" openssl "$@"; }

# Certificados del origen, desechables: se generan en cada ejecución.
openssl_literal req -x509 -newkey rsa:2048 -nodes -keyout origin-ca.key -out origin-ca.pem -days 2 \
  -subj "/CN=Lab Origin CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl_literal req -newkey rsa:2048 -nodes -keyout origin.key -out origin.csr -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" > ext.cnf
openssl x509 -req -in origin.csr -CA origin-ca.pem -CAkey origin-ca.key -CAcreateserial -out origin.pem -days 2 -extfile ext.cnf 2>/dev/null

# Escribe config.<nombre>.toml. Se puede ajustar con LISTEN, CLIENTS, RATE, INTERNAL, BUDGET, DOMAINS, CONTACT,
# ADMIN, ADMIN_TOKEN, LOG_ENABLED, LOG_DAYS, LOG_IP, MAX_DISK, ALERT_DISK_FREE, ALERT_CA_DAYS y CLIENT_STATS.
write_config() {
  local listen="${LISTEN:-127.0.0.1:$2}" clients="${CLIENTS:-[\"127.0.0.1/32\", \"::1/128\"]}"
  local internal="${INTERNAL:-[\"127.0.0.0/8\", \"::1/128\"]}" domains="${DOMAINS:-[\"localhost\"]}"
  local contact="${CONTACT:-redes@example.invalid}"
  cat > "config.$1.toml" <<EOF
listen = "$listen"
operator_contact = "$contact"
allowed_clients = $clients
rate_limit_per_minute = ${RATE:-0}
allowed_internal_networks = $internal
max_buffered_bytes = ${BUDGET:-67108864}
data_dir = "./data-$1"
ca_cert = "./ca/rayo-ca.crt"
ca_key = "./ca/rayo-ca.key"
max_object_bytes = 1048576
default_ttl_secs = 3600
mem_index_entries = 10000
cache_plain_http = true
intercept_domains = $domains
never_intercept = ["127.0.0.1"]
strip_query_params = ["fbclid"]
strip_query_prefixes = ["utm_"]
store_id = []
stats_host = "rayo.stats"
upstream_extra_ca = ["./origin-ca.pem"]
admin_listen = "${ADMIN:-}"
admin_token_file = "${ADMIN_TOKEN:-./ca/admin.token}"
max_disk_bytes = ${MAX_DISK:-0}
maintenance_interval_secs = 1
alert_disk_free_percent = ${ALERT_DISK_FREE:-0}
alert_ca_days = ${ALERT_CA_DAYS:-30}
client_stats_enabled = ${CLIENT_STATS:-false}
access_log_enabled = ${LOG_ENABLED:-false}
access_log_dir = "./logs-$1"
access_log_retention_days = ${LOG_DAYS:-7}
access_log_client_ip = "${LOG_IP:-pseudonym}"
EOF
}

PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null' EXIT
launch_proxy() {
  "$BIN" "config.$1.toml" >> "$1.log" 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 50); do
    curl -s --noproxy "" -x "http://127.0.0.1:$2" http://rayo.stats/ >/dev/null && return
    sleep 0.2
  done
}
start_proxy() {
  write_config "$1" "$2"
  launch_proxy "$1" "$2"
}

rm -rf ca data-* logs-* ./*.log
# Un log que ya venció y un archivo ajeno, para comprobar que la retención borra solo lo que debe.
mkdir -p logs-observed
echo '{}' > logs-observed/access-2020-01-01.jsonl
echo 'notas' > logs-observed/notas.txt
python3 origin.py & PIDS+=($!)
start_proxy e2e 3129
CLIENTS='["192.0.2.0/24"]' start_proxy denied 3130
RATE=5 start_proxy limited 3131
INTERNAL='[]' start_proxy strict 3132
DOMAINS='[]' BUDGET=1024 start_proxy tight 3133
RUST_LOG=rayo_cache=debug CONTACT='<script>alert(1)</script>' start_proxy detailed 3134
RUST_LOG=info start_proxy verbose 3135
ADMIN=127.0.0.1:3137 LOG_ENABLED=true start_proxy observed 3136
LOG_ENABLED=true LOG_IP=none LOG_DAYS=3 start_proxy anon 3139
ADMIN=127.0.0.1:3147 MAX_DISK=220000 start_proxy capped 3146
CAPPED_PID=${PIDS[-1]}
ADMIN=127.0.0.1:3149 ALERT_CA_DAYS=5000 ALERT_DISK_FREE=100 CLIENT_STATS=true start_proxy alerting 3148

FAILS=0
expect() { # descripción, esperado, obtenido
  if [ "$2" = "$3" ]; then echo "  ok    $1"; else echo "  FALLA $1: esperaba '$2', obtuve '$3'"; FAILS=$((FAILS + 1)); fi
}
section() { echo; echo "$1"; }
curlx() { curl -s -g --ssl-no-revoke --noproxy "" -x "$PX" --cacert ca/rayo-ca.crt -H "Accept-Encoding: gzip" "$@"; }
# Devuelve "<estado> <x-rayo-cache>", con "-" si la respuesta no pasó por la caché.
px() { curlx -o /dev/null -D - "$@" | tr -d '\r' | awk '/^HTTP/{s=$2} tolower($1)=="x-rayo-cache:"{c=$2} END{print s, (c?c:"-")}'; }
body() { curlx "$@"; }
metric() { curl -s --noproxy "" -x "$PX" http://rayo.stats/ | python3 -c "import json,sys; print(json.load(sys.stdin).get(sys.argv[1], 'ausente'))" "$1"; }
sha() { sha256sum | cut -d' ' -f1; }
# Ruta en disco del objeto cuyo contenido es el que el origen entrega hoy en esa URL.
object_path() { local h; h=$(curl -s --noproxy "*" "$ORIGIN_HTTP$1" | sha); echo "data-e2e/objects/${h:0:2}/$h"; }
# Emisor del certificado que recibe un cliente que conecta a $1 con SNI $2.
issuer() { echo Q | timeout 10 openssl s_client -proxy "${PX#http://}" -connect "$1" -servername "$2" 2>/dev/null | grep -o -E "Lab Origin CA|Rayo Cache Local CA" | head -1; }
# Veces que el origen recibió esa ruta, sin la barra inicial: Git Bash la convertiría en una ruta de Windows.
origin_hits() { curl -s --noproxy "*" "$ORIGIN_HTTP/__hits" | python3 -c "import json,sys; print(json.load(sys.stdin).get('/' + sys.argv[1], 0))" "$1"; }
# Lanza $1 peticiones simultáneas a $2 y dice cuántas recibieron un 200.
parallel() {
  local pids=() i
  for ((i = 0; i < $1; i++)); do px "$2" > "par.$i" & pids+=($!); done
  wait "${pids[@]}"
  cat par.* | grep -c '^200'
  rm -f par.*
}
# Código de salida del proxy con esa configuración (124 = no se negó a arrancar).
startup_exit() { timeout 8 "$BIN" "config.$1.toml" > "$1.log" 2>&1; echo $?; }
# ¿Una cadena firmada por la CA para este nombre es válida? La llave de la CA se usa aquí como lo haría un atacante.
ca_can_sign_for() {
  openssl_literal req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj "/CN=$1" 2>/dev/null
  printf "subjectAltName=DNS:%s\n" "$1" > leaf.cnf
  openssl x509 -req -in leaf.csr -CA ca/rayo-ca.crt -CAkey ca/rayo-ca.key -CAcreateserial -out leaf.pem -days 1 -extfile leaf.cnf 2>/dev/null
  if openssl verify -CAfile ca/rayo-ca.crt leaf.pem >/dev/null 2>&1; then echo si; else echo no; fi
  rm -f leaf.key leaf.csr leaf.cnf leaf.pem ca/rayo-ca.srl
}

section "1. HIT y MISS"
expect "primera petición HTTPS"              "200 MISS" "$(px $L/static.js)"
expect "segunda petición HTTPS"              "200 HIT"  "$(px $L/static.js)"
expect "parámetros de tracking no cambian la clave" "200 HIT" "$(px "$L/static.js?utm_source=x&fbclid=y")"
before=$(metric deduplicated_objects)
expect "mismo contenido en otra URL"         "200 MISS" "$(px $L/copia.js)"
expect "ese contenido se deduplica"          "$((before + 1))" "$(metric deduplicated_objects)"
expect "dinámico, primera petición"          "200 MISS" "$(px $L/dyn)"
expect "dinámico, se revalida con 304"       "200 REVALIDATED" "$(px $L/dyn)"
expect "HTTP plano permitido, primera vez"   "200 MISS" "$(px http://localhost:8080/static.js)"
expect "HTTP plano permitido, segunda vez"   "200 HIT"  "$(px http://localhost:8080/static.js)"

section "2. Contenido personal: nunca se comparte"
expect "respuesta con Set-Cookie"            "200 -" "$(px $L/private)"
expect "petición con Cookie no se guarda"    "200 -" "$(px -H 'Cookie: sid=alicia' $L/perfil)"
expect "cada cliente ve su propia página"    "perfil de anonimo" "$(body $L/perfil)"
expect "la cookie sigue yendo al origen"     "perfil de sid=alicia" "$(body -H 'Cookie: sid=alicia' $L/perfil)"
expect "una petición con Cookie no recibe la copia compartida" "200 -" "$(px -H 'Cookie: sid=alicia' $L/static.js)"

section "3. never_intercept también protege HTTP plano"
expect "primera petición"                    "200 -" "$(px $ORIGIN_HTTP/static.js)"
expect "segunda petición"                    "200 -" "$(px $ORIGIN_HTTP/static.js)"

section "4. Intercepción selectiva"
before_i=$(metric tls_intercepted); before_p=$(metric tls_passthrough)
expect "dominio no listado pasa cifrado"     "Lab Origin CA"       "$(issuer 127.0.0.1:8443 127.0.0.1.nip.invalid)"
expect "SNI no listado pasa cifrado"         "Lab Origin CA"       "$(issuer localhost:8443 otro.invalid)"
expect "dominio listado se intercepta"       "Rayo Cache Local CA" "$(issuer localhost:8443 localhost)"
expect "solo cuenta como interceptado el último" "$((before_i + 1))" "$(metric tls_intercepted)"
expect "los otros dos cuentan como passthrough"  "$((before_p + 2))" "$(metric tls_passthrough)"

section "5. Objetos corruptos se reparan"
obj=$(object_path /static.js)
printf 'alterado' > "$obj"
expect "copia fresca corrupta va al origen"  "200 MISS" "$(px $L/static.js)"
expect "el archivo queda reparado"           "$(basename "$obj")" "$(sha < "$obj")"
expect "la siguiente petición es HIT"        "200 HIT"  "$(px $L/static.js)"
obj=$(object_path /dyn)
printf 'alterado' > "$obj"
expect "copia vencida corrupta no da 304 vacío" "200 MISS" "$(px $L/dyn)"
expect "el cuerpo llega completo"            "$(curl -s --noproxy "*" $ORIGIN_HTTP/dyn)" "$(body $L/dyn)"
expect "vuelve a revalidarse"                "200 REVALIDATED" "$(px $L/dyn)"

section "6. Envenenamiento de caché"
expect "petición con X-Forwarded-Host no se guarda" "200 -" "$(px -H 'X-Forwarded-Host: evil.invalid' $L/reflect)"
expect "los demás no reciben el contenido alterado" '<script src="//cdn.legit/app.js"></script>' "$(body $L/reflect)"

section "7. Contadores"
before=$(metric bypass)
expect "304 pedido por el propio cliente"    "304 -" "$(px -H 'If-None-Match: "v1"' $L/dyn)"
expect "ese 304 cuenta como bypass"          "$((before + 1))" "$(metric bypass)"
before=$(metric bytes_bypass)
expect "objeto mayor que el límite llega entero" "2500000" "$(curlx -o /dev/null -w '%{size_download}' $L/big)"
expect "esos bytes cuentan como bypass"      "$((before + 2500000))" "$(metric bytes_bypass)"
before=$(metric bytes_bypass)
px -H 'Authorization: Bearer x' $L/private >/dev/null
expect "bypass decidido en la petición también cuenta bytes" "$((before + 15))" "$(metric bytes_bypass)"
before=$(metric origin_errors); before_b=$(metric bypass)
expect "origen caído en una petición cacheable" "502 -" "$(px http://localhost:1/x)"
expect "origen caído en un bypass"              "502 -" "$(px -X POST http://localhost:1/x)"
expect "ambos cuentan como error del origen"    "$((before + 2))" "$(metric origin_errors)"
expect "ninguno cuenta además como bypass"      "$before_b" "$(metric bypass)"
curlx --max-time 2 -o /dev/null -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" http://localhost:8080/ws

section "8. Coalescencia"
expect "20 clientes simultáneos reciben el objeto" "20" "$(parallel 20 http://localhost:8080/slow)"
expect "el origen recibe una sola petición"  "1" "$(origin_hits slow)"
expect "hubo clientes que esperaron"         "si" "$([ "$(metric coalesced)" -gt 0 ] 2>/dev/null && echo si || echo no)"
start=$(date +%s)
expect "5 clientes de una URL no cacheable"  "5" "$(parallel 5 http://localhost:8080/slow-private)"
elapsed=$(($(date +%s) - start))
expect "no quedan atendidos en fila (${elapsed}s, en fila serían 5s)" "si" "$([ "$elapsed" -lt 5 ] && echo si || echo no)"

req=$(metric requests); sum=0
for k in hits misses revalidated_304 bypass origin_errors cache_errors; do
  v=$(metric "$k"); [ "$v" = "ausente" ] && v=0; sum=$((sum + v))
done
expect "toda petición termina en un solo resultado" "$req" "$sum"

section "Estadísticas del proxy principal"
curl -s --noproxy "" -x "$PX" http://rayo.stats/; echo

section "9. Clientes no permitidos"
PX=http://127.0.0.1:3130
expect "HTTP plano rechazado"                "403 -" "$(px http://localhost:8080/static.js)"
expect "CONNECT rechazado"                   "403 -" "$(px $L/static.js)"
expect "estadísticas rechazadas"             "403 -" "$(px http://rayo.stats/)"

section "10. Límite por IP"
PX=http://127.0.0.1:3131
codes=$(for _ in $(seq 1 12); do px http://localhost:8080/static.js; done)
expect "las primeras peticiones pasan"       "200 MISS" "$(echo "$codes" | head -1)"
expect "al superar el límite se recibe 429"  "si" "$([ "$(echo "$codes" | grep -c '^429')" -gt 0 ] && echo si || echo no)"
expect "se indica cuándo reintentar"         "1" "$(curlx -o /dev/null -D - http://localhost:8080/static.js | grep -ci '^retry-after:')"

section "11. Destinos internos"
PX=http://127.0.0.1:3132
before=$(metric blocked_destinations)
expect "metadatos de la nube"                "403 -" "$(px http://169.254.169.254/latest/meta-data/)"
expect "red privada"                         "403 -" "$(px http://10.0.0.1/)"
expect "este equipo por IPv4"                "403 -" "$(px $ORIGIN_HTTP/static.js)"
expect "este equipo por IPv6"                "403 -" "$(px "http://[::1]:8080/static.js")"
expect "túnel a IP interna"                  "403 -" "$(px https://127.0.0.1:8443/static.js)"
expect "túnel a nombre interno"              "403 -" "$(px $L/static.js)"
expect "nombre que resuelve a IP interna"    "502 -" "$(px http://localhost:8080/static.js)"
expect "los 7 intentos quedan contados"      "$((before + 7))" "$(metric blocked_destinations)"
expect "IP escrita como número decimal"      "403 -" "$(px http://2130706433:8080/static.js)"
PX=http://127.0.0.1:3129
expect "una excepción configurada sí pasa"   "200 -" "$(px $ORIGIN_HTTP/static.js)"

section "12. Túneles con IP fijada y memoria agotada"
PX=http://127.0.0.1:3133
expect "un túnel a un nombre sigue funcionando" "Lab Origin CA" "$(issuer localhost:8443 localhost)"
size=$(curl -s --noproxy "*" "$ORIGIN_HTTP/static.js" | wc -c | tr -d ' ')
expect "sin memoria, el objeto llega entero" "$size" "$(curlx -o /dev/null -w '%{size_download}' http://localhost:8080/static.js)"
expect "y se atiende sin caché"              "200 -" "$(px http://localhost:8080/static.js)"
expect "no se guardó nada"                   "0" "$(metric stored_new_objects)"
expect "queda contado"                       "si" "$([ "$(metric over_budget)" -gt 0 ] 2>/dev/null && echo si || echo no)"

section "13. La CA está limitada y su llave protegida"
expect "firma para un dominio configurado"   "si" "$(ca_can_sign_for localhost)"
expect "firma para sus subdominios"          "si" "$(ca_can_sign_for sub.localhost)"
expect "no sirve para otros dominios"        "no" "$(ca_can_sign_for banco.invalid)"
expect "no puede crear otras CAs"            "1" "$(openssl x509 -in ca/rayo-ca.crt -noout -ext basicConstraints 2>/dev/null | grep -c 'pathlen:0')"
if command -v icacls >/dev/null; then
  acl=$(icacls ca/rayo-ca.key)
  expect "solo un usuario puede leer la llave" "1" "$(echo "$acl" | grep -c ':(')"
  expect "con acceso de su dueño"            "1" "$(echo "$acl" | grep -c "${USERNAME}:(F)")"
else
  expect "solo el dueño puede leer la llave" "600" "$(stat -c %a ca/rayo-ca.key)"
fi

section "14. Se niega a arrancar con una configuración insegura"
LISTEN=0.0.0.0:3140 write_config lan-sin-clientes 3140
expect "abierto a la red sin clientes"       "1" "$(startup_exit lan-sin-clientes)"
LISTEN=0.0.0.0:3141 CLIENTS='["0.0.0.0/0"]' write_config todo-internet 3141
expect "abierto a todo Internet"             "1" "$(startup_exit todo-internet)"
DOMAINS='["otro.invalid"]' write_config fuera-de-la-ca 3142
expect "dominio que la CA no puede firmar"   "1" "$(startup_exit fuera-de-la-ca)"
expect "y explica cómo resolverlo"           "1" "$(grep -c 'no puede firmar' fuera-de-la-ca.log)"

section "15. Aviso de transparencia"
PX=http://127.0.0.1:3129
before=$(metric requests)
page=$(body http://rayo.aviso/)
headers=$(curlx -o /dev/null -D - http://rayo.aviso/)
fp=$(openssl x509 -in ca/rayo-ca.crt -noout -fingerprint -sha256 | cut -d= -f2 | tr -d '\r')
has() { if echo "$1" | grep -qF -- "$2"; then echo si; else echo no; fi; }
# Líneas del registro con la IP de un cliente, sin los códigos de color del log.
client_ip_lines() { sed 's/\x1b\[[0-9;]*m//g' "$1" | grep -cE '(^|[^a-z_])client(_addr)?='; }
expect "se sirve como HTML"                  "si" "$(has "$headers" 'text/html; charset=utf-8')"
expect "prohíbe scripts y recursos externos" "si" "$(has "$headers" "default-src 'none'")"
expect "muestra los dominios que se descifran" "si" "$(has "$page" '<code>localhost</code>')"
expect "muestra los dominios protegidos"     "si" "$(has "$page" '<code>127.0.0.1</code>')"
expect "advierte sobre las contraseñas"      "si" "$(has "$page" 'incluidas contraseñas')"
expect "indica a quién acudir"               "si" "$(has "$page" 'redes@example.invalid')"
expect "su huella coincide con la del certificado" "si" "$(has "$page" "$fp")"
expect "indica que el registro detallado está apagado" "si" "$(has "$page" 'Registro detallado: desactivado')"
expect "no cuenta como petición de contenido" "$before" "$(metric requests)"
expect "el registro por defecto no incluye IPs de clientes" "0" "$(client_ip_lines e2e.log)"
PX=http://127.0.0.1:3135
px http://localhost:8080/static.js >/dev/null
page=$(body http://rayo.aviso/)
expect "con RUST_LOG=info el registro sí incluye IPs" "si" "$([ "$(client_ip_lines verbose.log)" -gt 0 ] && echo si || echo no)"
expect "y entonces el aviso lo indica"       "si" "$(has "$page" 'Registro detallado: activado')"
PX=http://127.0.0.1:3130
expect "un cliente no permitido no puede verlo" "403 -" "$(px http://rayo.aviso/)"
PX=http://127.0.0.1:3133
page=$(body http://rayo.aviso/)
expect "sin dominios configurados no inventa datos" "si" "$(has "$page" '<p>Ninguno.</p>')"
PX=http://127.0.0.1:3134
page=$(body http://rayo.aviso/)
expect "avisa si el registro detallado está activo" "si" "$(has "$page" 'Registro detallado: activado')"
expect "escapa los datos de la configuración" "no" "$(has "$page" '<script>')"
expect "y los muestra como texto"            "si" "$(has "$page" '&lt;script&gt;')"

section "16. Puerto de administración y métricas"
PX=http://127.0.0.1:3136
ADMIN_URL=http://127.0.0.1:3137
TOKEN=$(cat ca/admin.token)
admin_status() { curl -s --noproxy "*" -o /dev/null -w '%{http_code}' "$@"; }
# Valor de una serie de /metrics, tal como la escribe el proxy.
prom() { curl -s --noproxy "*" -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/metrics" | tr -d '\r' | awk -v k="$1" 'index($0, k " ") == 1 {print $2}'; }
over() { if python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) > float(sys.argv[2]) else 1)" "${1:-0}" "$2"; then echo si; else echo no; fi; }
expect "el token es largo"                   "64" "${#TOKEN}"
expect "sin token, /healthz responde"        "200" "$(admin_status $ADMIN_URL/healthz)"
expect "sin token, /metrics se rechaza"      "401" "$(admin_status $ADMIN_URL/metrics)"
expect "con un token incorrecto, también"    "401" "$(admin_status -H 'Authorization: Bearer incorrecto' $ADMIN_URL/metrics)"
expect "con el token, responde"              "200" "$(admin_status -H "Authorization: Bearer $TOKEN" $ADMIN_URL/metrics)"
expect "otras rutas no existen"              "404" "$(admin_status -H "Authorization: Bearer $TOKEN" $ADMIN_URL/otra)"
expect "a través del proxy, el token se sigue exigiendo" "401 -" "$(px $ADMIN_URL/metrics)"
PX=http://127.0.0.1:3132
expect "con los destinos internos bloqueados, ni se llega" "403 -" "$(px $ADMIN_URL/metrics)"
PX=http://127.0.0.1:3136
if command -v icacls >/dev/null; then
  expect "solo un usuario puede leer el token" "1" "$(icacls ca/admin.token | grep -c ':(')"
else
  expect "solo el dueño puede leer el token" "600" "$(stat -c %a ca/admin.token)"
fi

expect "primera petición"                    "200 MISS" "$(px "$L/static.js?token=SECRETO-QUERY")"
expect "segunda petición"                    "200 HIT"  "$(px "$L/static.js?token=SECRETO-QUERY")"
expect "dinámico"                            "200 MISS" "$(px $L/dyn)"
expect "dinámico revalidado"                 "200 REVALIDATED" "$(px $L/dyn)"
expect "con cookie y credenciales"           "200 -" "$(px -H 'Cookie: sid=SECRETO-COOKIE' -H 'Authorization: Bearer SECRETO-AUTH' "$L/private?clave=SECRETO-QUERY")"
curlx -o /dev/null -X POST -d 'SECRETO-CUERPO' "$L/perfil?clave=SECRETO-QUERY"
expect "origen caído"                        "502 -" "$(px "http://localhost:1/x?token=SECRETO-QUERY")"
expect "destino interno"                     "403 -" "$(px "http://169.254.169.254/latest?token=SECRETO-QUERY")"
expect "objeto grande llega entero"          "2500000" "$(curlx -o /dev/null -w '%{size_download}' $L/big)"
expect "túnel en passthrough"                "Lab Origin CA" "$(issuer 127.0.0.1:8443 127.0.0.1.nip.invalid)"
expect "SNI distinto en passthrough"         "Lab Origin CA" "$(issuer localhost:8443 otro.invalid)"

expect "cuenta los HIT"                      "1" "$(prom 'rayo_results_total{result="hit"}')"
expect "cuenta las revalidaciones"           "1" "$(prom 'rayo_results_total{result="revalidated"}')"
expect "mide la latencia de los HIT"         "1" "$(prom 'rayo_request_duration_seconds_count{result="hit"}')"
expect "y la de los errores"                 "1" "$(prom 'rayo_request_duration_seconds_count{result="error"}')"
expect "acumula el tiempo"                   "si" "$(over "$(prom 'rayo_request_duration_seconds_sum{result="miss"}')" 0)"
expect "ratio de peticiones"                 "si" "$(over "$(prom rayo_request_hit_ratio)" 0)"
expect "los túneles quedan contados"         "2" "$(prom 'rayo_tls_connections_total{mode="passthrough"}')"
expect "el formato es el de Prometheus"      "0" "$(curl -s --noproxy "*" -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/metrics" | tr -d '\r' | grep -cvE '^(# (HELP|TYPE) rayo_|rayo_[a-z_]+(\{[a-z]+="[^"]*"(,[a-z]+="[^"]*")*\})? [0-9.e+-]+$)')"
expect "mide el disco"                       "si" "$(over "$(prom rayo_disk_used_bytes)" 0)"
expect "cuenta los objetos"                  "si" "$(over "$(prom rayo_disk_objects)" 0)"

h=$(curl -s --noproxy "*" "$ORIGIN_HTTP/static.js" | sha)
printf 'alterado' > "data-observed/objects/${h:0:2}/$h"
expect "una copia corrupta se vuelve a pedir" "200 MISS" "$(px "$L/static.js?token=SECRETO-QUERY")"
expect "cuenta los objetos corruptos"        "1" "$(prom rayo_corrupt_objects_total)"
h=$(curl -s --noproxy "*" "$ORIGIN_HTTP/reflect" | sha)
rm -rf "data-observed/objects/${h:0:2}"
printf 'estorbo' > "data-observed/objects/${h:0:2}"
expect "un fallo de escritura no afecta al cliente" "200 MISS" "$(px $L/reflect)"
expect "y queda contado"                     "1" "$(prom rayo_store_write_errors_total)"
rm -f "data-observed/objects/${h:0:2}"

expect "rayo.stats no publica el uso de disco"   "ausente" "$(metric disk_used_bytes)"
expect "ni el tiempo encendido"                  "ausente" "$(metric uptime_secs)"
expect "el token no aparece en el registro"      "0" "$(grep -c "$TOKEN" observed.log)"

section "17. Log de acceso"
sleep 0.5
# Cuántas líneas del log cumplen una expresión de Python sobre `l`. No lleva barras: Git Bash las convertiría.
log_count() {
  python3 -c 'import glob,json,sys; rows=[json.loads(x) for f in glob.glob("logs-"+sys.argv[1]+"/access-*.jsonl") if "2020-01-01" not in f for x in open(f,encoding="utf-8")]; print(sum(1 for l in rows if eval(sys.argv[2])))' "$1" "$2"
}
log_text() { cat logs-observed/access-*.jsonl; }
LOG_FILE=$(ls logs-observed/access-*.jsonl | grep -v 2020-01-01 | head -1)
expect "un archivo por día, con el formato acordado" "si" "$([ -n "$LOG_FILE" ] && echo si || echo no)"
expect "cada línea es JSON válido"           "$(wc -l < "$LOG_FILE" | tr -d ' ')" "$(log_count observed True)"
expect "registra los MISS, también el que repara la copia" "2" "$(log_count observed 'l["result"]=="miss" and l["host"]=="localhost" and "static.js" in (l["path"] or "") and l["status"]==200 and l["bytes"]>0 and l["scheme"]=="https" and l["method"]=="GET" and l["port"]==8443')"
expect "los HIT"                             "1" "$(log_count observed 'l["result"]=="hit" and "static.js" in (l["path"] or "")')"
expect "las revalidaciones"                  "1" "$(log_count observed 'l["result"]=="revalidated" and "dyn" in (l["path"] or "")')"
expect "los errores del origen"              "1" "$(log_count observed 'l["result"]=="origin_error" and l["status"]==502 and l["bytes"] is None')"
expect "los destinos bloqueados"             "1" "$(log_count observed 'l["result"]=="blocked" and l["host"]=="169.254.169.254"')"
expect "los bytes reales de un bypass en streaming" "1" "$(log_count observed 'l["result"]=="bypass" and l["bytes"]==2500000')"
expect "los túneles, con su puerto"          "1" "$(log_count observed 'l["result"]=="tunnel" and l["method"]=="CONNECT" and l["port"]==8443 and l["bytes"] is None')"
expect "y los que se deciden por el SNI"     "1" "$(log_count observed 'l["result"]=="tunnel" and l["host"]=="otro.invalid"')"
expect "no registra las rutas de un bypass"  "0" "$(log_count observed 'l["result"]=="bypass" and l["path"] is not None')"
expect "no registra las visitas a rayo.stats y rayo.aviso" "0" "$(log_count observed 'l["host"] in ("rayo.stats","rayo.aviso")')"
expect "toda línea tiene un seudónimo de 16 caracteres" "0" "$(log_count observed 'len(l["client"])!=16')"
expect "el mismo cliente tiene el mismo seudónimo" "1" "$(python3 -c 'import json,sys; print(len({json.loads(x)["client"] for x in open(sys.argv[1],encoding="utf-8")}))' "$LOG_FILE")"
expect "no contiene parámetros"              "0" "$(log_text | grep -c 'SECRETO-QUERY')"
expect "ni cookies"                          "0" "$(log_text | grep -c 'SECRETO-COOKIE')"
expect "ni credenciales"                     "0" "$(log_text | grep -c 'SECRETO-AUTH')"
expect "ni cuerpos"                          "0" "$(log_text | grep -c 'SECRETO-CUERPO')"
expect "ni la IP del cliente"                "0" "$(log_count observed 'l["client"]=="127.0.0.1"')"
expect "el registro del proxy tampoco tiene parámetros" "0" "$(grep -c 'SECRETO' observed.log)"
expect "ni los metadatos guardados en disco" "0" "$(grep -rl 'SECRETO' data-observed/meta | wc -l | tr -d ' ')"
if command -v icacls >/dev/null; then
  expect "solo un usuario puede leer el log" "1" "$(icacls "$LOG_FILE" | grep -c ':(')"
else
  expect "solo el dueño puede leer el log"   "600" "$(stat -c %a "$LOG_FILE")"
fi
expect "borra los logs vencidos"             "no" "$([ -e logs-observed/access-2020-01-01.jsonl ] && echo si || echo no)"
expect "y no toca otros archivos"            "si" "$([ -e logs-observed/notas.txt ] && echo si || echo no)"
page=$(body http://rayo.aviso/)
expect "el aviso indica que está activo"     "si" "$(has "$page" 'Registro de acceso: activado')"
expect "y explica lo que permite el seudónimo" "si" "$(has "$page" 'qué dominios visitó un mismo dispositivo')"
expect "un log apagado no crea nada"         "no" "$([ -e logs-e2e ] && echo si || echo no)"
PX=http://127.0.0.1:3129
page=$(body http://rayo.aviso/)
expect "y el aviso dice que está desactivado" "si" "$(has "$page" 'Registro de acceso: desactivado')"
PX=http://127.0.0.1:3139
px http://localhost:8080/static.js >/dev/null
sleep 0.5
expect "en modo anónimo se registra la petición" "1" "$(log_count anon 'l["result"]=="miss"')"
expect "sin nada que distinga al cliente"    "0" "$(log_count anon 'l["client"] is not None')"
page=$(body http://rayo.aviso/)
expect "y el aviso lo dice, con su retención" "si" "$(has "$page" 'Se borra a los 3 días')"

section "18. Se niega a arrancar si no puede cumplir lo configurado"
LOG_ENABLED=true LOG_DAYS=0 write_config sin-retencion 3143
expect "log sin días de retención"           "1" "$(startup_exit sin-retencion)"
ADMIN=127.0.0.1:3137 write_config admin-ocupado 3144
expect "puerto de administración ocupado"    "1" "$(startup_exit admin-ocupado)"
printf 'corto' > debil.token
ADMIN=127.0.0.1:3145 ADMIN_TOKEN=./debil.token write_config token-debil 3145
expect "token demasiado corto"               "1" "$(startup_exit token-debil)"
rm -f debil.token

section "19. Límite de disco"
PX=http://127.0.0.1:3146
ADMIN_URL=http://127.0.0.1:3147
not_over() { if python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) <= float(sys.argv[2]) else 1)" "$1" "$2"; then echo si; else echo no; fi; }
blob() { px "http://localhost:8080/blob/$1"; }
# El índice ordena por segundos: las pausas hacen que el orden de uso no dependa del azar.
expect "objeto 1"                            "200 MISS" "$(blob 1)"
expect "objeto 2"                            "200 MISS" "$(blob 2)"
sleep 1.1
expect "objeto 3"                            "200 MISS" "$(blob 3)"
sleep 1.1
expect "volver a usar el objeto 1"           "200 HIT"  "$(blob 1)"
sleep 1.1
expect "objeto 4"                            "200 MISS" "$(blob 4)"
expect "objeto 5, que pasa del límite"       "200 MISS" "$(blob 5)"
sleep 0.5
expect "objeto 6"                            "200 MISS" "$(blob 6)"
sleep 0.5
expect "la caché no pasa de su límite"       "si" "$(not_over "$(prom rayo_disk_used_bytes)" 220000)"
expect "cuenta lo expulsado"                 "si" "$(over "$(prom rayo_evicted_entries_total)" 0)"
expect "los archivos coinciden con la cuenta" "$(prom rayo_disk_objects)" "$(find data-capped/objects -type f | wc -l | tr -d ' ')"
expect "lo usado hace poco se conserva"      "200 HIT"  "$(blob 1)"
expect "lo más antiguo salió"                "200 MISS" "$(blob 2)"
expect "no es un fallo: no se activa ninguna alerta" "0" "$(prom 'rayo_alert{name="disk_limit"}')"

PX=http://127.0.0.1:3129
first=$(curl -s --noproxy "*" "$ORIGIN_HTTP/mutable" | sha)
first_path="data-e2e/objects/${first:0:2}/$first"
expect "contenido que puede cambiar"         "200 MISS" "$(px http://localhost:8080/mutable)"
expect "queda en disco"                      "si" "$([ -e "$first_path" ] && echo si || echo no)"
curl -s --noproxy "*" -o /dev/null "$ORIGIN_HTTP/mutable-change"
expect "al cambiar se guarda lo nuevo"       "200 MISS" "$(px http://localhost:8080/mutable)"
expect "y se borra lo que ya nadie usa"      "no" "$([ -e "$first_path" ] && echo si || echo no)"
h=$(curl -s --noproxy "*" "$ORIGIN_HTTP/mutable" | sha)
expect "lo nuevo sí está"                    "si" "$([ -e "data-e2e/objects/${h:0:2}/$h" ] && echo si || echo no)"

section "20. Reinicio"
PX=http://127.0.0.1:3146
sleep 1.5
req_before=$(metric requests); used_before=$(prom rayo_disk_used_bytes); objects_before=$(prom rayo_disk_objects)
kill "$CAPPED_PID"
sleep 1
expect "los contadores quedaron en disco"    "si" "$(python3 -c 'import json,sys; print("si" if json.load(open(sys.argv[1]))["requests"]>0 else "no")' data-capped/stats.json)"
mkdir -p data-capped/objects/cc data-capped/objects/ff data-capped/meta/dd
orphan="data-capped/objects/cc/$(printf 'c%.0s' $(seq 1 64))"
temp="data-capped/objects/ff/$(printf 'f%.0s' $(seq 1 64)).tmp4242"
broken="data-capped/meta/dd/$(printf 'd%.0s' $(seq 1 64)).json"
echo huerfano > "$orphan"; echo temporal > "$temp"; echo '{roto' > "$broken"; echo mio > data-capped/objects/cc/notas.txt
launch_proxy capped 3146
expect "los contadores siguen sumando"       "$req_before" "$(metric requests)"
expect "la cuenta del disco es la misma"     "$used_before" "$(prom rayo_disk_used_bytes)"
expect "y la de los objetos"                 "$objects_before" "$(prom rayo_disk_objects)"
expect "lo guardado sigue sirviéndose"       "200 HIT" "$(blob 1)"
expect "borra los objetos sin dueño"         "no" "$([ -e "$orphan" ] && echo si || echo no)"
expect "los temporales de un corte"          "no" "$([ -e "$temp" ] && echo si || echo no)"
expect "y los metadatos dañados"             "no" "$([ -e "$broken" ] && echo si || echo no)"
expect "pero no los archivos ajenos"         "si" "$([ -e data-capped/objects/cc/notas.txt ] && echo si || echo no)"
expect "los histogramas empiezan de cero"    "1" "$(prom 'rayo_request_duration_seconds_count{result="hit"}')"
expect "las estadísticas públicas no cambian" "ausente" "$(metric evicted_entries)"

section "21. Alertas"
# Espera hasta $3 segundos a que una serie de /metrics tenga el valor $2, y dice cuál tiene al final.
wait_prom() {
  local i
  for ((i = 0; i < $3 * 4; i++)); do
    [ "$(prom "$1")" = "$2" ] && break
    sleep 0.25
  done
  prom "$1"
}
ADMIN_URL=http://127.0.0.1:3149
expect "avisa si la CA está por vencer"      "1" "$(wait_prom 'rayo_alert{name="ca_expiry"}' 1 4)"
expect "o si queda poco espacio"             "1" "$(wait_prom 'rayo_alert{name="disk_space"}' 1 4)"
expect "deja constancia en el registro"      "si" "$(has "$(sed 's/\x1b\[[0-9;]*m//g' alerting.log)" 'alerta="ca_expiry"')"
ADMIN_URL=http://127.0.0.1:3137
PX=http://127.0.0.1:3136
expect "sin problemas no se activa"          "0" "$(prom 'rayo_alert{name="ca_expiry"}')"
parallel 12 "http://localhost:1/x" >/dev/null
expect "muchos errores del origen la activan" "1" "$(wait_prom 'rayo_alert{name="origin_errors"}' 1 8)"
expect "y se apaga sola al pasar"            "0" "$(wait_prom 'rayo_alert{name="origin_errors"}' 0 15)"
h=$(curl -s --noproxy "*" "$ORIGIN_HTTP/static.js" | sha)
printf 'alterado' > "data-observed/objects/${h:0:2}/$h"
px "$L/static.js?token=SECRETO-QUERY" >/dev/null
expect "un objeto corrupto la activa"        "1" "$(wait_prom 'rayo_alert{name="corrupt_objects"}' 1 4)"

section "22. Panel y detalle por cliente"
api() { curl -s --noproxy "*" -H "Authorization: Bearer $TOKEN" "$1"; }
field() { python3 -c 'import json,sys; v=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }
page_headers=$(curl -s --noproxy "*" -o panel.html -D - $ADMIN_URL/ | tr -d '\r')
expect "sin token se sirve la página"        "si" "$(has "$page_headers" 'HTTP/1.1 200')"
expect "que no admite recursos externos"     "si" "$(has "$page_headers" "default-src 'none'")"
expect "ni scripts en línea"                 "no" "$(has "$page_headers" 'unsafe-inline')"
expect "y no contiene datos"                 "0" "$(grep -c "$(metric requests)" panel.html)"
rm -f panel.html
expect "su código está disponible"           "200" "$(admin_status $ADMIN_URL/panel.js)"
expect "y su estilo"                         "200" "$(admin_status $ADMIN_URL/panel.css)"
expect "los datos exigen el token"           "401" "$(admin_status $ADMIN_URL/api/summary)"
expect "también por cliente"                 "401" "$(admin_status $ADMIN_URL/api/clients)"
expect "con el token responde"               "$(metric requests)" "$(api $ADMIN_URL/api/summary | field 'v["requests"]')"
expect "e incluye las alertas"               "True" "$(api $ADMIN_URL/api/summary | field '"corrupt_objects" in [a["name"] for a in v["alerts"]]')"
expect "apagado no guarda nada por cliente"  "False []" "$(api $ADMIN_URL/api/clients | field 'str(v["enabled"]) + " " + str(v["clients"])')"
page=$(body http://rayo.aviso/)
expect "y el aviso lo dice"                  "si" "$(has "$page" 'Totales por dispositivo: desactivados')"
PX=http://127.0.0.1:3148
ADMIN_URL=http://127.0.0.1:3149
px http://localhost:8080/copia.js >/dev/null
px http://localhost:8080/copia.js >/dev/null
expect "activado, cuenta las peticiones"     "2" "$(api $ADMIN_URL/api/clients | field 'v["clients"][0]["requests"]')"
expect "y cuántas salieron de una copia"     "1" "$(api $ADMIN_URL/api/clients | field 'v["clients"][0]["served_from_copy"]')"
expect "con la IP"                           "127.0.0.1" "$(api $ADMIN_URL/api/clients | field 'v["clients"][0]["ip"]')"
expect "pero no qué sitios"                  "no" "$(has "$(api $ADMIN_URL/api/clients)" 'localhost')"
sleep 1.5
expect "y no se guarda en disco"             "0" "$(grep -c '127.0.0.1' data-alerting/stats.json)"
page=$(body http://rayo.aviso/)
expect "el aviso indica que está activo"     "si" "$(has "$page" 'Totales por dispositivo: activados')"

echo
if [ "$FAILS" -eq 0 ]; then
  echo "TODO OK"
else
  echo "$FAILS verificación(es) fallaron. Logs de los proxies: e2e/*.log"
  exit 1
fi
