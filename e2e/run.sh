#!/usr/bin/env bash
# Prueba de punta a punta: origen de laboratorio (HTTP :8080 / HTTPS :8443) + varios proxies en :3129-3135.
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

# Escribe config.<nombre>.toml. Se puede ajustar con LISTEN, CLIENTS, RATE, INTERNAL, BUDGET, DOMAINS y CONTACT.
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
EOF
}

PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null' EXIT
start_proxy() {
  write_config "$1" "$2"
  "$BIN" "config.$1.toml" > "$1.log" 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 50); do
    curl -s --noproxy "" -x "http://127.0.0.1:$2" http://rayo.stats/ >/dev/null && return
    sleep 0.2
  done
}

rm -rf ca data-*
python3 origin.py & PIDS+=($!)
start_proxy e2e 3129
CLIENTS='["192.0.2.0/24"]' start_proxy denied 3130
RATE=5 start_proxy limited 3131
INTERNAL='[]' start_proxy strict 3132
DOMAINS='[]' BUDGET=1024 start_proxy tight 3133
RUST_LOG=rayo_cache=debug CONTACT='<script>alert(1)</script>' start_proxy detailed 3134
RUST_LOG=info start_proxy verbose 3135

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

echo
if [ "$FAILS" -eq 0 ]; then
  echo "TODO OK"
else
  echo "$FAILS verificación(es) fallaron. Logs de los proxies: e2e/*.log"
  exit 1
fi
