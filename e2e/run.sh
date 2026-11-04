#!/usr/bin/env bash
# Prueba de punta a punta: origen de laboratorio (HTTP :8080 / HTTPS :8443) + proxy en :3129.
# Requiere: openssl, python3 y curl. No hace falta tocar el archivo hosts: usa localhost (se intercepta)
# y 127.0.0.1 (no se intercepta). Sale con código 1 si alguna verificación falla.
#
# Uso:  ./e2e/run.sh                         prueba target/release/rayo-cache
#       RAYO_BIN=ruta/al/binario ./e2e/run.sh  prueba otro binario
cd "$(dirname "$0")" || exit 1
BIN="${RAYO_BIN:-../target/release/rayo-cache}"
PX=http://127.0.0.1:3129
ORIGIN_HTTP=http://127.0.0.1:8080

# En Windows, Git Bash convertiría -subj "/CN=..." en una ruta. Se desactiva solo aquí: exportarlo
# rompería `curl -o /dev/null`, que necesita esa conversión.
openssl_literal() { MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" openssl "$@"; }

# Certificados del origen, desechables: se generan en cada ejecución.
openssl_literal req -x509 -newkey rsa:2048 -nodes -keyout origin-ca.key -out origin-ca.pem -days 2 \
  -subj "/CN=Lab Origin CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl_literal req -newkey rsa:2048 -nodes -keyout origin.key -out origin.csr -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" > ext.cnf
openssl x509 -req -in origin.csr -CA origin-ca.pem -CAkey origin-ca.key -CAcreateserial -out origin.pem -days 2 -extfile ext.cnf 2>/dev/null

cat > config.e2e.toml <<EOF
listen = "127.0.0.1:3129"
data_dir = "./data"
ca_cert = "./ca/rayo-ca.crt"
ca_key = "./ca/rayo-ca.key"
max_object_bytes = 1048576
default_ttl_secs = 3600
mem_index_entries = 10000
cache_plain_http = true
intercept_domains = ["localhost"]
never_intercept = ["127.0.0.1"]
strip_query_params = ["fbclid"]
strip_query_prefixes = ["utm_"]
store_id = []
stats_host = "rayo.stats"
upstream_extra_ca = ["./origin-ca.pem"]
EOF

rm -rf data
python3 origin.py & ORIGIN=$!
"$BIN" config.e2e.toml > proxy.log 2>&1 & PROXY=$!
trap 'kill $ORIGIN $PROXY 2>/dev/null' EXIT

for _ in $(seq 1 50); do
  curl -s --noproxy "" -x "$PX" http://rayo.stats/ >/dev/null && break
  sleep 0.2
done

FAILS=0
expect() { # descripción, esperado, obtenido
  if [ "$2" = "$3" ]; then echo "  ok    $1"; else echo "  FALLA $1: esperaba '$2', obtuve '$3'"; FAILS=$((FAILS + 1)); fi
}
section() { echo; echo "$1"; }
curlx() { curl -s --ssl-no-revoke --noproxy "" -x "$PX" --cacert ca/rayo-ca.crt -H "Accept-Encoding: gzip" "$@"; }
# Devuelve "<estado> <x-rayo-cache>", con "-" si la respuesta no pasó por la caché.
px() { curlx -o /dev/null -D - "$@" | tr -d '\r' | awk '/^HTTP/{s=$2} tolower($1)=="x-rayo-cache:"{c=$2} END{print s, (c?c:"-")}'; }
body() { curlx "$@"; }
metric() { curl -s --noproxy "" -x "$PX" http://rayo.stats/ | python3 -c "import json,sys; print(json.load(sys.stdin).get(sys.argv[1], 'ausente'))" "$1"; }
sha() { sha256sum | cut -d' ' -f1; }
# Ruta en disco del objeto cuyo contenido es el que el origen entrega hoy en esa URL.
object_path() { local h; h=$(curl -s --noproxy "*" "$ORIGIN_HTTP$1" | sha); echo "data/objects/${h:0:2}/$h"; }
# Emisor del certificado que recibe un cliente que conecta a $1 con SNI $2.
issuer() { echo Q | timeout 10 openssl s_client -proxy 127.0.0.1:3129 -connect "$1" -servername "$2" 2>/dev/null | grep -o -E "Lab Origin CA|Rayo Cache Local CA" | head -1; }

L=https://localhost:8443

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

req=$(metric requests); sum=0
for k in hits misses revalidated_304 bypass origin_errors cache_errors; do
  v=$(metric "$k"); [ "$v" = "ausente" ] && v=0; sum=$((sum + v))
done
expect "toda petición termina en un solo resultado" "$req" "$sum"

section "Estadísticas finales"
curl -s --noproxy "" -x "$PX" http://rayo.stats/; echo

echo
if [ "$FAILS" -eq 0 ]; then
  echo "TODO OK"
else
  echo "$FAILS verificación(es) fallaron. Log del proxy: e2e/proxy.log"
  exit 1
fi
