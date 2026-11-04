#!/usr/bin/env bash
# Prueba de punta a punta en tu máquina: origen de laboratorio (HTTP :8080 / HTTPS :8443) + proxy en :3129.
# Requiere: openssl, python3, curl y una entrada en /etc/hosts:  127.0.0.1 lab.test other.test
set -euo pipefail
cd "$(dirname "$0")"
D="$PWD"

if [ ! -f origin-ca.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout origin-ca.key -out origin-ca.pem -days 30 \
    -subj "/CN=Lab Origin CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout origin.key -out origin.csr -subj "/CN=lab.test" 2>/dev/null
  printf "subjectAltName=DNS:lab.test,DNS:other.test\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" > ext.cnf
  openssl x509 -req -in origin.csr -CA origin-ca.pem -CAkey origin-ca.key -CAcreateserial -out origin.pem -days 30 -extfile ext.cnf 2>/dev/null
fi

cat > config.e2e.toml <<EOF
listen = "127.0.0.1:3129"
data_dir = "$D/data"
ca_cert = "$D/ca/rayo-ca.crt"
ca_key = "$D/ca/rayo-ca.key"
max_object_bytes = 1048576
default_ttl_secs = 3600
mem_index_entries = 10000
cache_plain_http = true
intercept_domains = ["lab.test"]
never_intercept = []
strip_query_params = ["fbclid"]
strip_query_prefixes = ["utm_"]
store_id = []
stats_host = "rayo.stats"
upstream_extra_ca = ["$D/origin-ca.pem"]
EOF

rm -rf data
python3 origin.py & ORIGIN=$!
../target/release/rayo-cache config.e2e.toml > proxy.log 2>&1 & PROXY=$!
trap 'kill $ORIGIN $PROXY 2>/dev/null' EXIT
sleep 1.5

px() { curl -s -x http://127.0.0.1:3129 --cacert ca/rayo-ca.crt -H "Accept-Encoding: gzip" -o /dev/null -D - "$@" \
        | grep -iE "^HTTP|x-rayo-cache" | tr -d '\r' | tr '\n' ' '; echo; }

echo "1. HTTPS interceptado (MISS → HIT)";            px https://lab.test:8443/static.js; px https://lab.test:8443/static.js
echo "2. Tracking eliminado (HIT)";                   px "https://lab.test:8443/static.js?utm_source=x&fbclid=y"
echo "3. Mismo contenido, otra URL (dedup)";          px https://lab.test:8443/copia.js
echo "4. Dinámico con ETag (MISS → REVALIDATED)";     px https://lab.test:8443/dyn; px https://lab.test:8443/dyn
echo "5. Set-Cookie (nunca se cachea)";               px https://lab.test:8443/private
echo "6. Dominio no listado (passthrough):"
curl -s -v -x http://127.0.0.1:3129 --cacert origin-ca.pem -o /dev/null https://other.test:8443/static.js 2>&1 | grep -i "issuer" | head -1
echo "7. Estadísticas:"; curl -s -x http://127.0.0.1:3129 http://rayo.stats/; echo
