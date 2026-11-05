#!/bin/sh
# Prepara el firewall, arranca el agente de Wazuh y deja al proxy como proceso principal.
set -eu

# Cadena propia para los bloqueos, la primera de INPUT: corta también las conexiones ya abiertas.
for fw in iptables ip6tables; do
    "$fw" -N RAYO-BLOQUEO 2>/dev/null || true
    "$fw" -C INPUT -j RAYO-BLOQUEO 2>/dev/null || "$fw" -I INPUT 1 -j RAYO-BLOQUEO || {
        [ "$fw" = ip6tables ] || { echo "No se pudo preparar iptables: ¿falta cap_add NET_ADMIN?" >&2; exit 1; }
    }
done

# Que existan antes de arrancar el agente, para que los lea desde el principio.
mkdir -p /var/log/rayo-ips /opt/rayo/logs
touch /var/log/rayo-ips/bloqueos.jsonl "/opt/rayo/logs/security-$(date -u +%F).jsonl"

/var/ossec/bin/wazuh-control start >/dev/null

exec /usr/local/bin/rayo-cache /opt/rayo/config.toml
