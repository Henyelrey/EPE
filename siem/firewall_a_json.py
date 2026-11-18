"""Convierte a JSON el registro del firewall de Windows para que Wazuh lo lea.

Wazuh ya trae un decodificador para este registro, pero ignora las conexiones aceptadas y falla con ICMP.
Uso: firewall_a_json.py <registro del firewall> <salida .jsonl> <IP de este PC>
"""
import json
import os
import sys
import time
from collections import Counter

# Una inundación escribiría miles de líneas por segundo. Estos topes están por encima de los umbrales
# de las reglas: alcanzan para alertar sin saturar a Wazuh.
WINDOW_SECONDS = 10
MAX_LINES_PER_IP = 200
MAX_LINES_TOTAL = 1000


def parse(line, own_ip):
    """Devuelve el evento de un paquete recibido por este PC, o None si hay que ignorar la línea."""
    # date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin
    # icmptype icmpcode info path [pid]
    fields = line.split()
    if len(fields) < 17 or line.startswith("#"):
        return None
    action, protocol, src, dst, sport, dport, size, flags = fields[2:10]
    if fields[16] != "RECEIVE" or dst != own_ip or src == own_ip:
        return None
    # Con ACK o RST son restos de conexiones ya cerradas, no sondeos: parecerían un escaneo desde cualquier web.
    if action == "DROP" and protocol == "TCP" and ("A" in flags or "R" in flags):
        return None
    event = {
        "app": "celeris-firewall",
        "srcip": src,
        "dstip": dst,
        "fw_action": action,
        "fw_protocol": protocol,
        "fw_size": size,
        "fw_flags": flags,
        "fw_icmp_type": fields[13],
    }
    if sport != "-":
        event["srcport"] = sport
    if dport != "-":
        event["dstport"] = dport
    return event


def main():
    source, target, own_ip = sys.argv[1:4]
    position = os.path.getsize(source) if os.path.exists(source) else 0  # Solo interesa lo que ocurra desde ahora.
    pending = b""
    counts = Counter()
    window_start = time.monotonic()

    with open(target, "w", encoding="utf-8", newline="\n") as output:
        while True:
            time.sleep(0.5)
            if not os.path.exists(source):
                continue
            size = os.path.getsize(source)
            if size < position:  # Windows rotó el registro al llegar a su tamaño máximo.
                position, pending = 0, b""
            if size == position:
                continue
            with open(source, "rb") as log:
                log.seek(position)
                chunk = log.read()
                position = log.tell()

            if time.monotonic() - window_start >= WINDOW_SECONDS:
                counts.clear()
                window_start = time.monotonic()

            *lines, pending = (pending + chunk).split(b"\n")
            for raw in lines:
                event = parse(raw.decode("utf-8", "replace").strip(), own_ip)
                if not event or counts["total"] >= MAX_LINES_TOTAL or counts[event["srcip"]] >= MAX_LINES_PER_IP:
                    continue
                counts["total"] += 1
                counts[event["srcip"]] += 1
                output.write(json.dumps(event) + "\n")
            output.flush()


if __name__ == "__main__":
    main()
