# Equipos del laboratorio: el origen de pruebas, el cliente legítimo y los atacantes usan esta imagen.
FROM alpine:3.22
RUN apk add --no-cache curl nmap python3
COPY siem/origen_demo.py /lab/origen_demo.py
COPY siem/lab/herramientas/ataque.sh /usr/local/bin/ataque
RUN chmod 755 /usr/local/bin/ataque
