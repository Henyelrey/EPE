# Gateway del laboratorio: rayo-cache, iptables y un agente de Wazuh en el mismo equipo.
# Se construye desde la raíz del repositorio (ver compose.lab.yml).

FROM rust:1.98.1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-20261005-slim
ARG WAZUH_AGENT_VERSION=4.14.9-1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg iptables jq procps \
 && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update \
 && WAZUH_MANAGER=wazuh.manager WAZUH_AGENT_NAME=rayo-gateway apt-get install -y --no-install-recommends wazuh-agent=$WAZUH_AGENT_VERSION \
 && apt-get purge -y gnupg && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# El agente lee el log de seguridad del proxy, las alertas de Suricata y los bloqueos.
COPY siem/lab/gateway/agente.xml /tmp/agente.xml
RUN cat /tmp/agente.xml >> /var/ossec/etc/ossec.conf && rm /tmp/agente.xml \
 # Los archivos que aparecen después de arrancar se detectan en segundos, no en un minuto.
 && echo 'logcollector.vcheck_files=5' >> /var/ossec/etc/local_internal_options.conf

COPY siem/lab/gateway/rayo-bloquear /var/ossec/active-response/bin/rayo-bloquear
COPY siem/lab/gateway/no-bloquear /etc/rayo-ips/no-bloquear
RUN chown root:wazuh /var/ossec/active-response/bin/rayo-bloquear \
 && chmod 750 /var/ossec/active-response/bin/rayo-bloquear

COPY --from=build /src/target/release/rayo-cache /usr/local/bin/rayo-cache
COPY siem/lab/gateway/proxy.toml /opt/rayo/config.toml
COPY siem/lab/gateway/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY siem/lab/gateway/agente-listo /usr/local/bin/agente-listo
RUN chmod 755 /usr/local/bin/entrypoint.sh /usr/local/bin/agente-listo

WORKDIR /opt/rayo
EXPOSE 3128 9128
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
