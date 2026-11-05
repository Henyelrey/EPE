# Demostración con Wazuh

Levanta [Wazuh](https://wazuh.com/) 4.14.9 en Docker, le envía los eventos de seguridad de una instancia de `rayo-cache` y simula ataques para ver cómo aparecen.

La demostración usa su propio proxy, en los puertos 3190 y 3191, con su propia caché y su propia CA. Tu proxy real no se toca.

## Requisitos

- Docker Desktop en marcha, con al menos 4 GB de memoria disponibles para Docker.
- Unos 10 GB libres en el disco de Docker. Las imágenes ocupan 7,5 GB.
- Python, `git` y `curl.exe`. Si no existe `siem/demo/rayo-cache.exe`, también Rust para compilarlo.

## Uso

Ejecuta los comandos en PowerShell, desde la raíz del repositorio.

1. Levanta Wazuh y el proxy de demostración. Si PowerShell no permite scripts, antepón `powershell -ExecutionPolicy Bypass -File`.

   ```powershell
   .\siem\levantar.ps1
   ```

2. Lanza los ataques simulados. Tarda unos 2 minutos y al final muestra las alertas.

   ```powershell
   .\siem\simular-ataques.ps1
   ```

3. Abre `https://localhost:5601` y entra con `INDEXER_USERNAME` e `INDEXER_PASSWORD` de `siem/wazuh-docker/single-node/docker-compose.yml`. Ve a **Threat Hunting > Events** y filtra con `rule.groups:rayo`. Para ver solo los ataques probables, usa `rule.groups:rayo and rule.level>=10`. **MITRE ATT&CK** agrupa las mismas alertas por técnica.

4. Vuelve a ver las alertas desde la terminal cuando quieras:

   ```powershell
   .\siem\ver-alertas.ps1 -Minutos 60
   ```

5. Al terminar, libera la memoria. Con `-Borrar` también elimina las alertas y los datos de la demo.

   ```powershell
   .\siem\detener.ps1
   ```

Si cambias `wazuh/local_rules.xml` o `wazuh/rayo-active-response.xml`, aplícalo sin reiniciar la demo:

```powershell
.\siem\recargar-reglas.ps1
```

## Qué se simula

Todo ocurre dentro de este PC. Las direcciones `127.0.0.x` hacen de otros equipos de la red, y el proxy bloquea los destinos internos antes de conectarse a ellos.

| Ataque | Origen | Evento del proxy | Regla de Wazuh | Nivel | MITRE ATT&CK |
|---|---|---|---|---|---|
| Equipo no autorizado | `127.0.0.66` | `client_denied` | 100110, y 100111 si insiste | 5, 10 | T1133 |
| Fuerza bruta contra el token | `127.0.0.67` | `admin_auth_failed` | 100120, y 100121 si insiste | 5, 12 | T1110.001 |
| Escaneo de puertos | `127.0.0.51` | `port_blocked` | 100130, y 100131 si insiste | 5, 10 | T1046 |
| SSRF a la red interna | `127.0.0.52` | `destination_blocked` | 100140 | 7 | T1090 |
| SSRF a los metadatos de la nube | `127.0.0.52` | `destination_blocked` | 100141 | 12 | T1552.005 |
| Inundación | `127.0.0.50` | `rate_limited` | 100150, 100151 y 100152 | 5, 10, 8 | T1499 |
| Nombre de servidor suplantado | `127.0.0.53` | `detection` | 100160 | 8 | T1090.004 |
| Objeto de la caché alterado | Disco | `alert_raised` y revisión de integridad | 100171, 100183 | 13, 12 | T1565.001 |
| Clave de la CA alterada | Disco | Revisión de integridad | 100180 | 14 | T1552.004 |
| Configuración alterada | Disco | Revisión de integridad | 100182 | 10 | T1562.001 |

## Cómo está montado

- **Log de seguridad:** el proxy escribe `siem/demo/logs/security-AAAA-MM-DD.jsonl`, una línea JSON por evento. La sección "Log de seguridad para un SIEM" del [README principal](../README.md) describe cada evento.
- **Lectura:** el manager de Wazuh lee esa carpeta montada en `/var/rayo`. Las reglas están en [`wazuh/local_rules.xml`](wazuh/local_rules.xml).
- **Integridad:** Wazuh revisa cada 30 segundos la CA, la configuración y los objetos de la caché. En esta demo es una revisión periódica, así que un cambio tarda hasta 30 segundos en aparecer.
- **Red:** [`compose.rayo.yml`](compose.rayo.yml) publica únicamente el panel, y solo en `127.0.0.1`. Los archivos oficiales de Wazuh se descargan en `siem/wazuh-docker/`.

## Límites de esta demostración

Esta configuración no sirve para producción:

- **Contraseñas por defecto:** son públicas. Antes de exponer Wazuh, sigue la guía oficial para [cambiarlas](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html).
- **Manager y proxy en el mismo PC:** en producción, instala un agente de Wazuh en la máquina del proxy y mantén el manager aparte. La CA real no debe montarse en otro servicio.
- **Direcciones simuladas:** las `127.0.0.x` imitan otros equipos. Un ataque real desde la red necesitaría que el proxy escuche en esa red y que `allowed_clients` lo permita.
- **Atacante con control del PC:** podría borrar el log antes de que Wazuh lo lea. Un agente reduce ese margen, porque envía los eventos en cuanto aparecen.
- **Sin análisis de vulnerabilidades:** está desactivado porque descarga una base de datos de unos 11 GB y aquí no hay agentes que analizar.
- **Sin bloqueo automático:** Wazuh avisa, pero no bloquea. Tampoco hay bloqueo de IPs en el puerto de administración, así que el token debe seguir siendo largo y aleatorio. El [laboratorio](#laboratorio-con-suricata-y-bloqueo-automático) añade ambas cosas.
- **Tráfico cifrado sin descifrar:** los túneles solo dejan el puerto y el destino. Wazuh no ve lo que viaja dentro.

## Laboratorio con Suricata y bloqueo automático

La demo anterior solo avisa. El laboratorio añade lo que le falta: **Suricata** mira el tráfico de red del proxy y **Wazuh bloquea con iptables** a quien ataca. Corre entero en Docker, en una red propia (`10.77.0.0/24`) que no se publica fuera de este PC.

```
 atacantes y cliente ──▶ rayo-gateway 10.77.0.10 ──▶ rayo-origen 10.77.0.20
   10.77.0.x               ├─ rayo-cache (3128, panel 9128)
                           ├─ iptables: cadena RAYO-BLOQUEO, la primera de INPUT
                           ├─ agente de Wazuh: envía los logs y ejecuta los bloqueos
                           └─ Suricata: comparte su interfaz y ve cada paquete
                                   │ eventos ▲ bloquear IP
                                   ▼         │
                           wazuh.manager 10.77.0.5
```

1. El proxy y Suricata escriben sus eventos en el gateway. El agente de Wazuh los envía al manager.
2. Si salta una regla de ataque probable, el manager ordena al agente ejecutar [`rayo-bloquear`](lab/gateway/rayo-bloquear).
3. El script añade `-s IP -j DROP` a la cadena `RAYO-BLOQUEO` y lo anota. A los 10 minutos Wazuh ordena quitarlo.

### Uso

Requiere lo mismo que la demo anterior, pero no Python ni Rust: el proxy se compila dentro de Docker. La primera vez descarga unos 500 MB más y compila el proxy en un par de minutos. Después, `levantar-lab.ps1` tarda alrededor de un minuto. Los contenedores del laboratorio suman unos 150 MB de memoria a los de Wazuh.

```powershell
.\siem\levantar-lab.ps1
.\siem\simular-ataques-lab.ps1     # poco más de un minuto; termina con error si algo no se detecta o no se bloquea
.\siem\detener.ps1                 # detiene la demo y el laboratorio
```

`levantar-lab.ps1` no termina hasta que el agente del gateway puede bloquear. Un agente nuevo tarda unos 40 s: espera 20 s antes de conectarse y, al conectarse, recibe la respuesta activa del manager y se reinicia. Una orden de bloqueo que llegara antes se perdería sin dejar rastro.

Las dos demos comparten Wazuh, pero el manager solo lleva la respuesta activa en el laboratorio: al pasar de una a otra con su script `levantar`, se recrea con la configuración que toca. Para ver los bloqueos a mano:

```powershell
docker exec rayo-wazuh-rayo-gateway-1 iptables -S RAYO-BLOQUEO
docker exec rayo-wazuh-rayo-gateway-1 cat /var/log/rayo-ips/bloqueos.jsonl
```

### Qué se simula

Cada ataque sale de un contenedor nuevo con su propia IP. Al final, el script comprueba que cada atacante quedó bloqueado y que el equipo normal (`10.77.0.30`) y el de nivel 8 siguen funcionando.

| Ataque | Origen | Lo detecta | Regla | ¿Bloquea? |
|---|---|---|---|---|
| Equipo no autorizado | `10.77.0.200` | Proxy | 100111 | Sí |
| Fuerza bruta contra el token | `10.77.0.67` | Proxy | 100121 | Sí |
| Escaneo de puertos a través del proxy | `10.77.0.51` | Proxy | 100131 | Sí |
| SSRF a los metadatos, al SIEM y a la red interna | `10.77.0.52` | Proxy y Suricata | 100140, 100141, 100204 | Sí |
| Inundación | `10.77.0.50` | Proxy | 100151 | Sí |
| Nombre de servidor suplantado | `10.77.0.53` | Proxy | 100160 | No: nivel 8, solo avisa |
| Escaneo de red contra el gateway | `10.77.0.54` | Solo Suricata | 100200 | Sí |
| Log4Shell en una cabecera | `10.77.0.55` | Solo Suricata | 100201 | Sí |
| Inyección SQL con sqlmap | `10.77.0.56` | Solo Suricata | 100202, 100203 | Sí |

Los tres últimos muestran para qué sirve Suricata aquí: el proxy no ve un escaneo que no va dirigido a él, y deja pasar una petición permitida aunque lleve un ataque dentro, porque no inspecciona el contenido.

### Piezas

| Archivo | Qué hace |
|---|---|
| [`lab/compose.lab.yml`](lab/compose.lab.yml) | Red del laboratorio, gateway, Suricata y origen. Se aplica encima de la demo anterior. |
| [`lab/gateway.Dockerfile`](lab/gateway.Dockerfile) | Compila el proxy e instala iptables y el agente de Wazuh 4.14.9. |
| [`lab/gateway/rayo-bloquear`](lab/gateway/rayo-bloquear) | Respuesta activa. Entiende la IP del proxy (`srcip`) y la de Suricata (`src_ip`), que `firewall-drop` de Wazuh no lee. |
| [`lab/gateway/no-bloquear`](lab/gateway/no-bloquear) | IPs que nunca se bloquean: el manager, el gateway, el origen y la puerta de enlace de Docker. |
| [`lab/gateway/agente-listo`](lab/gateway/agente-listo) | Dice si el agente ya puede bloquear. Lo usan `levantar-lab.ps1` y `simular-ataques-lab.ps1`. |
| [`lab/suricata/rayo.rules`](lab/suricata/rayo.rules) | Las 5 firmas propias, `sid` 9100001 a 9100005. |
| [`lab/suricata/rayo.yaml`](lab/suricata/rayo.yaml) | Se añade al `suricata.yaml` de la imagen: las reglas y un `eve.json` solo con alertas. La red a proteger, `HOME_NET`, se pasa en el compose. |
| [`wazuh/rayo-active-response.xml`](wazuh/rayo-active-response.xml) | Qué reglas bloquean y durante cuánto tiempo. |
| [`wazuh/local_rules.xml`](wazuh/local_rules.xml) | 100200 a 100204 para Suricata y 100251 a 100253 para lo que hizo la respuesta activa. |

### Decisiones y límites

- **Solo bloquean los ataques probables** (nivel 10 o más). Un aviso suelto o de nivel 8 no corta a nadie: un falso positivo dejaría sin servicio a un equipo legítimo.
- **El bloqueo es por IP y temporal.** Un atacante puede cambiar de IP, y en una red con NAT una IP puede ser de varios equipos, que quedarían bloqueados a la vez.
- **El escaneo de red se puede falsificar.** Las alertas del proxy y las firmas HTTP de Suricata salen de conexiones TCP establecidas, así que su IP de origen no se puede inventar sin estar en medio de la conexión. La regla 100200 salta con paquetes SYN sueltos: alguien de la red puede enviarlos con la IP de otro equipo y hacer que lo bloqueen 10 minutos. `no-bloquear` protege al manager, al gateway y al origen, pero no a los clientes. En una red real, quita 100200 de `rules_id` en `rayo-active-response.xml` y deja que solo avise.
- **Bloquear solo a partir de la IP de la conexión.** `rayo-bloquear` acepta solo direcciones bien formadas y respeta `no-bloquear`, pero quien pueda escribir en los logs del gateway elige a quién bloquear. Si añades reglas que bloqueen, no uses campos que el cliente controle, como `Host` o el `User-Agent`.
- **Suricata solo guarda alertas, sin contenido ni URLs.** Ve las URLs completas de las peticiones HTTP sin cifrar, con parámetros que pueden llevar tokens, y el proxy nunca las registra. Si activas más tipos de evento en `rayo.yaml`, actualiza el aviso a los usuarios.
- **Suricata no ve dentro de los túneles HTTPS.** Ve el `CONNECT` y el cifrado, pero no lo que va dentro. Las firmas HTTP solo cubren `http://`.
- **El bloqueo llega tras la detección.** Pasan uno o dos segundos entre la alerta y la regla de iptables: una ráfaga corta puede completarse antes.
- **Las contraseñas de Wazuh siguen siendo las de serie**, como en la demo anterior.

## Activarlo en tu proxy real

Añade estas líneas al principio de `config.toml` y reinicia el proxy. El aviso de `http://rayo.aviso/` pasará a indicar que el registro está activo, y debes actualizar también tu [aviso a los usuarios](../docs/AVISO.md), porque este log guarda la IP real.

```toml
security_log_enabled = true
security_log_dir = "./logs"
security_log_retention_days = 30
```
