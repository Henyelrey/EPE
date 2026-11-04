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

Si cambias `wazuh/local_rules.xml`, aplícalo sin reiniciar la demo:

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
- **Sin bloqueo automático:** Wazuh avisa, pero no bloquea. Tampoco hay bloqueo de IPs en el puerto de administración, así que el token debe seguir siendo largo y aleatorio.
- **Tráfico cifrado sin descifrar:** los túneles solo dejan el puerto y el destino. Wazuh no ve lo que viaja dentro.

## Activarlo en tu proxy real

Añade estas líneas al principio de `config.toml` y reinicia el proxy. El aviso de `http://rayo.aviso/` pasará a indicar que el registro está activo, y debes actualizar también tu [aviso a los usuarios](../docs/AVISO.md), porque este log guarda la IP real.

```toml
security_log_enabled = true
security_log_dir = "./logs"
security_log_retention_days = 30
```
