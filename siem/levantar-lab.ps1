# Levanta Wazuh y el laboratorio: gateway con rayo-cache, iptables y agente de Wazuh, Suricata y el origen.
# La primera vez compila el proxy en Docker y descarga las imágenes: tarda varios minutos.
. (Join-Path $PSScriptRoot 'comun.ps1')

Initialize-Wazuh -Lab

Write-Host 'Construyendo y levantando el laboratorio. La primera vez compila el proxy y tarda unos minutos...'
ComposeLab up -d --build
if ($LASTEXITCODE -ne 0) { Fail 'Docker no pudo levantar el laboratorio.' }

Wait-WazuhPanel

Write-Host 'Esperando a que el agente del gateway se conecte y reciba la respuesta activa. Tarda menos de un minuto...'
if (-not (Wait-LabAgent 24)) { Fail "El agente no está listo. Mira: docker exec $Gateway tail -n 30 /var/ossec/logs/ossec.log" }

Write-Host 'Esperando a Suricata...'
# Comillas simples dentro del comando: PowerShell 5.1 quita las dobles al pasarlo a docker.
$ready = $false
foreach ($attempt in 1..24) {
    & docker exec $Suricata sh -c 'grep -q ''Engine started'' /var/log/suricata/suricata.log' 2>$null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep 5
}
if (-not $ready) { Fail "Suricata no arrancó. Mira: docker logs $Suricata" }

$rules = & docker exec $Suricata sh -c 'grep -o ''[0-9]* rules successfully loaded'' /var/log/suricata/suricata.log | tail -n 1'
Write-Host ''
Write-Host "Listo. Suricata: $rules. Panel de Wazuh: $PanelUrl" -ForegroundColor Green
Write-Host 'Usuario y contraseña de demo: INDEXER_USERNAME e INDEXER_PASSWORD en siem\wazuh-docker\single-node\docker-compose.yml'
Write-Host 'Siguiente paso: .\siem\simular-ataques-lab.ps1'
