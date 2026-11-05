# Simula ataques dentro del laboratorio y comprueba que Wazuh los detecta y que iptables bloquea a los atacantes.
# Cada ataque sale de un contenedor nuevo con su propia IP de la red 10.77.0.0/24. Nada sale de este PC.
. (Join-Path $PSScriptRoot 'comun.ps1')

& docker exec $Gateway true 2>$null
if ($LASTEXITCODE -ne 0) { Fail 'El laboratorio no está en marcha. Ejecuta antes .\siem\levantar-lab.ps1' }
# Si el gateway acaba de arrancar, su agente aún no puede bloquear y los ataques pasarían sin respuesta.
if (-not (Wait-LabAgent 12)) { Fail "El agente del gateway no está listo. Mira: docker exec $Gateway tail -n 30 /var/ossec/logs/ossec.log" }

$exitCode = 0
$legit = '10.77.0.30'

function Attack($title, $mitre, $ip, $name) {
    Write-Host ''
    Write-Host "== $title" -ForegroundColor Cyan
    Write-Host "   Origen: $ip   MITRE ATT&CK: $mitre"
    Invoke-LabAttack $ip $name | ForEach-Object { Write-Host "   $_" }
}

function Get-BlockedIps {
    $rules = & docker exec $Gateway iptables -S RAYO-BLOQUEO
    return @($rules | ForEach-Object { if ($_ -match '-s (\S+)/') { $Matches[1] } })
}

# Empieza sin bloqueos, por si se repite antes de que venzan los de la vez anterior.
& docker exec $Gateway iptables -F RAYO-BLOQUEO
Write-Host 'Bloqueos anteriores borrados.'

Write-Host ''
Write-Host "== 0. Un equipo normal usa el proxy" -ForegroundColor Cyan
Write-Host "   Origen: $legit   Respuesta: $(Invoke-LabAttack $legit comprobar)"

Attack '1. Un equipo no autorizado intenta usar el proxy' 'T1133' '10.77.0.200' 'intruso'
Attack '2. Fuerza bruta contra el token de administración' 'T1110.001' '10.77.0.67' 'fuerza-bruta'
Attack '3. Escaneo de puertos a través del proxy' 'T1046' '10.77.0.51' 'escaneo-proxy'
Attack '4. SSRF: metadatos de la nube, el SIEM y la red interna' 'T1090, T1552.005' '10.77.0.52' 'ssrf'
Attack '5. Inundación de peticiones' 'T1499' '10.77.0.50' 'inundacion'
Attack '6. Suplantar el nombre del servidor (solo avisa: nivel 8)' 'T1090.004' '10.77.0.53' 'nombre-suplantado'
Attack '7. Escaneo de red contra el gateway: el proxy no lo ve, Suricata sí' 'T1046' '10.77.0.54' 'escaneo-red'
Attack '8. Log4Shell a través del proxy: el proxy lo deja pasar, Suricata no' 'T1190' '10.77.0.55' 'log4shell'
Attack '9. Inyección SQL con sqlmap a través del proxy' 'T1190, T1595.002' '10.77.0.56' 'sqli'

Write-Host ''
Write-Host 'Esperando 20 s a que Wazuh responda a las últimas alertas...'
Start-Sleep 20

$attackers = [ordered]@{
    '10.77.0.200' = 'no autorizado'
    '10.77.0.67'  = 'fuerza bruta'
    '10.77.0.51'  = 'escaneo vía proxy'
    '10.77.0.52'  = 'SSRF'
    '10.77.0.50'  = 'inundación'
    '10.77.0.54'  = 'escaneo de red'
    '10.77.0.55'  = 'Log4Shell'
    '10.77.0.56'  = 'inyección SQL'
}
$notBlocked = [ordered]@{
    $legit       = 'equipo normal'
    '10.77.0.53' = 'nombre suplantado'
}

Write-Host ''
Write-Host '== Bloqueos en el gateway (iptables -S RAYO-BLOQUEO)' -ForegroundColor Cyan
& docker exec $Gateway iptables -S RAYO-BLOQUEO | ForEach-Object { Write-Host "   $_" }
$blocked = Get-BlockedIps

Write-Host ''
Write-Host '== ¿Pueden seguir usando el proxy?' -ForegroundColor Cyan
foreach ($ip in @($attackers.Keys) + @($notBlocked.Keys)) {
    $shouldBlock = $attackers.Contains($ip)
    $label = if ($shouldBlock) { $attackers[$ip] } else { $notBlocked[$ip] }
    $code = Invoke-LabAttack $ip comprobar
    $isBlocked = $blocked -contains $ip
    # 403 es la respuesta del proxy al equipo no autorizado: si llega, la IP no está bloqueada.
    $ok = if ($shouldBlock) { $isBlocked -and $code -eq '000' } else { -not $isBlocked -and $code -eq '200' }
    $state = if ($code -eq '000') { 'sin respuesta (bloqueada)' } else { "responde $code" }
    $color = if ($ok) { 'Green' } else { 'Red' }
    Write-Host ("   {0,-12} {1,-18} {2}" -f $ip, $label, $state) -ForegroundColor $color
    if (-not $ok) { $exitCode = 1 }
}

$expected = 100111, 100121, 100131, 100140, 100141, 100151, 100160, 100200, 100201, 100202, 100203, 100204, 100251
Write-Host ''
Write-Host 'Esperando a que las alertas lleguen al índice de Wazuh (60 s como máximo)...'
$missing = @(Wait-RayoRules $expected 5 60)
& (Join-Path $Siem 'ver-alertas.ps1') -Minutos 5

if ($missing.Count -eq 0) {
    Write-Host "Comprobación: las $($expected.Count) reglas esperadas llegaron al índice de Wazuh." -ForegroundColor Green
} else {
    Write-Host "Comprobación: faltan en el índice las reglas $($missing -join ', ')." -ForegroundColor Red
    $exitCode = 1
}
Write-Host ''
Write-Host 'Los bloqueos vencen solos 10 minutos después de la última alerta de cada IP (regla 100252).'
Write-Host "Míralas en el panel: $PanelUrl (Threat Hunting > Events, filtro rule.groups:rayo)"
exit $exitCode
