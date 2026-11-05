# Rutas y funciones que comparten los scripts de la demostración.
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$Siem = $PSScriptRoot
$Repo = Split-Path $Siem -Parent
$Demo = Join-Path $Siem 'demo'
$WazuhDocker = Join-Path $Siem 'wazuh-docker'
$SingleNode = Join-Path $WazuhDocker 'single-node'
$WazuhVersion = 'v4.14.9'
$Project = 'rayo-wazuh'
$Manager = "$Project-wazuh.manager-1"
$Proxy = 'http://127.0.0.1:3190'
$AdminUrl = 'http://127.0.0.1:3191'
$PanelUrl = 'https://localhost:5601'
$Origin = 'http://localhost:8099'

# Laboratorio con Suricata y bloqueo automático (siem/lab).
$LabDir = Join-Path $Siem 'lab'
$LabNetwork = 'rayo-lab'
$LabTools = 'rayo-lab-herramientas'
$Gateway = "$Project-rayo-gateway-1"
$Suricata = "$Project-rayo-suricata-1"

function Compose {
    & docker compose -p $Project -f (Join-Path $SingleNode 'docker-compose.yml') -f (Join-Path $Siem 'compose.rayo.yml') @args
}

function ComposeLab {
    & docker compose -p $Project -f (Join-Path $SingleNode 'docker-compose.yml') -f (Join-Path $Siem 'compose.rayo.yml') `
        -f (Join-Path $LabDir 'compose.lab.yml') @args
}

# Descarga Wazuh, genera sus certificados y escribe la configuración del manager. Con -Lab añade la
# respuesta activa. El manager la lee al arrancar: cambiar de demo lo recrea, y recargar-reglas.ps1 se la
# aplica sin recrearlo.
function Initialize-Wazuh([switch]$Lab) {
    & docker version --format '{{.Server.Version}}' *> $null
    if ($LASTEXITCODE -ne 0) { Fail 'Docker no responde. Abre Docker Desktop y vuelve a intentarlo.' }

    if (-not (Test-Path $SingleNode)) {
        Write-Host "Descargando los archivos oficiales de Wazuh $WazuhVersion..."
        & git -c advice.detachedHead=false clone -q --depth 1 -b $WazuhVersion https://github.com/wazuh/wazuh-docker.git $WazuhDocker
        if ($LASTEXITCODE -ne 0) { Fail 'No se pudo descargar wazuh-docker.' }
    }

    foreach ($dir in 'data', 'logs', 'ca') {
        New-Item -ItemType Directory -Force (Join-Path $Demo $dir) | Out-Null
    }
    $config = Join-Path $Demo 'config.toml'
    if (-not (Test-Path $config)) { Copy-Item (Join-Path $Siem 'demo-proxy.toml') $config }

    # La configuración oficial, con las revisiones de archivos limitadas a los de la demo y el log del proxy.
    $official = [IO.File]::ReadAllText((Join-Path $SingleNode 'config\wazuh_cluster\wazuh_manager.conf'))
    $syscheck = [IO.File]::ReadAllText((Join-Path $Siem 'wazuh\rayo-syscheck.xml'))
    $localfile = [IO.File]::ReadAllText((Join-Path $Siem 'wazuh\rayo-localfile.xml'))
    $merged = [regex]::Replace($official, '(?s)[ \t]*<syscheck>.*?</syscheck>\r?\n', { param($m) $syscheck }) + "`n" + $localfile
    # La base de vulnerabilidades ocupa unos 11 GB y esta demo no tiene agentes que analizar.
    $merged = $merged -replace '(<vulnerability-detection>\s*<enabled>)yes', '$1no'
    if ($Lab) {
        # Al recrear el gateway, su agente vuelve a registrarse con el mismo nombre: se reemplaza al anterior.
        $force = '<force><enabled>yes</enabled><key_mismatch>yes</key_mismatch><disconnected_time enabled="no">1h</disconnected_time><after_registration_time>1s</after_registration_time></force>'
        $merged = $merged -replace '</auth>', "  $force`n  </auth>"
        $merged += "`n" + [IO.File]::ReadAllText((Join-Path $Siem 'wazuh\rayo-active-response.xml'))
    }
    [IO.File]::WriteAllText((Join-Path $Demo 'ossec.conf'), ($merged -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding $false))

    if (-not (Test-Path (Join-Path $SingleNode 'config\wazuh_indexer_ssl_certs\root-ca.pem'))) {
        Write-Host 'Generando los certificados internos de Wazuh...'
        & docker compose -p "$Project-certs" -f (Join-Path $SingleNode 'generate-indexer-certs.yml') run --rm generator *> (Join-Path $Demo 'certs.log')
        if ($LASTEXITCODE -ne 0) { Fail "No se pudieron generar los certificados. Revisa $Demo\certs.log" }
    }
}

function Wait-WazuhPanel {
    Write-Host 'Esperando al panel de Wazuh. Suele tardar entre 1 y 3 minutos...'
    foreach ($attempt in 1..80) {
        $code = & curl.exe -sk -o NUL -w '%{http_code}' --max-time 3 "$PanelUrl/app/login"
        if ($code -eq '200') { return }
        Start-Sleep 5
    }
    Fail "El panel no respondió a tiempo. Mira los registros con: docker logs $Project-wazuh.dashboard-1"
}

# Espera hasta que el agente del gateway pueda bloquear (siem/lab/gateway/agente-listo), en pasos de 5 s.
function Wait-LabAgent($attempts) {
    foreach ($attempt in 1..$attempts) {
        & docker exec $Gateway agente-listo 2>$null
        if ($LASTEXITCODE -eq 0) { return $true }
        Start-Sleep 5
    }
    return $false
}

# Ejecuta un ataque de siem/lab/herramientas/ataque.sh desde un equipo nuevo con la IP indicada.
function Invoke-LabAttack($ip, $name) {
    & docker run --rm --network $LabNetwork --ip $ip $LabTools ataque $name
}

function Fail($message) {
    Write-Host "ERROR: $message" -ForegroundColor Red
    exit 1
}

function Stop-DemoProcess($name) {
    $file = Join-Path $Demo "$name.pid"
    if (-not (Test-Path $file)) { return }
    $process = Get-Process -Id ([int](Get-Content $file)) -ErrorAction SilentlyContinue
    if ($process) { Stop-Process -Id $process.Id -Force }
    Remove-Item $file
}

# Alertas de rayo-cache guardadas en el índice: lo que muestra el panel, no solo lo que generó el manager.
function Get-RayoAlerts($minutes, $limit) {
    $query = @{
        size = $limit
        sort = @(@{ timestamp = 'desc' })
        query = @{ bool = @{ filter = @(
            @{ term = @{ 'rule.groups' = 'rayo' } },
            @{ range = @{ timestamp = @{ gte = "now-$($minutes)m" } } }
        ) } }
    } | ConvertTo-Json -Depth 8 -Compress

    $request = 'curl -sk -u "$INDEXER_USERNAME:$INDEXER_PASSWORD" -H "Content-Type: application/json" -d @- "https://wazuh.indexer:9200/wazuh-alerts-*/_search"'
    # PowerShell 5.1 quita las comillas dobles de los argumentos si no se escapan.
    $answer = $query | & docker exec -i $Manager sh -c ($request -replace '"', '\"')
    if ($LASTEXITCODE -ne 0) { Fail 'Wazuh no responde. Ejecuta .\siem\levantar.ps1' }
    $result = ($answer -join "`n") | ConvertFrom-Json
    if ($result.error) { Fail "El índice respondió con un error: $($result.error.type)" }
    return @($result.hits.hits | ForEach-Object { $_._source })
}

function Test-ProxyRunning {
    $file = Join-Path $Demo 'proxy.pid'
    if (-not (Test-Path $file)) { return $false }
    return [bool](Get-Process -Id ([int](Get-Content $file)) -ErrorAction SilentlyContinue)
}
