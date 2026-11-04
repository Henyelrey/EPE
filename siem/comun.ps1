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

function Compose {
    & docker compose -p $Project -f (Join-Path $SingleNode 'docker-compose.yml') -f (Join-Path $Siem 'compose.rayo.yml') @args
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
