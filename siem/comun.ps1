# Rutas y funciones que comparten los scripts de la demostración.
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$Siem = $PSScriptRoot
$Repo = Split-Path $Siem -Parent
$Demo = Join-Path $Siem 'demo'
$WazuhDocker = Join-Path $Siem 'wazuh-docker'
$SingleNode = Join-Path $WazuhDocker 'single-node'
$WazuhVersion = 'v4.14.9'
$Project = 'celeris-wazuh'
$Manager = "$Project-wazuh.manager-1"
$Proxy = 'http://127.0.0.1:3190'
$AdminUrl = 'http://127.0.0.1:3191'
$PanelUrl = 'https://localhost:5601'
$Origin = 'http://127.0.0.99:8099'
$FirewallLog = Join-Path $Demo 'firewall\pfirewall.log'

function Compose {
    & docker compose -p $Project -f (Join-Path $SingleNode 'docker-compose.yml') -f (Join-Path $Siem 'compose.celeris.yml') @args
}

function Fail($message) {
    Write-Host "ERROR: $message" -ForegroundColor Red
    exit 1
}

function Write-OssecConf {
    # La configuración oficial, con las revisiones de archivos limitadas a los de la demo y los logs de la demo.
    $official = [IO.File]::ReadAllText((Join-Path $SingleNode 'config\wazuh_cluster\wazuh_manager.conf'))
    $syscheck = [IO.File]::ReadAllText((Join-Path $Siem 'wazuh\celeris-syscheck.xml'))
    $localfile = [IO.File]::ReadAllText((Join-Path $Siem 'wazuh\celeris-localfile.xml'))
    $merged = [regex]::Replace($official, '(?s)[ \t]*<syscheck>.*?</syscheck>\r?\n', { param($m) $syscheck }) + "`n" + $localfile
    # La base de vulnerabilidades ocupa unos 11 GB y esta demo no tiene agentes que analizar.
    $merged = $merged -replace '(<vulnerability-detection>\s*<enabled>)yes', '$1no'
    [IO.File]::WriteAllText((Join-Path $Demo 'ossec.conf'), ($merged -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding $false))
    # Debe existir antes de que Wazuh arranque, aunque Apache aún no esté en marcha.
    $apacheLog = Join-Path $Demo 'logs\apache-access.log'
    if (-not (Test-Path $apacheLog)) { New-Item -ItemType File $apacheLog | Out-Null }
    $firewallEvents = Join-Path $Demo 'logs\firewall.jsonl'
    if (-not (Test-Path $firewallEvents)) { New-Item -ItemType File $firewallEvents | Out-Null }
}

# Por defecto, la demo solo escucha en este PC. Exponerla exige pedirlo cada vez con exponer-red.ps1.
function Write-DemoConfig([string]$Listen = '', [string[]]$ExtraClients = @()) {
    $text = [IO.File]::ReadAllText((Join-Path $Siem 'demo-proxy.toml'))
    if ($Listen) { $text = $text -replace '(?m)^listen = [^\r\n]*', "listen = `"$Listen`"" }
    foreach ($client in $ExtraClients) {
        $network = if ($client -match '/') { $client } else { "$client/32" }
        $text = $text -replace '(?m)^allowed_clients = \[', "allowed_clients = [`"$network`", "
    }
    [IO.File]::WriteAllText((Join-Path $Demo 'config.toml'), $text, (New-Object Text.UTF8Encoding $false))
}

function Start-DemoProxy {
    $process = Start-Process (Join-Path $Demo 'celeris-cache.exe') -ArgumentList 'config.toml' -WorkingDirectory $Demo -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $Demo 'proxy.out') -RedirectStandardError (Join-Path $Demo 'proxy.err')
    Set-Content (Join-Path $Demo 'proxy.pid') $process.Id
    Start-Sleep 2
    if ($process.HasExited) { Fail "El proxy no arrancó. Revisa $Demo\proxy.err" }
}

function Start-DemoOrigin {
    $process = Start-Process python -ArgumentList "`"$(Join-Path $Siem 'origen_demo.py')`"" -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $Demo 'origen.out') -RedirectStandardError (Join-Path $Demo 'origen.err')
    Set-Content (Join-Path $Demo 'origen.pid') $process.Id
}

# Sigue el registro del firewall aunque aún no exista: empieza a leerlo en cuanto aparece.
function Start-DemoFirewallReader([string]$Ip) {
    $arguments = "`"$(Join-Path $Siem 'firewall_a_json.py')`" `"$FirewallLog`" `"$(Join-Path $Demo 'logs\firewall.jsonl')`" $Ip"
    $process = Start-Process python -ArgumentList $arguments -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $Demo 'firewall.out') -RedirectStandardError (Join-Path $Demo 'firewall.err')
    Set-Content (Join-Path $Demo 'firewall.pid') $process.Id
}

function Stop-DemoProcess($name) {
    $file = Join-Path $Demo "$name.pid"
    if (-not (Test-Path $file)) { return }
    $process = Get-Process -Id ([int](Get-Content $file)) -ErrorAction SilentlyContinue
    # Apache lanza un proceso hijo que retiene el puerto: se cierra el árbol completo.
    if ($process) {
        & taskkill.exe /PID $process.Id /T /F *> $null
        # taskkill vuelve antes de que el proceso termine, y Windows mantiene su ejecutable bloqueado.
        $process.WaitForExit(5000) | Out-Null
    }
    Remove-Item $file
}

# Alertas de celeris-cache guardadas en el índice: lo que muestra el panel, no solo lo que generó el manager.
function Get-CelerisAlerts($minutes, $limit) {
    $query = @{
        size = $limit
        sort = @(@{ timestamp = 'desc' })
        query = @{ bool = @{ filter = @(
            @{ term = @{ 'rule.groups' = 'celeris' } },
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
