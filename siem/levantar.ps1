# Levanta Wazuh en Docker y una instancia del proxy solo para la demostración.
# La primera vez descarga varios GB. Al terminar, usa memoria hasta que ejecutes detener.ps1.
. (Join-Path $PSScriptRoot 'comun.ps1')

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
[IO.File]::WriteAllText((Join-Path $Demo 'ossec.conf'), ($merged -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding $false))

if (-not (Test-Path (Join-Path $SingleNode 'config\wazuh_indexer_ssl_certs\root-ca.pem'))) {
    Write-Host 'Generando los certificados internos de Wazuh...'
    & docker compose -p "$Project-certs" -f (Join-Path $SingleNode 'generate-indexer-certs.yml') run --rm generator *> (Join-Path $Demo 'certs.log')
    if ($LASTEXITCODE -ne 0) { Fail "No se pudieron generar los certificados. Revisa $Demo\certs.log" }
}

$binary = Join-Path $Demo 'rayo-cache.exe'
if (-not (Test-Path $binary)) {
    Write-Host 'Compilando el proxy. La primera vez tarda unos minutos...'
    # Carpeta propia: la compilación normal falla si tu proxy real está en marcha.
    $target = Join-Path $Demo 'target'
    & cargo build --release --manifest-path (Join-Path $Repo 'Cargo.toml') --target-dir $target
    if ($LASTEXITCODE -ne 0) { Fail 'No se pudo compilar el proxy.' }
    Copy-Item (Join-Path $target 'release\rayo-cache.exe') $binary
}

if (-not (Test-ProxyRunning)) {
    Write-Host "Arrancando el proxy de demostración en $Proxy..."
    $process = Start-Process $binary -ArgumentList 'config.toml' -WorkingDirectory $Demo -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $Demo 'proxy.out') -RedirectStandardError (Join-Path $Demo 'proxy.err')
    Set-Content (Join-Path $Demo 'proxy.pid') $process.Id
    Start-Sleep 2
    if ($process.HasExited) { Fail "El proxy no arrancó. Revisa $Demo\proxy.err" }

    $process = Start-Process python -ArgumentList "`"$(Join-Path $Siem 'origen_demo.py')`"" -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $Demo 'origen.out') -RedirectStandardError (Join-Path $Demo 'origen.err')
    Set-Content (Join-Path $Demo 'origen.pid') $process.Id
}

Write-Host 'Levantando Wazuh...'
Compose up -d
if ($LASTEXITCODE -ne 0) { Fail 'Docker no pudo levantar Wazuh.' }

Write-Host 'Esperando al panel de Wazuh. Suele tardar entre 1 y 3 minutos...'
$ready = $false
foreach ($attempt in 1..80) {
    $code = & curl.exe -sk -o NUL -w '%{http_code}' --max-time 3 "$PanelUrl/app/login"
    if ($code -eq '200') { $ready = $true; break }
    Start-Sleep 5
}
if (-not $ready) { Fail "El panel no respondió a tiempo. Mira los registros con: docker logs $Project-wazuh.dashboard-1" }

Write-Host ''
Write-Host "Listo. Panel de Wazuh: $PanelUrl" -ForegroundColor Green
Write-Host 'El navegador avisará del certificado autofirmado: es esperado en esta demo.'
Write-Host 'Usuario y contraseña de demo: INDEXER_USERNAME e INDEXER_PASSWORD en siem\wazuh-docker\single-node\docker-compose.yml'
Write-Host 'Siguiente paso: .\siem\simular-ataques.ps1'
