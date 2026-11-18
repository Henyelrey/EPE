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

Write-OssecConf

if (-not (Test-Path (Join-Path $SingleNode 'config\wazuh_indexer_ssl_certs\root-ca.pem'))) {
    Write-Host 'Generando los certificados internos de Wazuh...'
    & docker compose -p "$Project-certs" -f (Join-Path $SingleNode 'generate-indexer-certs.yml') run --rm generator *> (Join-Path $Demo 'certs.log')
    if ($LASTEXITCODE -ne 0) { Fail "No se pudieron generar los certificados. Revisa $Demo\certs.log" }
}

$binary = Join-Path $Demo 'celeris-cache.exe'
if (-not (Test-Path $binary)) {
    Write-Host 'Compilando el proxy. La primera vez tarda unos minutos...'
    # Carpeta propia: la compilación normal falla si tu proxy real está en marcha.
    $target = Join-Path $Demo 'target'
    & cargo build --release --manifest-path (Join-Path $Repo 'Cargo.toml') --target-dir $target
    if ($LASTEXITCODE -ne 0) { Fail 'No se pudo compilar el proxy.' }
    Copy-Item (Join-Path $target 'release\celeris-cache.exe') $binary
}

if (-not (Test-ProxyRunning)) {
    Write-Host "Arrancando el proxy de demostración en $Proxy..."
    Write-DemoConfig
    Start-DemoProxy
    Start-DemoOrigin
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
