# Levanta Wazuh en Docker y una instancia del proxy solo para la demostración.
# La primera vez descarga varios GB. Al terminar, usa memoria hasta que ejecutes detener.ps1.
. (Join-Path $PSScriptRoot 'comun.ps1')

Initialize-Wazuh

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
# --remove-orphans: si antes se usó el laboratorio, sus contenedores se apagan.
Compose up -d --remove-orphans
if ($LASTEXITCODE -ne 0) { Fail 'Docker no pudo levantar Wazuh.' }

Wait-WazuhPanel

Write-Host ''
Write-Host "Listo. Panel de Wazuh: $PanelUrl" -ForegroundColor Green
Write-Host 'El navegador avisará del certificado autofirmado: es esperado en esta demo.'
Write-Host 'Usuario y contraseña de demo: INDEXER_USERNAME e INDEXER_PASSWORD en siem\wazuh-docker\single-node\docker-compose.yml'
Write-Host 'Siguiente paso: .\siem\simular-ataques.ps1'
