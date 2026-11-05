# Detiene la demostración y libera la memoria. Conserva las alertas salvo que uses -Borrar.
param([switch]$Borrar)
. (Join-Path $PSScriptRoot 'comun.ps1')

Stop-DemoProcess 'proxy'
Stop-DemoProcess 'origen'

if ($Borrar) {
    ComposeLab down -v
    if ($LASTEXITCODE -ne 0) { Fail 'Docker no pudo borrar los contenedores de la demo.' }
    foreach ($item in 'data', 'logs', 'ca', 'config.toml', 'ossec.conf') {
        $path = Join-Path $Demo $item
        if (Test-Path $path) { Remove-Item $path -Recurse -Force }
    }
    Write-Host 'Demostración detenida. Se borraron sus alertas, su caché y su CA.'
} else {
    ComposeLab down
    if ($LASTEXITCODE -ne 0) { Fail 'Docker no pudo detener Wazuh.' }
    Write-Host 'Demostración detenida. Las alertas se conservan para la próxima vez.'
}
