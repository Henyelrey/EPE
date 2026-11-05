# Simula ataques contra la instancia de demostración. Nada sale de este PC:
# las direcciones 127.0.0.x hacen de otros equipos y los destinos internos los bloquea el propio proxy.
. (Join-Path $PSScriptRoot 'comun.ps1')

if (-not (Test-ProxyRunning)) { Fail 'El proxy de demostración no está en marcha. Ejecuta antes .\siem\levantar.ps1' }

function Attack($title, $mitre, $from) {
    Write-Host ''
    Write-Host "== $title" -ForegroundColor Cyan
    Write-Host "   Origen simulado: $from   MITRE ATT&CK: $mitre"
}

function Result($text) { Write-Host "   $text" }

function Status {
    & curl.exe -s -o NUL -w '%{http_code}' --max-time 5 @args
}

$exitCode = 0
$data = Join-Path $Demo 'data\objects'
$config = Join-Path $Demo 'config.toml'
$caKey = Join-Path $Demo 'ca\rayo-ca.key'

Write-Host 'Guardando un archivo en la caché: servirá para el ataque de alteración.'
$first = Status -x $Proxy "$Origin/static.js"
$second = Status -x $Proxy "$Origin/static.js"
Result "Respuestas: $first y $second"

Attack '1. Un equipo no autorizado intenta usar el proxy' 'T1133' '127.0.0.66'
1..7 | ForEach-Object { $code = Status --interface 127.0.0.66 -x $Proxy "$Origin/static.js" }
Result "7 intentos. El proxy responde $code."

Attack '2. Fuerza bruta contra el token de administración' 'T1110.001' '127.0.0.67'
1..12 | ForEach-Object { $code = Status --noproxy '*' --interface 127.0.0.67 -H "Authorization: Bearer intento-$_" "$AdminUrl/api/summary" }
Result "12 tokens probados. El panel responde $code."

Attack '3. Escaneo de puertos a través del proxy' 'T1046' '127.0.0.51'
foreach ($port in 22, 25, 445, 1433, 3306, 3389) {
    $code = & curl.exe -s -o NUL -w '%{http_connect}' --max-time 5 --interface 127.0.0.51 -x $Proxy -p "http://example.invalid:$port/"
    Result "Puerto $port -> $code"
}

Attack '4. SSRF: usar el proxy para llegar a la red interna' 'T1090, T1552.005' '127.0.0.52'
foreach ($target in 'http://169.254.169.254/latest/meta-data/', 'http://192.168.1.1/', 'http://10.0.0.1/admin') {
    $code = Status --interface 127.0.0.52 -x $Proxy $target
    Result "$target -> $code"
}

Attack '5. Inundación de peticiones' 'T1499' '127.0.0.50'
$codes = & curl.exe -s --interface 127.0.0.50 -x $Proxy -o NUL -w '%{http_code}\n' "$Origin/static.js#[1-200]"
$summary = ($codes | Group-Object | ForEach-Object { "$($_.Count) con $($_.Name)" }) -join ', '
Result "200 peticiones: $summary."

Attack '6. Suplantar el nombre del servidor' 'T1090.004' '127.0.0.53'
$code = Status --interface 127.0.0.53 -x $Proxy -H 'Host: banco.invalid' "$Origin/static.js"
Result "El proxy responde $code y anota que el nombre no coincide."

Write-Host ''
Write-Host 'Esperando 40 s para que Wazuh registre el estado original de los archivos...'
Start-Sleep 40

Attack '7. Alterar archivos críticos en disco' 'T1565.001, T1552.004, T1562.001' 'este equipo'
$object = Get-ChildItem $data -Recurse -File | Where-Object { $_.Extension -ne '.tmp' } | Sort-Object Length -Descending | Select-Object -First 1
if (-not $object) { Fail 'No hay objetos en la caché: el proxy no guardó el archivo de prueba.' }
$originalConfig = [IO.File]::ReadAllBytes($config)
$originalKey = [IO.File]::ReadAllBytes($caKey)
[IO.File]::WriteAllText($object.FullName, "<script>alert('contenido envenenado')</script>")
Result 'Objeto de la caché sustituido por contenido malicioso.'
Add-Content $config '# Línea añadida por la simulación'
Add-Content $caKey '# Línea añadida por la simulación'
Result 'Configuración y clave de la CA de demostración modificadas.'

Write-Host '   Esperando 40 s a la siguiente revisión de integridad de Wazuh...'
Start-Sleep 40

$body = & curl.exe -s -x $Proxy "$Origin/static.js"
if (($body -join "`n") -match 'contenido envenenado') {
    Result 'PROBLEMA: el proxy sirvió el contenido alterado.'
} else {
    Result 'El proxy detectó la alteración: descartó la copia y volvió a pedir el original.'
}

[IO.File]::WriteAllBytes($config, $originalConfig)
[IO.File]::WriteAllBytes($caKey, $originalKey)
Result 'Configuración y clave de demostración restauradas.'

$expected = 100110, 100111, 100120, 100121, 100130, 100131, 100140, 100141, 100150, 100151, 100152, 100160, 100171, 100180, 100182, 100183
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
Write-Host "Míralas en el panel: $PanelUrl (Threat Hunting > Events, filtro rule.groups:rayo)"
exit $exitCode
