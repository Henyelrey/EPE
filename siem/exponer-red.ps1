# Expone la demostración en la red local para atacarla desde otras máquinas.
#   Panel: Apache en <Ip>:3191, solo para la subred de esa IP.
#   Proxy: <Ip>:3190. Rechaza a todos salvo a las IPs de -Permitir, y anota cada rechazo.
# Wazuh sigue accesible solo desde este PC.
#
#   .\siem\exponer-red.ps1 -Ip 172.20.46.51
#   .\siem\exponer-red.ps1 -Ip 172.20.46.51 -Permitir 172.20.46.80
#   .\siem\exponer-red.ps1 -Ip 172.20.46.51 -PermitirRedesPrivadas
#   .\siem\exponer-red.ps1 -Cerrar
param([string]$Ip, [string[]]$Permitir = @(), [switch]$PermitirRedesPrivadas, [switch]$Cerrar)
. (Join-Path $PSScriptRoot 'comun.ps1')

# Comprueba Wazuh y no el proxy: así se puede repetir el comando si un intento anterior dejó el proxy parado.
$running = & docker inspect -f '{{.State.Running}}' $Manager 2>$null
if ($running -ne 'true') { Fail 'La demostración no está en marcha. Ejecuta antes .\siem\levantar.ps1' }

Stop-DemoProcess 'apache'
Stop-DemoProcess 'firewall'

function Restart-DemoServices {
    Stop-DemoProcess 'proxy'
    Stop-DemoProcess 'origen'
    Start-DemoProxy
    Start-DemoOrigin
}

if ($Cerrar) {
    Write-DemoConfig
    Restart-DemoServices
    Write-Host 'La demostración ya no está expuesta: el proxy y el panel solo escuchan en este PC.' -ForegroundColor Green
    exit 0
}

if (-not $Ip) { Fail 'Indica la IP de este PC, por ejemplo: .\siem\exponer-red.ps1 -Ip 172.20.46.51' }
$address = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Ip -ErrorAction SilentlyContinue
if (-not $address) { Fail "$Ip no es una IP de este PC. Comprueba la actual con: ipconfig" }
foreach ($client in $Permitir) {
    $parsed = $null
    if (-not [ipaddress]::TryParse($client, [ref]$parsed)) { Fail "$client no es una dirección IP." }
}

# El proxy se niega a arrancar con 0.0.0.0/0 porque sería un proxy abierto: esto es lo más amplio que acepta sin serlo.
$privateNetworks = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
$panelClients = if ($PermitirRedesPrivadas) { $privateNetworks -join ' ' } else { "$Ip/$($address.PrefixLength)" }
$proxyClients = @($Ip) + $Permitir
if ($PermitirRedesPrivadas) { $proxyClients += $privateNetworks }

$httpd = @(
    (Get-Command httpd -ErrorAction SilentlyContinue).Source
    Get-ChildItem 'C:\laragon\bin\apache\*\bin\httpd.exe', 'C:\xampp\apache\bin\httpd.exe', 'C:\Apache24\bin\httpd.exe' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
) | Where-Object { $_ } | Select-Object -First 1
if (-not $httpd) { Fail 'No se encontró Apache. Instálalo o añade httpd.exe al PATH.' }

function Slash($path) { $path -replace '\\', '/' }

$apacheDir = Join-Path $Demo 'apache'
New-Item -ItemType Directory -Force $apacheDir | Out-Null
$conf = Join-Path $apacheDir 'httpd.conf'
$text = [IO.File]::ReadAllText((Join-Path $Siem 'apache\celeris-demo.conf'))
$text = $text.Replace('@SERVER_ROOT@', (Slash (Split-Path (Split-Path $httpd -Parent) -Parent)))
$text = $text.Replace('@DEMO@', (Slash $Demo)).Replace('@IP@', $Ip).Replace('@SUBNET@', $panelClients)
[IO.File]::WriteAllText($conf, $text, (New-Object Text.UTF8Encoding $false))

& $httpd -t -f $conf *> (Join-Path $apacheDir 'prueba.log')
if ($LASTEXITCODE -ne 0) { Fail "La configuración de Apache no es válida. Revisa $apacheDir\prueba.log" }

# El proxy se niega a escuchar en la red si solo permite 127.0.0.1: se añade la IP de este PC, no la subred.
Write-DemoConfig -Listen '0.0.0.0:3190' -ExtraClients $proxyClients
Restart-DemoServices

$process = Start-Process $httpd -ArgumentList '-f', "`"$conf`"" -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $apacheDir 'apache.out') -RedirectStandardError (Join-Path $apacheDir 'apache.err')
Set-Content (Join-Path $Demo 'apache.pid') $process.Id
Start-Sleep 2
if ($process.HasExited) { Fail "Apache no arrancó. Revisa $apacheDir\apache.err y $Demo\logs\apache-error.log" }

Write-Host 'Haciendo que Wazuh lea los registros de Apache y del firewall...'
Write-OssecConf
Start-DemoFirewallReader $Ip
& (Join-Path $Siem 'recargar-reglas.ps1')

Write-Host ''
Write-Host "Panel de la demo:  http://${Ip}:3191/" -ForegroundColor Green
Write-Host "Proxy de la demo:  http://${Ip}:3190" -ForegroundColor Green
if ($PermitirRedesPrivadas) {
    Write-Host 'El proxy y el panel aceptan cualquier IP privada. Una IP pública recibe 403 y queda anotada.' -ForegroundColor Yellow
    Write-Host "El firewall de Windows puede seguir limitándolo a tu subred: revisa el valor RemoteAddress de la regla 'celeris-cache demo'."
} elseif ($Permitir.Count -gt 0) {
    Write-Host "El proxy acepta a: $($Permitir -join ', '). Cualquier otra IP recibe 403 y queda anotada."
} else {
    Write-Host 'El proxy no acepta a ninguna otra máquina: recibirán 403 y quedarán anotadas.'
}
Write-Host 'El panel viaja sin cifrar: usa solo el token de esta demo, nunca el de tu proxy real.'

if (-not (Get-NetFirewallRule -DisplayName 'celeris-cache demo' -ErrorAction SilentlyContinue)) {
    Write-Host ''
    Write-Host 'El firewall de Windows aún bloquea el puerto 3190 desde otras máquinas. Para abrirlo, ejecuta esto en un PowerShell de administrador:' -ForegroundColor Yellow
    Write-Host "New-NetFirewallRule -DisplayName 'celeris-cache demo' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3190 -RemoteAddress LocalSubnet -Program '$(Join-Path $Demo 'celeris-cache.exe')'"
}
if (-not (Test-Path $FirewallLog)) {
    Write-Host ''
    Write-Host 'Wazuh no detectará Nmap, DoS, DDoS ni ping de la muerte hasta que actives el registro del firewall. Ejecuta esto en un PowerShell de administrador:' -ForegroundColor Yellow
    Write-Host "powershell -ExecutionPolicy Bypass -File `"$(Join-Path $Siem 'activar-registro-firewall.ps1')`""
}
Write-Host ''
Write-Host 'Para dejar de exponerla: .\siem\exponer-red.ps1 -Cerrar'
