# Hace que el firewall de Windows anote las conexiones de la demo, para que Wazuh detecte ataques de red.
# Cambia una configuración de Windows: ejecútalo tú, en un PowerShell de administrador.
#
#   .\siem\activar-registro-firewall.ps1
#   .\siem\activar-registro-firewall.ps1 -Desactivar
param([switch]$Desactivar)
. (Join-Path $PSScriptRoot 'comun.ps1')

$identity = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'Ejecuta este script en un PowerShell de administrador.'
}

function Netsh-Logging($setting, $value) {
    & netsh advfirewall set allprofiles logging $setting $value | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "Windows rechazó el ajuste $setting." }
}

if ($Desactivar) {
    Netsh-Logging filename '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
    Netsh-Logging allowedconnections disable
    Netsh-Logging droppedconnections disable
    Write-Host 'Registro del firewall desactivado.' -ForegroundColor Green
    exit 0
}

$folder = Split-Path $FirewallLog -Parent
New-Item -ItemType Directory -Force $folder | Out-Null
# El servicio del firewall solo escribe en carpetas donde tiene permiso expreso.
& icacls $folder /grant 'NT SERVICE\mpssvc:(OI)(CI)M' | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "No se pudo dar permiso al firewall sobre $folder." }

Netsh-Logging filename $FirewallLog
Netsh-Logging maxfilesize 32767
Netsh-Logging allowedconnections enable
Netsh-Logging droppedconnections enable

Write-Host "El firewall ya anota las conexiones en $FirewallLog" -ForegroundColor Green
Write-Host 'Si la demo ya estaba expuesta, ejecuta otra vez .\siem\exponer-red.ps1 con tu IP.'
