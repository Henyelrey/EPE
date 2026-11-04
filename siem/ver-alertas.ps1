# Muestra las alertas de rayo-cache que Wazuh tiene guardadas en su índice.
param([int]$Minutos = 30, [int]$Limite = 2000)
. (Join-Path $PSScriptRoot 'comun.ps1')

$alerts = Get-RayoAlerts $Minutos $Limite
Write-Host "$($alerts.Count) alerta(s) de rayo-cache en los últimos $Minutos minutos, agrupadas por regla y origen:"
$alerts | Group-Object { "$($_.rule.id)|$($_.data.srcip)" } | ForEach-Object {
    $times = $_.Group | ForEach-Object { [datetime]$_.timestamp } | Sort-Object
    $alert = $_.Group[0]
    [pscustomobject]@{
        Primera     = $times[0]
        Veces       = $_.Count
        Nivel       = $alert.rule.level
        Regla       = $alert.rule.id
        Origen      = $alert.data.srcip
        MITRE       = ($alert.rule.mitre.id -join ',')
        Descripcion = $alert.rule.description
    }
} | Sort-Object Primera | Format-Table -AutoSize -Wrap @{ Label = 'Hora'; Expression = { $_.Primera.ToString('HH:mm:ss') } }, Veces, Nivel, Regla, Origen, MITRE, Descripcion
