# Copia siem/wazuh/local_rules.xml al manager y reinicia su análisis. El contenedor no se recrea.
. (Join-Path $PSScriptRoot 'comun.ps1')

$rules = '/var/ossec/etc/rules/local_rules.xml'
& docker exec $Manager sh -c "cp /wazuh-config-mount/etc/rules/local_rules.xml $rules && chown wazuh:wazuh $rules && /var/ossec/bin/wazuh-control restart" *> $null
if ($LASTEXITCODE -ne 0) { Fail "No se pudo recargar. Revisa el registro con: docker logs $Manager" }

$errors = & docker exec $Manager sh -c "tail -n 200 /var/ossec/logs/ossec.log | grep -E 'wazuh-analysisd: (ERROR|CRITICAL)'"
if ($errors) {
    $errors
    Fail 'Wazuh rechazó las reglas.'
}
Write-Host 'Reglas recargadas.'
