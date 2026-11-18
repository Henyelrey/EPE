# Copia las reglas y la configuración al manager y lo reinicia. El contenedor no se recrea.
. (Join-Path $PSScriptRoot 'comun.ps1')

$rules = '/var/ossec/etc/rules/local_rules.xml'
& docker exec $Manager sh -c "cp /wazuh-config-mount/etc/rules/local_rules.xml $rules && chown wazuh:wazuh $rules && cp /wazuh-config-mount/etc/ossec.conf /var/ossec/etc/ossec.conf && chown root:wazuh /var/ossec/etc/ossec.conf && /var/ossec/bin/wazuh-control restart" *> $null
if ($LASTEXITCODE -ne 0) { Fail "No se pudo recargar. Revisa el registro con: docker logs $Manager" }

$errors = & docker exec $Manager sh -c "tail -n 200 /var/ossec/logs/ossec.log | grep -E 'wazuh-analysisd: (ERROR|CRITICAL)'"
if ($errors) {
    $errors
    Fail 'Wazuh rechazó las reglas.'
}
Write-Host 'Reglas recargadas.'
