# Copia al manager siem/wazuh/local_rules.xml y la configuración, con la respuesta activa si el laboratorio
# está en marcha, y reinicia Wazuh. El contenedor no se recrea.
. (Join-Path $PSScriptRoot 'comun.ps1')

$labRunning = (& docker inspect -f '{{.State.Running}}' $Gateway 2>$null) -eq 'true'
Initialize-Wazuh -Lab:$labRunning

$rules = '/var/ossec/etc/rules/local_rules.xml'
# cat y no cp: así ossec.conf conserva su dueño y sus permisos.
$copy = "cp /wazuh-config-mount/etc/rules/local_rules.xml $rules && chown wazuh:wazuh $rules && cat /wazuh-config-mount/etc/ossec.conf > /var/ossec/etc/ossec.conf"
& docker exec $Manager sh -c "$copy && /var/ossec/bin/wazuh-control restart" *> $null
if ($LASTEXITCODE -ne 0) { Fail "No se pudo recargar. Revisa el registro con: docker logs $Manager" }

$errors = & docker exec $Manager sh -c "tail -n 200 /var/ossec/logs/ossec.log | grep -E 'wazuh-analysisd: (ERROR|CRITICAL)|Configuration error'"
if ($errors) {
    $errors
    Fail 'Wazuh rechazó las reglas o la configuración.'
}
Write-Host 'Reglas y configuración recargadas.'
