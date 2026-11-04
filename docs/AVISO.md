<!--
PARA QUIEN ADMINISTRA EL PROXY. Borra este bloque antes de repartir la hoja.

1. Completa todo lo que está entre [corchetes].
2. Compara la hoja con http://rayo.aviso/ : los dominios y la huella deben coincidir.
3. Entrégala ANTES de que alguien instale el certificado. Conserva constancia de quién aceptó.
4. Actualízala si cambias los dominios o si empiezas a registrar más datos.

Esta plantilla describe lo que hace el programa; no es asesoría legal. Si el proxy se usa con
personas de una organización, revisa las normas que apliquen, como la Ley 29733 de Protección
de Datos Personales en Perú, o el RGPD si hay personas en la Unión Europea.
-->

# Aviso antes de usar el proxy rayo-cache

**Responsable:** [nombre y forma de contacto]
**Red o grupo:** [por ejemplo, laboratorio 3 del campus]
**Fecha de este aviso:** [fecha]

## Para qué sirve

Este proxy guarda copias de contenido público para que cargue más rápido y se use menos internet. Para hacerlo, **descifra el tráfico de algunos dominios**. Por eso te pedimos instalar un certificado en tu dispositivo.

Usarlo es voluntario: [indica qué pasa si alguien no quiere usarlo, por ejemplo "puedes navegar sin proxy"].

## Lo más importante

**En los dominios de esta lista, el proxy puede ver todo lo que envías y recibes, incluidas contraseñas y formularios,** aunque solo guarde contenido público. No inicies sesión en ellos si eso no te parece aceptable.

Dominios que se descifran:

- [dominio 1]
- [dominio 2]

El certificado no sirve para descifrar otros sitios: tu dispositivo lo rechazaría.

## Qué no se descifra

Todo lo demás pasa cifrado, incluidos los bancos y servicios de inicio de sesión protegidos. De esos sitios, el proxy solo ve tu IP, el dominio y el puerto.

Los sitios `http://` no usan cifrado, así que el proxy los ve siempre, tengas o no el certificado.

## Qué se guarda

| Dato | Incluye quién lo pidió | Cuánto dura |
|---|---|---|
| Copias de contenido y su dirección | No | Hasta que el responsable las borre |
| Registro de contenido servido o guardado, con la dirección completa, y de los destinos de conexiones que fallan | No | [indica si se guarda y por cuánto tiempo] |
| Contadores generales | No | Hasta reiniciar el proxy |
| Tu IP, para aplicar el límite de peticiones | Sí | Solo en memoria, durante el minuto en curso |

**Nunca se guardan** cookies, credenciales, formularios enviados ni respuestas a peticiones que lleven cookies o credenciales.

Si el responsable activa el registro detallado, el registro puede incluir además la IP de los dispositivos y los dominios a los que se conectan. La página del aviso muestra si está activo.

**Quién puede ver estos datos:** [personas o cargos]. Técnicamente, quien administra el equipo puede acceder a todos ellos.

## Cómo comprobarlo

Con el proxy configurado, abre `http://rayo.aviso/`. Esa página se genera a partir de la configuración y el certificado reales, y muestra los dominios, si el registro detallado está activo y la huella del certificado.

La huella SHA-256 debe ser:

`[huella que muestra http://rayo.aviso/]`

Para ver la del archivo que te dieron:

- **Windows (PowerShell):** `(Get-PfxCertificate rayo-ca.crt).GetCertHashString('SHA256')`. Muestra la misma huella, sin los dos puntos.
- **Linux o macOS:** `openssl x509 -in rayo-ca.crt -noout -fingerprint -sha256`

Si no coincide, no instales el certificado y avisa al responsable.

## Cómo dejar de usarlo

Hay que hacer las dos cosas. Si solo quitas el proxy, el certificado sigue instalado.

1. **Quita el proxy** de la configuración de tu navegador o sistema.
2. **Elimina el certificado** llamado **Rayo Cache Local CA**:
   - **Windows (PowerShell como administrador):** `certutil -delstore ROOT "Rayo Cache Local CA"`
   - **CachyOS o Arch:** `sudo trust anchor --remove rayo-ca.crt`
   - **Debian o Ubuntu:** `sudo rm /usr/local/share/ca-certificates/rayo-ca.crt && sudo update-ca-certificates --fresh`
   - **Firefox:** Ajustes → Privacidad y seguridad → Certificados → Ver certificados → Autoridades.
   - **Otros dispositivos:** [instrucciones o contacto del responsable]

## Tu aceptación

Instalar el certificado significa que leíste este aviso y aceptas estas condiciones. Puedes dejar de usar el proxy cuando quieras.

Nombre: ____________________   Dispositivo: ____________________   Fecha: ______________
