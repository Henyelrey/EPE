//! Aviso de transparencia para los usuarios, servido en http://rayo.aviso/.
//!
//! Se genera al arrancar desde la configuración y el certificado reales, para que no pueda quedar
//! desactualizado. Lo que dice sobre qué se registra debe cambiar junto con el código: si se agrega un
//! registro nuevo, hay que actualizar la sección "Qué se guarda" y también docs/AVISO.md.

use crate::ca::CaSummary;
use crate::config::{ClientIpMode, Config};

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

fn domain_list(domains: &[String]) -> String {
    if domains.is_empty() {
        return "<p>Ninguno.</p>".to_owned();
    }
    let items: String = domains.iter().map(|d| format!("<li><code>{}</code></li>", escape(d))).collect();
    format!("<ul>{items}</ul>")
}

/// `detailed_logs` indica si el registro detallado, que puede incluir IPs de clientes, está activo.
pub fn render(cfg: &Config, ca: &CaSummary, detailed_logs: bool) -> String {
    let contact = match cfg.operator_contact.trim() {
        "" => "<strong>No se indicó.</strong> Pregunta a quien te dio acceso a este proxy.".to_owned(),
        contact => escape(contact),
    };
    let intercepted = domain_list(&cfg.intercept_domains);
    let protected = domain_list(&cfg.never_intercept);
    let plain_http = if cfg.cache_plain_http {
        "Los sitios <code>http://</code> no usan cifrado, así que el proxy los ve siempre y puede guardar copias de ellos, \
         salvo los dominios protegidos de la lista anterior."
    } else {
        "Los sitios <code>http://</code> no usan cifrado, así que el proxy los ve siempre, pero no guarda copias de ellos."
    };
    let detailed = if detailed_logs {
        "<strong>Registro detallado: activado.</strong> Ahora mismo el registro puede incluir también la IP de los dispositivos \
         y los dominios a los que se conectan."
    } else {
        "Registro detallado: desactivado. Quien administra el proxy puede activarlo; entonces el registro podría incluir la IP de los \
         dispositivos y los dominios a los que se conectan, y este aviso lo indicaría."
    };
    let access_log = if cfg.access_log_enabled {
        let identity = match cfg.access_log_client_ip {
            ClientIpMode::Pseudonym => {
                "Tu IP no se guarda: se anota un identificador calculado a partir de ella, que cambia cada día. Aun así, durante ese día permite \
                 ver qué dominios visitó un mismo dispositivo, y en una red pequeña podría deducirse de quién es."
            }
            ClientIpMode::None => "No se anota nada que distinga a tu dispositivo de los demás.",
        };
        format!(
            "<li><strong>Registro de acceso: activado.</strong> Por cada petición y cada conexión cifrada se anota la fecha y hora, el método, el dominio, \
             el resultado, el tamaño y la duración. En las conexiones cifradas, también el puerto. La ruta solo se anota para contenido servido desde una copia o guardado. \
             Nunca incluye parámetros de la dirección, cookies, credenciales ni contenido. {identity} Se borra a los {} días.</li>",
            cfg.access_log_retention_days
        )
    } else {
        "<li>Registro de acceso: desactivado. Quien administra el proxy puede activarlo; entonces anotaría los dominios visitados por cada dispositivo, y este aviso lo indicaría.</li>".to_owned()
    };
    let rate_limit = if cfg.rate_limit_per_minute > 0 {
        format!(
            "<li>Se aceptan hasta {} peticiones por minuto de cada dispositivo. Para aplicar ese límite, tu IP se cuenta en memoria durante el minuto en curso; no se guarda en disco.</li>",
            cfg.rate_limit_per_minute
        )
    } else {
        String::new()
    };
    let scope = match &ca.permitted {
        Some(domains) => format!(
            "<p>Este certificado solo sirve para descifrar estos dominios y sus subdominios. Para cualquier otro sitio, tu dispositivo lo rechazaría.</p>{}",
            domain_list(domains)
        ),
        None => "<p><strong>Este certificado no tiene límites:</strong> podría usarse para suplantar cualquier sitio en los dispositivos que lo instalaron. \
                 Pide a quien administra el proxy que lo reemplace por uno limitado.</p>"
            .to_owned(),
    };
    let fingerprint = escape(&ca.fingerprint);

    format!(
        r#"<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aviso del proxy</title>
<style>
:root {{ color-scheme: light dark; --text: #1f2328; --muted: #57606a; --bg: #ffffff; --panel: #f6f8fa; --line: #d0d7de; --accent: #9a6700; }}
@media (prefers-color-scheme: dark) {{ :root {{ --text: #e6edf3; --muted: #9da7b3; --bg: #0d1117; --panel: #161b22; --line: #30363d; --accent: #d29922; }} }}
body {{ margin: 0 auto; max-width: 44rem; padding: 2rem 1rem 4rem; background: var(--bg); color: var(--text); font: 1rem/1.6 system-ui, sans-serif; }}
h1 {{ font-size: 1.75rem; line-height: 1.25; margin: 0 0 .75rem; }}
h2 {{ font-size: 1.15rem; margin: 2.25rem 0 .5rem; }}
code {{ font-family: ui-monospace, Consolas, monospace; font-size: .9em; overflow-wrap: anywhere; }}
.warning {{ border-left: 4px solid var(--accent); background: var(--panel); padding: .75rem 1rem; margin: 1rem 0; }}
.fingerprint {{ display: block; background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: .75rem; }}
footer {{ margin-top: 3rem; color: var(--muted); font-size: .875rem; }}
</style>
</head>
<body>
<h1>Qué hace este proxy con tu tráfico</h1>
<p>Este proxy guarda copias de contenido público para que cargue más rápido. Para hacerlo, descifra el tráfico de algunos dominios en los dispositivos que instalaron su certificado.</p>
<p><strong>Responsable:</strong> {contact}</p>

<h2>Qué se descifra</h2>
{intercepted}
<p class="warning"><strong>En estos dominios, el proxy puede ver todo lo que envías y recibes, incluidas contraseñas y formularios,</strong> aunque solo guarde contenido público. No inicies sesión en ellos si eso no te parece aceptable.</p>
<p>Si tu dispositivo no tiene instalado el certificado, estos sitios mostrarán un error de seguridad y no se descifrará nada.</p>

<h2>Qué pasa sin descifrar</h2>
<p>Todo lo demás pasa cifrado. El proxy solo ve tu IP, el dominio y el puerto, no el contenido. Estos dominios están protegidos de forma expresa: nunca se descifran ni se guardan.</p>
{protected}
<p>{plain_http}</p>

<h2>Qué se guarda</h2>
<ul>
<li><strong>Copias de contenido:</strong> la respuesta y su dirección, sin parámetros de seguimiento, en el disco del proxy. No indican quién las pidió. Por ahora no se borran solas: permanecen hasta que quien administra el proxy las elimine.</li>
<li><strong>Nunca se guardan:</strong> cookies, credenciales, formularios enviados ni respuestas a peticiones que lleven cookies o credenciales.</li>
<li><strong>Registro del proxy:</strong> la dirección de cada contenido servido desde la copia o guardado por primera vez, sin sus parámetros, y el destino de las conexiones que fallan, sin tu IP. El proxy no lo conserva por sí mismo en un archivo; si quien lo administra lo guarda, su conservación depende de esa persona.</li>
{access_log}
<li><strong>Contadores:</strong> totales generales, tiempos de respuesta y uso de disco, sin datos por persona.</li>
</ul>
<p>{detailed}</p>
<p>Quien administra este equipo puede acceder a todo lo anterior.</p>

<h2>Límites de seguridad</h2>
<ul>
{rate_limit}<li>A través del proxy no se puede llegar a este equipo ni a la red local, salvo las redes que quien lo administra haya permitido.</li>
</ul>

<h2>Comprueba tu certificado</h2>
{scope}
<p>Su huella SHA-256 debe coincidir con la del certificado que instalaste:</p>
<code class="fingerprint">{fingerprint}</code>

<h2>Cómo dejar de usarlo</h2>
<p>Quita el proxy de la configuración de tu navegador o sistema y elimina el certificado <strong>Rayo Cache Local CA</strong> de tu dispositivo. Si solo quitas el proxy, el certificado seguirá instalado.</p>

<footer>Este aviso se genera al arrancar el proxy a partir de su configuración y su certificado reales.</footer>
</body>
</html>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca(permitted: Option<Vec<String>>) -> CaSummary {
        CaSummary { permitted, fingerprint: "AB:CD".into() }
    }

    fn cfg() -> Config {
        Config {
            intercept_domains: vec!["cdn.example.com".into()],
            never_intercept: vec!["banco.example.com".into()],
            operator_contact: "redes@example.com".into(),
            ..Config::default()
        }
    }

    #[test]
    fn muestra_la_configuracion_real() {
        let page = render(&cfg(), &ca(Some(vec!["cdn.example.com".into()])), false);
        assert!(page.contains("<li><code>cdn.example.com</code></li>"));
        assert!(page.contains("<li><code>banco.example.com</code></li>"));
        assert!(page.contains("redes@example.com"));
        assert!(page.contains("AB:CD"));
        assert!(page.contains("6000 peticiones por minuto"));
        assert!(page.contains("Registro detallado: desactivado"));
        assert!(page.contains("incluidas contraseñas"));
    }

    #[test]
    fn avisa_de_lo_que_es_menos_seguro() {
        let page = render(&cfg(), &ca(None), true);
        assert!(page.contains("Este certificado no tiene límites"));
        assert!(page.contains("Registro detallado: activado"));

        let without_contact = Config { operator_contact: "  ".into(), ..cfg() };
        assert!(render(&without_contact, &ca(None), false).contains("No se indicó"));
    }

    #[test]
    fn indica_si_el_log_de_acceso_esta_activo() {
        let page = render(&cfg(), &ca(None), false);
        assert!(page.contains("Registro de acceso: desactivado"));

        let logged = Config { access_log_enabled: true, access_log_retention_days: 3, ..cfg() };
        let page = render(&logged, &ca(None), false);
        assert!(page.contains("Registro de acceso: activado"));
        assert!(page.contains("Se borra a los 3 días"));
        assert!(page.contains("qué dominios visitó un mismo dispositivo"));

        let anonymous = Config { access_log_client_ip: ClientIpMode::None, ..logged };
        let page = render(&anonymous, &ca(None), false);
        assert!(page.contains("No se anota nada que distinga a tu dispositivo"));
        assert!(!page.contains("qué dominios visitó un mismo dispositivo"));
    }

    #[test]
    fn escapa_lo_que_viene_de_la_configuracion() {
        let hostile = Config {
            operator_contact: "<script>alert('x')</script>".into(),
            intercept_domains: vec!["a<b>.example.com".into()],
            ..cfg()
        };
        let page = render(&hostile, &ca(None), false);
        assert!(!page.contains("<script>"));
        assert!(!page.contains("<b>"));
        assert!(page.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"));
    }

    #[test]
    fn sin_limite_ni_dominios_no_inventa_datos() {
        let empty = Config { intercept_domains: vec![], rate_limit_per_minute: 0, ..cfg() };
        let page = render(&empty, &ca(Some(vec![])), false);
        assert!(page.contains("<p>Ninguno.</p>"));
        assert!(!page.contains("peticiones por minuto"));
    }
}
