//! CA local: se genera una sola vez y el usuario la instala en SUS dispositivos.
//! Instalarla es el consentimiento explícito: sin ella, el navegador rechaza la intercepción.
//!
//! La CA solo puede firmar certificados para los dominios que se configuran al generarla. Si su
//! llave se filtra, el daño queda limitado a esos dominios y no a todas las webs de cada dispositivo.

use crate::config::matches_suffix;
use anyhow::{bail, Context};
use hudsucker::{certificate_authority::RcgenAuthority, rustls::crypto::aws_lc_rs};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, GeneralSubtree, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, NameConstraints,
};
use std::path::Path;
use x509_parser::extensions::GeneralName;
use x509_parser::pem::parse_x509_pem;

/// Una restricción vacía equivale a no tener ninguna, así que sin dominios se usa un nombre inexistente.
const NO_DOMAINS_PLACEHOLDER: &str = "rayo.invalid";

pub fn load_or_generate(cert_path: &Path, key_path: &Path, intercept_domains: &[String]) -> anyhow::Result<RcgenAuthority> {
    if !cert_path.exists() || !key_path.exists() {
        generate(cert_path, key_path, intercept_domains)?;
    }
    // También protege llaves generadas por versiones anteriores.
    if let Err(e) = protect_key(key_path) {
        tracing::warn!("no se pudo restringir el acceso a {}: {e:#}", key_path.display());
    }
    let cert_pem = std::fs::read_to_string(cert_path).context("leyendo certificado de la CA")?;
    let key_pem = std::fs::read_to_string(key_path).context("leyendo llave de la CA")?;

    match permitted_domains(&cert_pem)? {
        Some(permitted) => {
            let uncovered = uncovered_domains(intercept_domains, &permitted);
            if !uncovered.is_empty() {
                bail!(
                    "la CA no puede firmar para {uncovered:?} y los navegadores rechazarían esos dominios. \
                     Quítalos de intercept_domains o genera una CA nueva: borra {} y {} y reinstala el certificado en todos los dispositivos.",
                    cert_path.display(),
                    key_path.display()
                );
            }
        }
        None => tracing::warn!(
            "la CA {} puede firmar para cualquier dominio. En una red compartida, borra {} y {} para generar una limitada y reinstálala en los dispositivos.",
            cert_path.display(),
            cert_path.display(),
            key_path.display()
        ),
    }

    let key = KeyPair::from_pem(&key_pem).context("llave de la CA inválida")?;
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key).context("certificado de la CA inválido")?;
    // 1000 = certificados por dominio cacheados en memoria.
    Ok(RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider()))
}

fn generate(cert_path: &Path, key_path: &Path, intercept_domains: &[String]) -> anyhow::Result<()> {
    if let Some(dir) = cert_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    if let Some(dir) = key_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut params = CertificateParams::default();
    // Longitud de ruta 0: esta CA firma certificados finales, pero no otras CAs.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: name_constraints_for(intercept_domains),
        excluded_subtrees: vec![],
    });
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Rayo Cache Local CA");
    dn.push(DnType::OrganizationName, "rayo-cache (solo uso local)");
    params.distinguished_name = dn;
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2028, 12, 31);

    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;

    // El archivo se protege estando vacío: la llave nunca existe en disco con permisos abiertos.
    std::fs::File::create(key_path).context("creando la llave de la CA")?;
    if let Err(e) = protect_key(key_path) {
        let _ = std::fs::remove_file(key_path);
        return Err(e.context("no se pudo restringir el acceso a la llave de la CA"));
    }
    std::fs::write(key_path, key.serialize_pem())?;
    std::fs::write(cert_path, cert.pem())?;

    tracing::warn!(
        "CA nueva generada en {}, limitada a {intercept_domains:?}. Instálala SOLO en dispositivos con el consentimiento de sus dueños. La llave ({}) nunca debe salir de esta máquina.",
        cert_path.display(),
        key_path.display()
    );
    Ok(())
}

fn name_constraints_for(domains: &[String]) -> Vec<GeneralSubtree> {
    let mut names: Vec<String> =
        domains.iter().map(|d| d.trim_start_matches('.').to_ascii_lowercase()).collect();
    if names.is_empty() {
        names.push(NO_DOMAINS_PLACEHOLDER.to_owned());
    }
    names.into_iter().map(GeneralSubtree::DnsName).collect()
}

/// Dominios para los que la CA puede firmar, o `None` si no tiene restricciones.
fn permitted_domains(cert_pem: &str) -> anyhow::Result<Option<Vec<String>>> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).context("certificado de la CA inválido")?;
    let cert = pem.parse_x509().context("certificado de la CA inválido")?;
    let constraints = cert.name_constraints().context("restricciones de la CA inválidas")?;
    Ok(constraints.and_then(|c| c.value.permitted_subtrees.as_ref()).map(|subtrees| {
        subtrees
            .iter()
            .filter_map(|s| match s.base {
                GeneralName::DNSName(name) => Some(name.to_owned()),
                _ => None,
            })
            .collect()
    }))
}

fn uncovered_domains(domains: &[String], permitted: &[String]) -> Vec<String> {
    domains
        .iter()
        .filter(|d| {
            let host = d.trim_start_matches('.').to_ascii_lowercase();
            !permitted.iter().any(|p| matches_suffix(&host, p))
        })
        .cloned()
        .collect()
}

#[cfg(unix)]
fn protect_key(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
fn protect_key(path: &Path) -> anyhow::Result<()> {
    let user = std::env::var("USERNAME").context("no se conoce el usuario actual")?;
    let account = match std::env::var("USERDOMAIN") {
        Ok(domain) => format!("{domain}\\{user}"),
        Err(_) => user,
    };
    // Quita los permisos heredados y deja acceso solo a la cuenta que ejecuta el proxy.
    let output = std::process::Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("{account}:F"))
        .output()
        .context("ejecutando icacls")?;
    if !output.status.success() {
        bail!("icacls terminó con error: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rayo-ca-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn la_ca_queda_limitada_a_los_dominios_configurados() {
        let dir = temp_dir("limitada");
        let (cert, key) = (dir.join("ca.crt"), dir.join("ca.key"));
        generate(&cert, &key, &["cdn.example.com".into(), ".fonts.example.org".into()]).unwrap();

        let pem = std::fs::read_to_string(&cert).unwrap();
        let permitted = permitted_domains(&pem).unwrap().unwrap();
        assert_eq!(permitted, ["cdn.example.com", "fonts.example.org"]);
        assert!(uncovered_domains(&["a.cdn.example.com".into()], &permitted).is_empty());
        assert_eq!(uncovered_domains(&["otro.example.net".into()], &permitted), ["otro.example.net"]);
        assert!(!std::fs::read_to_string(&key).unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sin_dominios_la_ca_sigue_limitada() {
        let dir = temp_dir("vacia");
        let (cert, key) = (dir.join("ca.crt"), dir.join("ca.key"));
        generate(&cert, &key, &[]).unwrap();
        let pem = std::fs::read_to_string(&cert).unwrap();
        assert_eq!(permitted_domains(&pem).unwrap().unwrap(), [NO_DOMAINS_PLACEHOLDER]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
