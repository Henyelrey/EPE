//! CA local: se genera una sola vez y el usuario la instala en SUS dispositivos.
//! Instalarla es el consentimiento explícito: sin ella, el navegador rechaza la intercepción.

use anyhow::Context;
use hudsucker::{certificate_authority::RcgenAuthority, rustls::crypto::aws_lc_rs};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use std::path::Path;

pub fn load_or_generate(cert_path: &Path, key_path: &Path) -> anyhow::Result<RcgenAuthority> {
    if !cert_path.exists() || !key_path.exists() {
        generate(cert_path, key_path)?;
    }
    let cert_pem = std::fs::read_to_string(cert_path).context("leyendo certificado de la CA")?;
    let key_pem = std::fs::read_to_string(key_path).context("leyendo llave de la CA")?;
    let key = KeyPair::from_pem(&key_pem).context("llave de la CA inválida")?;
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key).context("certificado de la CA inválido")?;
    // 1000 = certificados por dominio cacheados en memoria.
    Ok(RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider()))
}

fn generate(cert_path: &Path, key_path: &Path) -> anyhow::Result<()> {
    if let Some(dir) = cert_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Rayo Cache Local CA");
    dn.push(DnType::OrganizationName, "rayo-cache (solo uso local)");
    params.distinguished_name = dn;
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2028, 12, 31);

    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    std::fs::write(cert_path, cert.pem())?;
    std::fs::write(key_path, key.serialize_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    tracing::warn!(
        "CA nueva generada en {}. Instálala SOLO en dispositivos tuyos. La llave ({}) nunca debe salir de esta máquina.",
        cert_path.display(),
        key_path.display()
    );
    Ok(())
}
