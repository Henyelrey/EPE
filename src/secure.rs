//! Azar criptográfico y archivos que solo debe poder leer el usuario que ejecuta el proxy.

use anyhow::Context;
#[cfg(windows)]
use anyhow::bail;
use hudsucker::rustls::crypto::aws_lc_rs;
use std::path::Path;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    aws_lc_rs::default_provider().secure_random.fill(&mut bytes).expect("el sistema debe proveer azar seguro");
    bytes
}

/// Crea un archivo privado. Se protege estando vacío: su contenido nunca existe con permisos abiertos.
pub fn write_private(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::File::create(path).with_context(|| format!("creando {}", path.display()))?;
    if let Err(e) = restrict_to_owner(path) {
        let _ = std::fs::remove_file(path);
        return Err(e.context(format!("no se pudo restringir el acceso a {}", path.display())));
    }
    std::fs::write(path, contents)?;
    Ok(())
}

#[cfg(unix)]
pub fn restrict_to_owner(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
pub fn restrict_to_owner(path: &Path) -> anyhow::Result<()> {
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

    #[test]
    fn el_azar_no_se_repite() {
        assert_ne!(random_bytes::<32>(), random_bytes::<32>());
    }

    #[test]
    fn crea_el_archivo_con_su_contenido() {
        let dir = std::env::temp_dir().join(format!("rayo-secure-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nuevo").join("secreto");
        write_private(&path, b"valor").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"valor");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
