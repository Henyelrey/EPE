//! Auto-bloqueo: el proxy deja de atender a una IP que el detector marcó como abusiva, durante unos
//! minutos, y la libera al vencer. Es un IPS a nivel del proxy: no corta otros puertos de la máquina,
//! pero el atacante ya no puede usar el proxy, vea su IP real (no depende de iptables ni del Firewall).
//!
//! Lo decide el detector (detect.rs) con sus propios umbrales; aquí solo se guarda quién está bloqueado.
//! Cada acción deja un evento para el SIEM: `ip_bloqueada` al empezar, `ip_desbloqueada` al vencer.
//!
//! Las IPs bloqueadas viven solo en memoria, con su vencimiento, y desaparecen al reiniciar. Se guarda la
//! IP y el motivo, nunca qué sitios. Si cambia lo que se guarda aquí, actualiza notice.rs y docs/AVISO.md.

use crate::security::{SecurityEvent, SecurityLog};
use crate::store::now;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Tope de IPs bloqueadas a la vez, para acotar la memoria.
const MAX_BLOCKED: usize = 4096;

pub struct BanList {
    enabled: bool,
    ttl_secs: u64,
    security: Option<Arc<SecurityLog>>,
    /// IP -> instante de vencimiento (segundos UNIX).
    blocked: Mutex<HashMap<IpAddr, u64>>,
}

impl BanList {
    pub fn new(enabled: bool, ttl_secs: u64, security: Option<Arc<SecurityLog>>) -> Self {
        Self { enabled, ttl_secs: ttl_secs.max(1), security, blocked: Mutex::new(HashMap::new()) }
    }

    /// Bloquea una IP o reinicia su plazo. Registra `ip_bloqueada` solo la primera vez.
    pub fn block(&self, ip: IpAddr, reason: &'static str, detail: &str) {
        self.block_at(ip, reason, detail, now());
    }

    fn block_at(&self, ip: IpAddr, reason: &'static str, detail: &str, at: u64) {
        if !self.enabled {
            return;
        }
        let ip = ip.to_canonical();
        let nuevo = {
            let mut blocked = self.blocked.lock().expect("la lista de bloqueos no se envenena");
            let nuevo = !blocked.contains_key(&ip);
            // Memoria llena: no se añaden nuevas IPs, pero las ya bloqueadas siguen vigentes.
            if nuevo && blocked.len() >= MAX_BLOCKED {
                return;
            }
            blocked.insert(ip, at.saturating_add(self.ttl_secs));
            nuevo
        };
        if nuevo {
            if let Some(security) = &self.security {
                security.record(SecurityEvent {
                    event: "ip_bloqueada",
                    srcip: Some(ip),
                    reason: Some(reason),
                    detail: Some(detail),
                    ..Default::default()
                });
            }
        }
    }

    /// ¿Está bloqueada ahora? No elimina nada: el vencimiento lo hace `expire()`.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        self.is_blocked_at(ip, now())
    }

    fn is_blocked_at(&self, ip: IpAddr, at: u64) -> bool {
        if !self.enabled {
            return false;
        }
        let ip = ip.to_canonical();
        self.blocked
            .lock()
            .expect("la lista de bloqueos no se envenena")
            .get(&ip)
            .is_some_and(|&expira| expira > at)
    }

    /// Libera las IPs cuyo plazo venció y registra `ip_desbloqueada`. Lo llama el mantenimiento periódico.
    pub fn expire(&self) {
        self.expire_at(now());
    }

    fn expire_at(&self, at: u64) {
        if !self.enabled {
            return;
        }
        let vencidas: Vec<IpAddr> = {
            let mut blocked = self.blocked.lock().expect("la lista de bloqueos no se envenena");
            let vencidas: Vec<IpAddr> = blocked.iter().filter(|&(_, &expira)| expira <= at).map(|(&ip, _)| ip).collect();
            for ip in &vencidas {
                blocked.remove(ip);
            }
            vencidas
        };
        if let Some(security) = &self.security {
            for ip in vencidas {
                security.record(SecurityEvent {
                    event: "ip_desbloqueada",
                    srcip: Some(ip),
                    detail: Some("Venció el bloqueo automático."),
                    ..Default::default()
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const T: u64 = 10_000;

    fn lista(enabled: bool) -> BanList {
        BanList::new(enabled, 600, None)
    }

    #[test]
    fn apagada_no_bloquea_nada() {
        let b = lista(false);
        b.block_at(ip("10.0.0.1"), "denied", "x", T);
        assert!(!b.is_blocked_at(ip("10.0.0.1"), T));
    }

    #[test]
    fn bloquea_y_vence_sola() {
        let b = lista(true);
        b.block_at(ip("10.0.0.1"), "denied", "x", T);
        assert!(b.is_blocked_at(ip("10.0.0.1"), T));
        assert!(b.is_blocked_at(ip("10.0.0.1"), T + 599));
        // Al vencer deja de estar bloqueada, aunque expire() aún no haya corrido.
        assert!(!b.is_blocked_at(ip("10.0.0.1"), T + 600));
        b.expire_at(T + 600);
        assert!(!b.is_blocked_at(ip("10.0.0.1"), T + 600));
    }

    #[test]
    fn una_alerta_nueva_reinicia_el_plazo() {
        let b = lista(true);
        b.block_at(ip("10.0.0.1"), "denied", "x", T);
        b.block_at(ip("10.0.0.1"), "denied", "x", T + 300);
        // El vencimiento se recalcula desde la última: sigue bloqueada pasado el plazo original.
        assert!(b.is_blocked_at(ip("10.0.0.1"), T + 601));
        assert!(!b.is_blocked_at(ip("10.0.0.1"), T + 900));
    }

    #[test]
    fn ipv4_en_forma_canonica() {
        let b = lista(true);
        b.block_at(ip("::ffff:10.0.0.1"), "denied", "x", T);
        assert!(b.is_blocked_at(ip("10.0.0.1"), T));
    }

    #[test]
    fn la_memoria_tiene_tope() {
        let b = lista(true);
        for n in 0..(MAX_BLOCKED as u32 + 10) {
            b.block_at(IpAddr::V4(n.into()), "denied", "x", T);
        }
        // Las primeras MAX_BLOCKED caben; las que llegan con la memoria llena se descartan.
        assert!(b.is_blocked_at(IpAddr::V4(0.into()), T));
        assert!(!b.is_blocked_at(IpAddr::V4((MAX_BLOCKED as u32).into()), T));
    }
}
