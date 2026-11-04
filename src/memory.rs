//! Tope de memoria para objetos en RAM. Nunca hace esperar: si no hay presupuesto, la petición se
//! atiende en streaming, sin caché. Así un cliente lento no puede bloquear a los demás.

use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const UNIT_BYTES: u64 = 1024;

/// Memoria reservada. Se libera al soltarla, así que debe vivir hasta que el cliente reciba el cuerpo.
pub type Reservation = OwnedSemaphorePermit;

pub struct MemoryBudget {
    units: Arc<Semaphore>,
}

fn units_for(bytes: u64) -> u32 {
    bytes.div_ceil(UNIT_BYTES).min(u64::from(u32::MAX)) as u32
}

impl MemoryBudget {
    pub fn new(max_bytes: u64) -> Self {
        Self { units: Arc::new(Semaphore::new(units_for(max_bytes) as usize)) }
    }

    pub fn try_reserve(&self, bytes: u64) -> Option<Reservation> {
        self.units.clone().try_acquire_many_owned(units_for(bytes)).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserva_hasta_el_tope_y_libera_al_soltar() {
        let budget = MemoryBudget::new(10 * UNIT_BYTES);
        let mut first = budget.try_reserve(6 * UNIT_BYTES).unwrap();
        let second = budget.try_reserve(4 * UNIT_BYTES).unwrap();
        assert!(budget.try_reserve(1).is_none());

        first.merge(second);
        assert!(budget.try_reserve(1).is_none());
        drop(first);
        assert!(budget.try_reserve(10 * UNIT_BYTES).is_some());
    }

    #[test]
    fn un_objeto_mayor_que_el_tope_no_cabe() {
        let budget = MemoryBudget::new(UNIT_BYTES);
        assert!(budget.try_reserve(UNIT_BYTES + 1).is_none());
        assert!(budget.try_reserve(0).is_some());
    }
}
