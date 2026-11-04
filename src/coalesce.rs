//! Coalescencia: si varios clientes piden un objeto que no está, solo uno va al origen.
//!
//! Quien espera lo hace una sola vez y con tiempo límite. Si después sigue sin haber copia (porque no
//! era cacheable o el origen falló), va al origen por su cuenta, para no atender en fila una URL no cacheable.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

type InFlight = Arc<Mutex<HashMap<String, watch::Receiver<()>>>>;

pub struct Flights {
    wait: Duration,
    in_flight: InFlight,
}

pub enum Entry {
    /// Esta petición va al origen. Quienes esperan despiertan al soltar el guardia.
    Leader(FlightGuard),
    /// Otra petición ya fue al origen y esta terminó de esperarla.
    Waited,
    /// La coalescencia está desactivada.
    Disabled,
}

pub struct FlightGuard {
    key: String,
    in_flight: InFlight,
    _done: watch::Sender<()>,
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        self.in_flight.lock().expect("el mapa de peticiones no se envenena").remove(&self.key);
    }
}

impl Flights {
    /// `wait_secs = 0` desactiva la coalescencia.
    pub fn new(wait_secs: u64) -> Self {
        Self { wait: Duration::from_secs(wait_secs), in_flight: Arc::default() }
    }

    pub async fn enter(&self, key: &str) -> Entry {
        if self.wait.is_zero() {
            return Entry::Disabled;
        }
        let mut leader_done = {
            let mut map = self.in_flight.lock().expect("el mapa de peticiones no se envenena");
            match map.get(key) {
                Some(rx) => rx.clone(),
                None => {
                    let (tx, rx) = watch::channel(());
                    map.insert(key.to_owned(), rx);
                    return Entry::Leader(FlightGuard { key: key.to_owned(), in_flight: self.in_flight.clone(), _done: tx });
                }
            }
        };
        // `changed` termina con error cuando el líder suelta el emisor; aquí basta con que haya terminado.
        let _ = tokio::time::timeout(self.wait, leader_done.changed()).await;
        Entry::Waited
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn el_segundo_espera_al_primero() {
        let flights = Arc::new(Flights::new(30));
        let Entry::Leader(guard) = flights.enter("k").await else { panic!("debía ser líder") };

        let waiter = flights.clone();
        let task = tokio::spawn(async move { waiter.enter("k").await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished());

        drop(guard);
        assert!(matches!(task.await.unwrap(), Entry::Waited));
        assert!(matches!(flights.enter("k").await, Entry::Leader(_)), "al terminar, la clave queda libre");
    }

    #[tokio::test]
    async fn claves_distintas_no_se_esperan() {
        let flights = Flights::new(30);
        let _a = flights.enter("a").await;
        assert!(matches!(flights.enter("b").await, Entry::Leader(_)));
    }

    #[tokio::test]
    async fn la_espera_tiene_limite() {
        let flights = Flights::new(1);
        let _leader = flights.enter("k").await;
        let start = Instant::now();
        assert!(matches!(flights.enter("k").await, Entry::Waited));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn se_puede_desactivar() {
        let flights = Flights::new(0);
        assert!(matches!(flights.enter("k").await, Entry::Disabled));
    }
}
