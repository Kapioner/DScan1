//! Pula workerów (zadanie S4): podgrupy są skanowane równolegle, ale nigdy więcej niż
//! `parallel` naraz (tokio `Semaphore`). Wyniki trafiają kanałem do jednego odbiorcy,
//! który zapisuje je w bazie i raportuje postęp.

use std::future::Future;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use tokio::sync::{Semaphore, mpsc, watch};

use crate::ScannerError;
use crate::nmap::{NmapCommand, NmapOptions, ScanOutput, run_scan};

/// Skanowanie jednej podgrupy. Pula zależy od tego traitu, więc w testach można
/// podstawić atrapę zamiast prawdziwego nmap.
pub trait SubgroupScanner: Send + Sync + 'static {
    fn scan(
        &self,
        targets: &[IpNet],
    ) -> impl Future<Output = Result<ScanOutput, ScannerError>> + Send;
}

/// Skaner podgrup oparty na nmap.
#[derive(Debug, Clone)]
pub struct NmapScanner {
    pub command: NmapCommand,
    pub options: NmapOptions,
}

impl SubgroupScanner for NmapScanner {
    async fn scan(&self, targets: &[IpNet]) -> Result<ScanOutput, ScannerError> {
        run_scan(&self.command, &self.options, targets).await
    }
}

/// Wynik jednej podgrupy z czasem trwania.
#[derive(Debug)]
pub struct SubgroupResult {
    pub index: usize,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub outcome: Result<ScanOutput, ScannerError>,
}

/// Zdarzenia z puli w kolejności, w jakiej zachodzą.
#[derive(Debug)]
pub enum PoolEvent {
    Started {
        index: usize,
        at: DateTime<Utc>,
    },
    Finished(SubgroupResult),
    /// Podgrupa przerwana sygnałem zatrzymania (S9) — proces nmap zabity, do ponowienia.
    Interrupted {
        index: usize,
    },
}

/// Sygnał zatrzymania, który nigdy nie nastąpi (dla skanów bez okna czasowego).
pub fn never_stop() -> watch::Receiver<bool> {
    let (_sender, receiver) = watch::channel(false);
    receiver
}

/// Czeka na sygnał zatrzymania. Zamknięty kanał oznacza „nigdy”.
pub async fn wait_for_stop(stop: &mut watch::Receiver<bool>) {
    loop {
        if *stop.borrow() {
            return;
        }
        if stop.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Uruchamia skan podgrup i od razu zwraca odbiornik zdarzeń. Kanał zamyka się,
/// gdy wszystkie podgrupy się zakończą.
pub fn run_pool<S: SubgroupScanner>(
    scanner: Arc<S>,
    subgroups: Vec<Vec<IpNet>>,
    parallel: usize,
    stop: watch::Receiver<bool>,
) -> mpsc::Receiver<PoolEvent> {
    let parallel = parallel.max(1);
    let (sender, receiver) = mpsc::channel(parallel * 2);
    let semaphore = Arc::new(Semaphore::new(parallel));

    tokio::spawn(async move {
        let mut dispatcher_stop = stop.clone();
        for (index, targets) in subgroups.into_iter().enumerate() {
            // Czekamy na wolne miejsce albo na sygnał zatrzymania (wtedy nie startujemy już nic).
            // `biased`: gdy oba są gotowe, zatrzymanie wygrywa z wolnym miejscem.
            let permit = tokio::select! {
                biased;
                () = wait_for_stop(&mut dispatcher_stop) => break,
                permit = Arc::clone(&semaphore).acquire_owned() => permit,
            };
            let Ok(permit) = permit else { break };
            if *dispatcher_stop.borrow() {
                break;
            }
            let (scanner, sender, mut task_stop) =
                (Arc::clone(&scanner), sender.clone(), stop.clone());
            tokio::spawn(async move {
                let started_at = Utc::now();
                if sender
                    .send(PoolEvent::Started {
                        index,
                        at: started_at,
                    })
                    .await
                    .is_err()
                {
                    return; // odbiorca już nie słucha
                }
                // Zatrzymanie porzuca skan — proces nmap ginie razem z nim (kill_on_drop).
                let event = tokio::select! {
                    outcome = scanner.scan(&targets) => {
                        PoolEvent::Finished(SubgroupResult { index, started_at, finished_at: Utc::now(), outcome })
                    }
                    () = wait_for_stop(&mut task_stop) => PoolEvent::Interrupted { index },
                };
                let _ = sender.send(event).await;
                drop(permit);
            });
        }
    });
    receiver
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use super::*;

    /// Atrapa: „skanuje” 50 ms, zapamiętuje największą liczbę równoczesnych skanów,
    /// a podgrupę zawierającą 10.0.0.66 kończy błędem.
    #[derive(Default)]
    struct FakeScanner {
        running: AtomicUsize,
        max_running: AtomicUsize,
    }

    impl SubgroupScanner for FakeScanner {
        async fn scan(&self, targets: &[IpNet]) -> Result<ScanOutput, ScannerError> {
            let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_running.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            self.running.fetch_sub(1, Ordering::SeqCst);

            if targets.iter().any(|net| net.to_string() == "10.0.0.66/32") {
                return Err(ScannerError::NmapNotFound);
            }
            Ok(ScanOutput {
                hosts: Vec::new(),
                raw_xml: format!("<nmaprun>{}</nmaprun>", targets[0]),
            })
        }
    }

    fn subgroups(count: usize) -> Vec<Vec<IpNet>> {
        (0..count)
            .map(|i| vec![format!("10.0.0.{i}/32").parse().unwrap()])
            .collect()
    }

    async fn collect(mut receiver: mpsc::Receiver<PoolEvent>) -> (usize, Vec<SubgroupResult>) {
        let (mut started, mut finished) = (0, Vec::new());
        while let Some(event) = receiver.recv().await {
            match event {
                PoolEvent::Started { .. } => started += 1,
                PoolEvent::Finished(result) => finished.push(result),
                PoolEvent::Interrupted { .. } => {}
            }
        }
        (started, finished)
    }

    #[tokio::test]
    async fn never_runs_more_than_parallel_scans() {
        let scanner = Arc::new(FakeScanner::default());
        let (started, finished) = collect(run_pool(
            Arc::clone(&scanner),
            subgroups(12),
            3,
            never_stop(),
        ))
        .await;

        assert_eq!(started, 12);
        assert_eq!(finished.len(), 12);
        assert_eq!(scanner.max_running.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn parallel_scans_are_faster_than_sequential() {
        let begin = Instant::now();
        collect(run_pool(
            Arc::new(FakeScanner::default()),
            subgroups(8),
            8,
            never_stop(),
        ))
        .await;
        // 8 × 50 ms szeregowo = 400 ms; równolegle ok. 50 ms.
        assert!(begin.elapsed() < Duration::from_millis(300));
    }

    #[tokio::test]
    async fn failure_of_one_subgroup_does_not_stop_others() {
        let (_, finished) = collect(run_pool(
            Arc::new(FakeScanner::default()),
            subgroups(70),
            8,
            never_stop(),
        ))
        .await;

        let failed: Vec<usize> = finished
            .iter()
            .filter(|r| r.outcome.is_err())
            .map(|r| r.index)
            .collect();
        assert_eq!(failed, vec![66]);
        assert_eq!(finished.len(), 70);
    }

    struct SlowScanner;

    impl SubgroupScanner for SlowScanner {
        async fn scan(&self, _targets: &[IpNet]) -> Result<ScanOutput, ScannerError> {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Err(ScannerError::NmapNotFound)
        }
    }

    #[tokio::test]
    async fn stop_interrupts_running_and_skips_remaining() {
        let (stop_sender, stop) = watch::channel(false);
        // Skan trwający „wiecznie” — wynik nie zależy od obciążenia maszyny testowej.
        let mut events = run_pool(Arc::new(SlowScanner), subgroups(10), 2, stop);
        // Po starcie dwóch pierwszych podgrup zatrzymujemy pulę.
        let mut started = 0;
        while started < 2 {
            if let Some(PoolEvent::Started { .. }) = events.recv().await {
                started += 1;
            }
        }
        stop_sender.send(true).unwrap();

        let (mut interrupted, mut finished) = (0, 0);
        while let Some(event) = events.recv().await {
            match event {
                PoolEvent::Interrupted { .. } => interrupted += 1,
                PoolEvent::Finished(_) => finished += 1,
                PoolEvent::Started { .. } => started += 1,
            }
        }
        assert_eq!(started, 2, "po zatrzymaniu nie startuje nic nowego");
        assert_eq!(interrupted + finished, 2);
        assert_eq!(interrupted, 2);
    }

    #[tokio::test]
    async fn results_carry_timing() {
        let (_, finished) = collect(run_pool(
            Arc::new(FakeScanner::default()),
            subgroups(1),
            1,
            never_stop(),
        ))
        .await;
        let duration = finished[0].finished_at - finished[0].started_at;
        assert!(duration.num_milliseconds() >= 40);
    }
}
