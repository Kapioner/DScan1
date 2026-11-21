//! Pula workerów (zadanie S4): podgrupy są skanowane równolegle, ale nigdy więcej niż
//! `parallel` naraz (tokio `Semaphore`). Wyniki trafiają kanałem do jednego odbiorcy,
//! który zapisuje je w bazie i raportuje postęp.

use std::future::Future;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use tokio::sync::{Semaphore, mpsc};

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
    Started { index: usize, at: DateTime<Utc> },
    Finished(SubgroupResult),
}

/// Uruchamia skan podgrup i od razu zwraca odbiornik zdarzeń. Kanał zamyka się,
/// gdy wszystkie podgrupy się zakończą.
pub fn run_pool<S: SubgroupScanner>(
    scanner: Arc<S>,
    subgroups: Vec<Vec<IpNet>>,
    parallel: usize,
) -> mpsc::Receiver<PoolEvent> {
    let parallel = parallel.max(1);
    let (sender, receiver) = mpsc::channel(parallel * 2);
    let semaphore = Arc::new(Semaphore::new(parallel));

    tokio::spawn(async move {
        for (index, targets) in subgroups.into_iter().enumerate() {
            // Czekamy na wolne miejsce, zanim wystartuje kolejna podgrupa.
            let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                break;
            };
            let scanner = Arc::clone(&scanner);
            let sender = sender.clone();
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
                let outcome = scanner.scan(&targets).await;
                let result = SubgroupResult {
                    index,
                    started_at,
                    finished_at: Utc::now(),
                    outcome,
                };
                let _ = sender.send(PoolEvent::Finished(result)).await;
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
            }
        }
        (started, finished)
    }

    #[tokio::test]
    async fn never_runs_more_than_parallel_scans() {
        let scanner = Arc::new(FakeScanner::default());
        let (started, finished) = collect(run_pool(Arc::clone(&scanner), subgroups(12), 3)).await;

        assert_eq!(started, 12);
        assert_eq!(finished.len(), 12);
        assert_eq!(scanner.max_running.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn parallel_scans_are_faster_than_sequential() {
        let begin = Instant::now();
        collect(run_pool(Arc::new(FakeScanner::default()), subgroups(8), 8)).await;
        // 8 × 50 ms szeregowo = 400 ms; równolegle ok. 50 ms.
        assert!(begin.elapsed() < Duration::from_millis(300));
    }

    #[tokio::test]
    async fn failure_of_one_subgroup_does_not_stop_others() {
        let (_, finished) =
            collect(run_pool(Arc::new(FakeScanner::default()), subgroups(70), 8)).await;

        let failed: Vec<usize> = finished
            .iter()
            .filter(|r| r.outcome.is_err())
            .map(|r| r.index)
            .collect();
        assert_eq!(failed, vec![66]);
        assert_eq!(finished.len(), 70);
    }

    #[tokio::test]
    async fn results_carry_timing() {
        let (_, finished) =
            collect(run_pool(Arc::new(FakeScanner::default()), subgroups(1), 1)).await;
        let duration = finished[0].finished_at - finished[0].started_at;
        assert!(duration.num_milliseconds() >= 40);
    }
}
