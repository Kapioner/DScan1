use std::net::SocketAddr;

use figment::Figment;
use figment::providers::Serialized;

/// Wartości podane flagami wiersza poleceń — najwyższa warstwa konfiguracji.
/// `None` oznacza „flaga nie została podana”, więc obowiązuje niższa warstwa.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliOverrides {
    pub listen: Option<SocketAddr>,
    pub nmap_max_rate: Option<u32>,
    pub max_parallel_nmap: Option<u32>,
}

impl CliOverrides {
    /// Nakłada podane flagi na konfigurację z niższych warstw.
    pub(crate) fn apply(&self, mut figment: Figment) -> Figment {
        if let Some(listen) = self.listen {
            figment = figment.merge(Serialized::default("server.listen", listen));
        }
        if let Some(rate) = self.nmap_max_rate {
            figment = figment.merge(Serialized::default("limits.nmap_max_rate", rate));
        }
        if let Some(parallel) = self.max_parallel_nmap {
            figment = figment.merge(Serialized::default("limits.max_parallel_nmap", parallel));
        }
        figment
    }
}
