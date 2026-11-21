//! Cele skanowania (zadanie S2): od tekstu wpisanego przez użytkownika do listy
//! niepowtarzających się sieci, które wolno skanować.
//!
//! Deduplikacja nie trzyma adresów w pamięci: sieci są scalane ([`aggregate_networks`]),
//! więc nakładające się cele (np. `10.0.0.0/24` i `10.0.0.5`) dają jeden zakres,
//! a [`AddressIterator`] rozwija go adres po adresie — także dla setek tysięcy adresów.

mod addresses;
mod parse;
mod plan;
mod resolve;
mod scope;

pub use addresses::{AddressIterator, aggregate_networks, count_addresses, single_address_network};
pub use parse::{is_valid_domain, parse_target};
pub use plan::{TargetPlan, prepare_targets};
pub use resolve::{DomainResolver, SystemResolver};
pub use scope::{is_in_scope, partition_by_scope};
