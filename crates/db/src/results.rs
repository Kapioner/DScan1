//! Wydajny zapis wyników skanu (zadanie B5).
//!
//! Zamiast jednego INSERT na wiersz używamy INSERT z wieloma wierszami (multi-row),
//! po kilkaset–tysiąc wierszy naraz. Paczki są potrzebne, bo PostgreSQL przyjmuje
//! najwyżej 65 535 parametrów w jednym zapytaniu.

use std::collections::HashMap;
use std::net::IpAddr;

use dscan_core::models::{Host, Service};
use dscan_crypto::Cipher;
use sqlx::{PgConnection, Postgres, QueryBuilder};

use crate::columns::SERVICES_BANNER;
use crate::{DbError, Encrypted, PgPool};

/// Hostów w jednym INSERT (6 parametrów na wiersz).
pub const HOSTS_PER_INSERT: usize = 1000;
/// Usług w jednym INSERT (9 parametrów na wiersz).
pub const SERVICES_PER_INSERT: usize = 1000;

// Sprawdzenie w czasie kompilacji: paczki mieszczą się w limicie parametrów PostgreSQL.
const POSTGRES_MAX_PARAMETERS: usize = 65_535;
const _: () = assert!(HOSTS_PER_INSERT * 6 <= POSTGRES_MAX_PARAMETERS);
const _: () = assert!(SERVICES_PER_INSERT * 9 <= POSTGRES_MAX_PARAMETERS);

/// Ile wierszy zapisano.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SaveSummary {
    pub hosts: u64,
    pub services: u64,
}

/// Zapisuje hosty z usługami w osobnej transakcji (np. przy imporcie wyników).
pub async fn save_scan_results(
    pool: &PgPool,
    cipher: &Cipher,
    run_id: i64,
    hosts: &[Host],
) -> Result<SaveSummary, DbError> {
    let mut transaction = pool.begin().await.map_err(DbError::Query)?;
    let summary = insert_hosts_with_services(&mut transaction, cipher, run_id, hosts).await?;
    transaction.commit().await.map_err(DbError::Query)?;
    Ok(summary)
}

/// Zapis hostów i usług w ramach przekazanego połączenia/transakcji.
pub async fn insert_hosts_with_services(
    connection: &mut PgConnection,
    cipher: &Cipher,
    run_id: i64,
    hosts: &[Host],
) -> Result<SaveSummary, DbError> {
    let mut host_ids: HashMap<IpAddr, i64> = HashMap::with_capacity(hosts.len());
    for chunk in hosts.chunks(HOSTS_PER_INSERT) {
        host_ids.extend(insert_hosts(connection, run_id, chunk).await?);
    }

    let services: Vec<(i64, &Service)> = hosts
        .iter()
        .filter_map(|host| host_ids.get(&host.ip).map(|id| (*id, host)))
        .flat_map(|(id, host)| host.services.iter().map(move |service| (id, service)))
        .collect();
    for chunk in services.chunks(SERVICES_PER_INSERT) {
        insert_services(connection, cipher, chunk).await?;
    }

    Ok(SaveSummary {
        hosts: host_ids.len() as u64,
        services: services.len() as u64,
    })
}

/// Jeden INSERT dla paczki hostów; zwraca mapę adres → id.
async fn insert_hosts(
    connection: &mut PgConnection,
    run_id: i64,
    hosts: &[Host],
) -> Result<Vec<(IpAddr, i64)>, DbError> {
    let mut query: QueryBuilder<Postgres> = QueryBuilder::new(
        "INSERT INTO hosts (scan_run_id, ip, hostnames, status, first_seen, last_seen) ",
    );
    query.push_values(hosts, |mut row, host| {
        row.push_bind(run_id)
            .push_bind(host.ip)
            .push_bind(&host.hostnames)
            .push_bind(host.status.as_str())
            .push_bind(host.first_seen)
            .push_bind(host.last_seen);
    });
    query.push(" RETURNING ip, id");

    query
        .build_query_as::<(IpAddr, i64)>()
        .fetch_all(&mut *connection)
        .await
        .map_err(DbError::Query)
}

/// Jeden INSERT dla paczki usług. Banery są szyfrowane przed zapisem.
async fn insert_services(
    connection: &mut PgConnection,
    cipher: &Cipher,
    services: &[(i64, &Service)],
) -> Result<(), DbError> {
    let banners = services
        .iter()
        .map(|(_, service)| match &service.banner {
            Some(banner) => Encrypted::seal(cipher, &SERVICES_BANNER, banner).map(Some),
            None => Ok(None),
        })
        .collect::<Result<Vec<_>, DbError>>()?;

    let mut query: QueryBuilder<Postgres> = QueryBuilder::new(
        "INSERT INTO services (host_id, port, protocol, state, name, product, version, cpe, banner) ",
    );
    query.push_values(
        services.iter().zip(banners),
        |mut row, ((host_id, service), banner)| {
            row.push_bind(*host_id)
                .push_bind(i32::from(service.port))
                .push_bind(service.protocol.as_str())
                .push_bind(service.state.as_str())
                .push_bind(&service.name)
                .push_bind(&service.product)
                .push_bind(&service.version)
                .push_bind(&service.cpe)
                .push_bind(banner);
        },
    );

    query
        .build()
        .execute(&mut *connection)
        .await
        .map(|_| ())
        .map_err(DbError::Query)
}
