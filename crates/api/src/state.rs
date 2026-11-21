use dscan_db::PgPool;

/// Stan współdzielony przez wszystkie handlery. `PgPool` jest tani do klonowania
/// (wewnątrz to licznik referencji), więc cały stan może być `Clone`.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
}

impl AppState {
    pub fn new(db: PgPool) -> Self {
        AppState { db }
    }
}
