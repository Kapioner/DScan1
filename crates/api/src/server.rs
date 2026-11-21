use axum::Router;
use tokio::net::TcpListener;

/// Obsługuje żądania do momentu Ctrl+C lub SIGTERM (np. `docker stop`),
/// po czym kończy pracę łagodnie — trwające żądania są dokańczane.
pub async fn serve(listener: TcpListener, router: Router) -> std::io::Result<()> {
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
}

async fn shutdown_signal() {
    let ctrl_c = async {
        // Gdyby nie dało się zarejestrować Ctrl+C, serwer działa dalej do SIGTERM.
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };

    tokio::select! {
        () = ctrl_c => {},
        () = terminate_signal() => {},
    }
    tracing::info!("zatrzymywanie serwera…");
}

#[cfg(unix)]
async fn terminate_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    match signal(SignalKind::terminate()) {
        Ok(mut stream) => {
            stream.recv().await;
        }
        Err(_) => std::future::pending::<()>().await,
    }
}

#[cfg(not(unix))]
async fn terminate_signal() {
    std::future::pending::<()>().await;
}
