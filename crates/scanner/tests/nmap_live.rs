//! Test z prawdziwym nmap na 127.0.0.1. Pomijany, jeśli nmap nie jest zainstalowany.
//! Uruchamia lokalny „serwer SSH” (tylko baner), który nmap -sV powinien rozpoznać.

// Plik testowy: unwrap() w funkcjach pomocniczych jest tu dozwolony.
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;

use dscan_core::models::ServiceState;
use dscan_scanner::nmap::{NmapCommand, NmapOptions, NmapProfile, run_scan};
use ipnet::IpNet;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

fn nmap_installed() -> bool {
    let installed = std::process::Command::new("nmap")
        .arg("--version")
        .output()
        .is_ok();
    if !installed {
        eprintln!("pomijam test: brak programu nmap");
    }
    installed
}

/// Nasłuchuje na losowym porcie i każdemu klientowi wysyła baner OpenSSH.
async fn start_fake_ssh() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = socket
                    .write_all(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
                    .await;
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            });
        }
    });
    address
}

fn localhost() -> Vec<IpNet> {
    vec!["127.0.0.1/32".parse().unwrap()]
}

#[tokio::test]
async fn discovery_finds_localhost() {
    if !nmap_installed() {
        return;
    }
    let options = NmapOptions {
        profile: NmapProfile::Discovery,
        ports: String::new(),
        max_rate: 100,
        host_timeout_seconds: None,
        max_retries: None,
    };

    let output = run_scan(&NmapCommand::default(), &options, &localhost())
        .await
        .unwrap();

    assert_eq!(output.hosts.len(), 1);
    assert!(output.raw_xml.contains("<nmaprun"));
}

#[tokio::test]
async fn service_scan_detects_ssh_banner() {
    if !nmap_installed() {
        return;
    }
    let address = start_fake_ssh().await;
    let options = NmapOptions {
        profile: NmapProfile::Services,
        ports: address.port().to_string(),
        max_rate: 100,
        host_timeout_seconds: None,
        max_retries: None,
    };

    let output = run_scan(&NmapCommand::default(), &options, &localhost())
        .await
        .unwrap();

    let service = &output.hosts[0].services[0];
    assert_eq!(service.port, address.port());
    assert_eq!(service.state, ServiceState::Open);
    assert_eq!(service.name.as_deref(), Some("ssh"));
    assert_eq!(service.product.as_deref(), Some("OpenSSH"));
}
