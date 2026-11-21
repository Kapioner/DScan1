//! Odczyt certyfikatu TLS (zadanie H3).
//!
//! Łączymy się osobnym połączeniem TLS, które przyjmuje **każdy** certyfikat — celem jest
//! tylko jego odczyt (także wygasłego lub self-signed), a nie bezpieczna wymiana danych:
//! po uzgodnieniu połączenia nic nie wysyłamy i od razu je zamykamy.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dscan_core::models::CertificateInfo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};

use crate::encode_hex_lower;

/// Pobiera i odczytuje certyfikat serwera TLS pod `ip:port`.
pub async fn fetch_certificate(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> Result<CertificateInfo, String> {
    let connector = TlsConnector::from(Arc::new(read_only_config()?));
    let stream = tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(ip, port)))
        .await
        .map_err(|_| "przekroczony czas połączenia".to_string())?
        .map_err(|error| error.to_string())?;
    let tls = tokio::time::timeout(
        timeout,
        connector.connect(ServerName::IpAddress(ip.into()), stream),
    )
    .await
    .map_err(|_| "przekroczony czas uzgadniania TLS".to_string())?
    .map_err(|error| error.to_string())?;
    let (_, session) = tls.get_ref();
    let der = session
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or_else(|| "serwer nie przesłał certyfikatu".to_string())?;
    parse_certificate(der.as_ref())
}

/// Odczytuje pola certyfikatu z postaci DER.
pub fn parse_certificate(der: &[u8]) -> Result<CertificateInfo, String> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|error| format!("niepoprawny certyfikat: {error}"))?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(String::from);
    let validity = cert.validity();
    Ok(CertificateInfo {
        self_signed: subject == issuer,
        subject,
        common_name,
        alt_names: alt_names(&cert),
        issuer,
        not_before: to_utc(validity.not_before.timestamp()),
        not_after: to_utc(validity.not_after.timestamp()),
        signature_algorithm: signature_algorithm_name(&cert),
        sha256: encode_hex_lower(&Sha256::digest(der)),
    })
}

fn alt_names(cert: &X509Certificate<'_>) -> Vec<String> {
    cert.extensions()
        .iter()
        .filter_map(|extension| match extension.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => Some(&san.general_names),
            _ => None,
        })
        .flatten()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some(dns.to_string()),
            GeneralName::IPAddress(bytes) => ip_from_bytes(bytes).map(|ip| ip.to_string()),
            _ => None,
        })
        .collect()
}

fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => <[u8; 4]>::try_from(bytes).ok().map(IpAddr::from),
        16 => <[u8; 16]>::try_from(bytes).ok().map(IpAddr::from),
        _ => None,
    }
}

/// Nazwa algorytmu podpisu (np. `sha256WithRSAEncryption`); nieznany — numer OID.
fn signature_algorithm_name(cert: &X509Certificate<'_>) -> String {
    let oid = &cert.signature_algorithm.algorithm;
    x509_parser::objects::oid2sn(oid, x509_parser::objects::oid_registry())
        .map(String::from)
        .unwrap_or_else(|_| oid.to_id_string())
}

fn to_utc(timestamp: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(timestamp, 0).unwrap_or_default()
}

/// Konfiguracja klienta TLS przyjmująca każdy certyfikat (tylko do odczytu certyfikatu).
fn read_only_config() -> Result<ClientConfig, String> {
    let provider = Arc::new(ring::default_provider());
    let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(provider)))
        .with_no_client_auth();
    Ok(config)
}

/// Weryfikator, który niczego nie odrzuca. Używany wyłącznie do odczytu certyfikatu —
/// przez to połączenie nie są przesyłane żadne dane.
#[derive(Debug)]
struct AcceptAnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_der_is_an_error() {
        assert!(parse_certificate(b"to nie jest certyfikat").is_err());
    }

    #[test]
    fn ip_addresses_from_san_bytes() {
        assert_eq!(
            ip_from_bytes(&[10, 0, 0, 5]).unwrap().to_string(),
            "10.0.0.5"
        );
        assert_eq!(ip_from_bytes(&[0; 3]), None);
    }
}
