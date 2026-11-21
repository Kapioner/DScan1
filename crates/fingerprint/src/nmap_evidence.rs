//! Wyniki `nmap -sV` jako dodatkowe dowody (H9): pola product, version i CPE łączone
//! z detekcjami HTTP. Jeśli nmap i sygnatury HTTP wskazują tę samą technologię, dowody
//! się sumują (wyższa pewność); jeśli nie — nmap daje osobną detekcję.

use dscan_core::models::{Detection, Evidence, EvidenceKind, Host, Service, cap_confidence};

/// Wagi dowodów z nmap.
pub const PRODUCT_WEIGHT: u8 = 40;
pub const VERSION_WEIGHT: u8 = 10;
pub const CPE_WEIGHT: u8 = 20;

/// Nazwy z nmap/CPE → nazwy sygnatur DScan (reszta bez zmian).
const ALIASES: [(&str, &str); 10] = [
    ("apache httpd", "Apache HTTP Server"),
    ("apache:http_server", "Apache HTTP Server"),
    ("microsoft iis httpd", "Microsoft IIS"),
    ("microsoft:internet_information_services", "Microsoft IIS"),
    ("apache tomcat", "Apache Tomcat"),
    ("apache:tomcat", "Apache Tomcat"),
    ("igor_sysoev:nginx", "nginx"),
    ("f5:nginx", "nginx"),
    ("openbsd:openssh", "OpenSSH"),
    ("jenkins:jenkins", "Jenkins"),
];

/// `cpe:/a:apache:http_server:2.4.58` → `apache:http_server`.
pub fn cpe_vendor_product(cpe: &str) -> Option<String> {
    let rest = cpe
        .strip_prefix("cpe:/")
        .or_else(|| cpe.strip_prefix("cpe:2.3:"))?;
    let mut parts = rest.split(':').skip(1);
    Some(format!("{}:{}", parts.next()?, parts.next()?).to_lowercase())
}

/// Nazwa technologii z pól nmap: alias z produktu, potem z CPE, w ostateczności sam produkt.
pub fn technology_name(service: &Service) -> Option<String> {
    let alias = |key: &str| {
        ALIASES
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    };
    let product = service
        .product
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty());
    product
        .and_then(|p| alias(&p.to_lowercase()))
        .or_else(|| {
            service
                .cpe
                .iter()
                .find_map(|cpe| cpe_vendor_product(cpe).and_then(|key| alias(&key)))
        })
        .or_else(|| product.map(str::to_string))
}

/// Czy dwie nazwy oznaczają tę samą technologię (bez wielkości liter; jedna zawiera drugą).
pub fn same_technology(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_lowercase(), b.to_lowercase());
    a == b || a.contains(&b) || b.contains(&a)
}

/// Dowody z nmap dla usługi.
pub fn nmap_evidence(service: &Service) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    let item = |description: String, weight: u8| Evidence {
        kind: EvidenceKind::NmapService,
        description,
        weight,
    };
    if let Some(product) = service.product.as_deref().filter(|p| !p.is_empty()) {
        evidence.push(item(format!("nmap -sV: produkt {product}"), PRODUCT_WEIGHT));
        if let Some(version) = service.version.as_deref().filter(|v| !v.is_empty()) {
            evidence.push(item(format!("nmap -sV: wersja {version}"), VERSION_WEIGHT));
        }
    }
    if let Some(cpe) = service.cpe.first() {
        evidence.push(item(format!("nmap -sV: CPE {cpe}"), CPE_WEIGHT));
    }
    evidence
}

/// Łączy dowody z nmap z detekcjami usługi.
pub fn merge_nmap_evidence(service: &mut Service) {
    let Some(technology) = technology_name(service) else {
        return;
    };
    let evidence = nmap_evidence(service);
    if evidence.is_empty()
        || service.detections.iter().any(|d| {
            d.evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::NmapService)
        })
    {
        return; // już połączone (np. ponowne przetwarzanie importu)
    }
    let version = service.version.clone().filter(|v| !v.is_empty());
    match service
        .detections
        .iter_mut()
        .find(|d| same_technology(&d.technology, &technology))
    {
        Some(detection) => {
            detection.evidence.extend(evidence);
            let total: u32 = detection.evidence.iter().map(|e| u32::from(e.weight)).sum();
            detection.confidence = cap_confidence(total);
            if detection.version.is_none() {
                detection.version = version;
            }
        }
        None => service
            .detections
            .push(Detection::from_evidence(technology, version, evidence)),
    }
    service.detections.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.technology.cmp(&b.technology))
    });
}

/// [`merge_nmap_evidence`] dla wszystkich usług hostów.
pub fn merge_nmap_evidence_hosts(hosts: &mut [Host]) {
    hosts
        .iter_mut()
        .flat_map(|h| h.services.iter_mut())
        .for_each(merge_nmap_evidence);
}

#[cfg(test)]
mod tests {
    use super::*;
    use dscan_core::models::{Protocol, ServiceState};

    fn service(product: &str, version: &str, cpe: &[&str]) -> Service {
        let mut s = Service::new(80, Protocol::Tcp, ServiceState::Open);
        s.product = Some(product.into());
        s.version = Some(version.into());
        s.cpe = cpe.iter().map(|c| c.to_string()).collect();
        s
    }

    #[test]
    fn nmap_strengthens_matching_http_detection() {
        let mut s = service("nginx", "1.24.0", &["cpe:/a:igor_sysoev:nginx:1.24.0"]);
        s.detections = vec![Detection::from_evidence(
            "nginx".into(),
            None,
            vec![Evidence {
                kind: EvidenceKind::Header,
                description: "Server".into(),
                weight: 30,
            }],
        )];
        merge_nmap_evidence(&mut s);
        assert_eq!(s.detections.len(), 1);
        assert_eq!(s.detections[0].confidence, 100);
        assert_eq!(s.detections[0].version.as_deref(), Some("1.24.0"));
        // Drugie wywołanie niczego nie dubluje.
        merge_nmap_evidence(&mut s);
        assert_eq!(s.detections[0].evidence.len(), 4);
    }

    #[test]
    fn nmap_alone_gives_separate_detection_with_alias() {
        let mut s = service(
            "Apache httpd",
            "2.4.58",
            &["cpe:/a:apache:http_server:2.4.58"],
        );
        merge_nmap_evidence(&mut s);
        assert_eq!(s.detections[0].technology, "Apache HTTP Server");
        assert_eq!(s.detections[0].confidence, 70);
        assert_eq!(
            cpe_vendor_product("cpe:2.3:a:apache:tomcat:9"),
            Some("apache:tomcat".into())
        );
    }
}
