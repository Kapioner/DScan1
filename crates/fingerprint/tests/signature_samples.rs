//! Startowa baza sygnatur (H7): każda grupa technologii musi rozpoznawać typową odpowiedź.

// Plik testowy: unwrap() w funkcjach pomocniczych jest tu dozwolony.
#![allow(clippy::unwrap_used)]

use dscan_core::models::{Cookie, HttpHeader, HttpInfo};
use dscan_fingerprint::ProbeResult;
use dscan_fingerprint::signatures::{SignatureSet, WebEvidence};

struct Sample {
    technology: &'static str,
    headers: &'static [(&'static str, &'static str)],
    cookies: &'static [&'static str],
    body: &'static str,
    probe: Option<(&'static str, u16, &'static str)>,
}

const SAMPLES: &[Sample] = &[
    Sample {
        technology: "Microsoft IIS",
        headers: &[("Server", "Microsoft-IIS/10.0")],
        cookies: &[],
        body: "",
        probe: None,
    },
    Sample {
        technology: "Apache Tomcat",
        headers: &[],
        cookies: &[],
        body: "<title>Apache Tomcat/9.0.80</title>",
        probe: None,
    },
    Sample {
        technology: "Microsoft ASP.NET",
        headers: &[("X-AspNet-Version", "4.0.30319")],
        cookies: &[],
        body: "",
        probe: None,
    },
    Sample {
        technology: "Express (Node.js)",
        headers: &[("X-Powered-By", "Express")],
        cookies: &[],
        body: "",
        probe: None,
    },
    Sample {
        technology: "Laravel",
        headers: &[],
        cookies: &["laravel_session"],
        body: "",
        probe: None,
    },
    Sample {
        technology: "Django",
        headers: &[],
        cookies: &["csrftoken"],
        body: r#"<input name="csrfmiddlewaretoken">"#,
        probe: None,
    },
    Sample {
        technology: "Spring Boot",
        headers: &[],
        cookies: &[],
        body: "",
        probe: Some(("/actuator/health", 200, r#"{"status":"UP"}"#)),
    },
    Sample {
        technology: "phpMyAdmin",
        headers: &[],
        cookies: &[],
        body: "<title>phpMyAdmin</title>",
        probe: None,
    },
    Sample {
        technology: "Grafana",
        headers: &[],
        cookies: &[],
        body: "<title>Grafana</title>",
        probe: None,
    },
    Sample {
        technology: "Jenkins",
        headers: &[("X-Jenkins", "2.440")],
        cookies: &[],
        body: "",
        probe: None,
    },
    Sample {
        technology: "Kibana",
        headers: &[("kbn-name", "kibana")],
        cookies: &[],
        body: "",
        probe: None,
    },
    Sample {
        technology: "Elasticsearch",
        headers: &[],
        cookies: &[],
        body: r#"{"version":{"number":"8.11.1"},"tagline" : "You Know, for Search"}"#,
        probe: None,
    },
    Sample {
        technology: "Hikvision",
        headers: &[("Server", "App-webs/")],
        cookies: &[],
        body: "",
        probe: None,
    },
    Sample {
        technology: "Axis",
        headers: &[],
        cookies: &[],
        body: "<a href=\"/axis-cgi/mjpg/video.cgi\">",
        probe: None,
    },
    Sample {
        technology: "Kamera IP (ogólna)",
        headers: &[],
        cookies: &[],
        body: "<title>IP Camera Login</title>",
        probe: None,
    },
    Sample {
        technology: "MikroTik RouterOS",
        headers: &[],
        cookies: &[],
        body: "<title>RouterOS router configuration page</title>",
        probe: None,
    },
    Sample {
        technology: "Joomla",
        headers: &[],
        cookies: &[],
        body: r#"<meta name="generator" content="Joomla! - Open Source">"#,
        probe: None,
    },
    Sample {
        technology: "Drupal",
        headers: &[("X-Generator", "Drupal 10 (https://www.drupal.org)")],
        cookies: &[],
        body: "",
        probe: None,
    },
];

fn info(sample: &Sample) -> HttpInfo {
    HttpInfo {
        url: "http://10.0.0.5/".into(),
        status_code: 200,
        title: None,
        headers: sample
            .headers
            .iter()
            .map(|(n, v)| HttpHeader {
                name: n.to_string(),
                value: v.to_string(),
            })
            .collect(),
        cookies: sample
            .cookies
            .iter()
            .map(|name| Cookie {
                name: name.to_string(),
                value: "x".into(),
                domain: None,
                path: None,
                secure: false,
                http_only: false,
                same_site: None,
            })
            .collect(),
        redirect_chain: Vec::new(),
        tls_verified: None,
        certificate: None,
        favicon: None,
        simhash: None,
        response_ms: None,
    }
}

#[test]
fn every_sample_is_recognized() {
    let set = SignatureSet::builtin().unwrap();
    for sample in SAMPLES {
        let probes: Vec<ProbeResult> = sample
            .probe
            .iter()
            .map(|(path, status, body)| ProbeResult {
                path: path.to_string(),
                status: *status,
                body: body.to_string(),
            })
            .collect();
        let info = info(sample);
        let detections = set.detect(&WebEvidence {
            info: &info,
            body: sample.body,
            probes: &probes,
            favicon_hash: None,
        });
        assert!(
            detections.iter().any(|d| d.technology == sample.technology),
            "nie rozpoznano: {} (wykryto: {:?})",
            sample.technology,
            detections.iter().map(|d| &d.technology).collect::<Vec<_>>()
        );
    }
}

#[test]
fn versions_are_extracted() {
    let set = SignatureSet::builtin().unwrap();
    let check = |sample: &Sample, expected: &str| {
        let info = info(sample);
        let detections = set.detect(&WebEvidence {
            info: &info,
            body: sample.body,
            probes: &[],
            favicon_hash: None,
        });
        let found = detections
            .iter()
            .find(|d| d.technology == sample.technology)
            .unwrap();
        assert_eq!(
            found.version.as_deref(),
            Some(expected),
            "{}",
            sample.technology
        );
    };
    check(&SAMPLES[0], "10.0");
    check(&SAMPLES[1], "9.0.80");
    check(&SAMPLES[9], "2.440");
    check(&SAMPLES[11], "8.11.1");
}

#[test]
fn plain_page_gives_no_false_positives() {
    let set = SignatureSet::builtin().unwrap();
    let sample = Sample {
        technology: "",
        headers: &[("Content-Type", "text/html")],
        cookies: &[],
        body: "<html><title>Firma XYZ</title><p>Witamy</p></html>",
        probe: None,
    };
    let info = info(&sample);
    let detections = set.detect(&WebEvidence {
        info: &info,
        body: sample.body,
        probes: &[],
        favicon_hash: None,
    });
    assert!(detections.is_empty(), "{detections:?}");
}

#[test]
fn extra_signature_file_is_appended() {
    let extra = "- { name: Aplikacja organizatora, matchers: [ { type: header, name: x-lab-app, weight: 90 } ] }";
    let builtin = SignatureSet::builtin().unwrap().len();
    let set = SignatureSet::builtin_with(Some(extra)).unwrap();
    assert_eq!(set.len(), builtin + 1);
    assert!(SignatureSet::builtin_with(Some("- { name: X }")).is_err());
}
