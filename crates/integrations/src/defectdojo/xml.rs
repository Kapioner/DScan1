//! Scalanie wyników podgrup (osobne dokumenty `<nmaprun>`) w jeden plik dla DefectDojo.

/// Wstawia elementy `<host>` ze wszystkich dokumentów do pierwszego (przed `<runstats>`
/// albo `</nmaprun>`). Dokumenty bez hostów są pomijane.
pub fn merge_nmap_xml(documents: &[String]) -> Option<String> {
    let (first, rest) = documents.split_first()?;
    let hosts: String = rest
        .iter()
        .filter_map(|doc| host_section(doc))
        .collect::<Vec<_>>()
        .join("\n");
    if hosts.is_empty() {
        return Some(first.clone());
    }
    let insert_at = first
        .find("<runstats")
        .or_else(|| first.rfind("</nmaprun>"))?;
    let mut merged = String::with_capacity(first.len() + hosts.len() + 1);
    merged.push_str(&first[..insert_at]);
    merged.push_str(&hosts);
    merged.push('\n');
    merged.push_str(&first[insert_at..]);
    Some(merged)
}

/// Fragment od pierwszego `<host` do końca ostatniego `</host>`.
fn host_section(document: &str) -> Option<&str> {
    let start = document
        .find("<host ")
        .or_else(|| document.find("<host>"))?;
    let end = document.rfind("</host>")? + "</host>".len();
    (end > start).then(|| &document[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_from_all_documents_are_merged() {
        let a =
            r#"<nmaprun><host><address addr="10.0.0.1"/></host><runstats/></nmaprun>"#.to_string();
        let b = r#"<nmaprun><host starttime="1"><address addr="10.0.1.1"/></host></nmaprun>"#
            .to_string();
        let empty = "<nmaprun><runstats/></nmaprun>".to_string();
        let merged = merge_nmap_xml(&[a, b, empty]).unwrap();
        assert_eq!(merged.matches("<host").count(), 2);
        assert!(merged.find("10.0.1.1").unwrap() < merged.find("<runstats").unwrap());
        assert!(merge_nmap_xml(&[]).is_none());
    }
}
