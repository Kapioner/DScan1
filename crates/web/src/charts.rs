//! Proste wykresy SVG generowane po stronie serwera (F10) — bez zewnętrznych skryptów,
//! więc działają offline i z restrykcyjnym Content-Security-Policy.

use std::fmt::Write;

/// Seria danych wykresu liniowego.
pub struct Series<'a> {
    pub name: &'a str,
    /// Klasa CSS koloru linii (`series-a`, `series-b`).
    pub css: &'a str,
    pub values: Vec<f64>,
}

const WIDTH: f64 = 720.0;
const HEIGHT: f64 = 240.0;
const PAD: f64 = 36.0;

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Wykres liniowy z osią Y od zera; `labels` — podpisy osi X (np. numery przebiegów).
pub fn line_chart(title: &str, labels: &[String], series: &[Series<'_>]) -> String {
    let max = series
        .iter()
        .flat_map(|s| s.values.iter().copied())
        .fold(0.0_f64, f64::max)
        .max(1.0);
    let count = labels.len().max(1);
    let x = |i: usize| {
        PAD + (WIDTH - 2.0 * PAD)
            * if count == 1 {
                0.5
            } else {
                i as f64 / (count - 1) as f64
            }
    };
    let y = |v: f64| HEIGHT - PAD - (HEIGHT - 2.0 * PAD) * v / max;
    let mut svg = format!(
        "<svg class=\"chart\" viewBox=\"0 0 {WIDTH} {HEIGHT}\" role=\"img\" aria-label=\"{}\">",
        escape(title)
    );
    // Siatka: 0, połowa, maksimum.
    for fraction in [0.0, 0.5, 1.0] {
        let value = max * fraction;
        let _ = write!(
            svg,
            "<line class=\"grid\" x1=\"{PAD}\" x2=\"{}\" y1=\"{y0:.1}\" y2=\"{y0:.1}\"/><text class=\"axis\" x=\"4\" y=\"{ty:.1}\">{value:.0}</text>",
            WIDTH - PAD,
            y0 = y(value),
            ty = y(value) + 4.0
        );
    }
    let step = (count / 8).max(1);
    for (i, label) in labels.iter().enumerate().filter(|(i, _)| i % step == 0) {
        let _ = write!(
            svg,
            "<text class=\"axis\" x=\"{:.1}\" y=\"{}\" text-anchor=\"middle\">{}</text>",
            x(i),
            HEIGHT - 10.0,
            escape(label)
        );
    }
    for s in series {
        let points: Vec<String> = s
            .values
            .iter()
            .enumerate()
            .map(|(i, v)| format!("{:.1},{:.1}", x(i), y(*v)))
            .collect();
        let _ = write!(
            svg,
            "<polyline class=\"line {}\" points=\"{}\"><title>{}</title></polyline>",
            s.css,
            points.join(" "),
            escape(s.name)
        );
        for (i, v) in s.values.iter().enumerate() {
            let _ = write!(
                svg,
                "<circle class=\"dot {}\" cx=\"{:.1}\" cy=\"{:.1}\" r=\"3\"><title>{}: {v}</title></circle>",
                s.css,
                x(i),
                y(*v),
                escape(s.name)
            );
        }
    }
    svg.push_str("</svg>");
    svg
}

/// Mapa cieplna 7 dni × 24 godziny; wartości 0..=max → klasy `heat-0`…`heat-4`.
pub fn heatmap(title: &str, cells: &[[f64; 24]; 7]) -> String {
    const DAYS: [&str; 7] = ["pn", "wt", "śr", "cz", "pt", "sb", "nd"];
    let max = cells
        .iter()
        .flatten()
        .copied()
        .fold(0.0_f64, f64::max)
        .max(1.0);
    let (cell, left, top) = (26.0, 30.0, 18.0);
    let mut svg = format!(
        "<svg class=\"chart\" viewBox=\"0 0 {} {}\" role=\"img\" aria-label=\"{}\">",
        left + 24.0 * cell,
        top + 7.0 * cell,
        escape(title)
    );
    for hour in (0..24).step_by(3) {
        let _ = write!(
            svg,
            "<text class=\"axis\" x=\"{:.1}\" y=\"12\" text-anchor=\"middle\">{hour}</text>",
            left + hour as f64 * cell + cell / 2.0
        );
    }
    for (day, row) in cells.iter().enumerate() {
        let _ = write!(
            svg,
            "<text class=\"axis\" x=\"0\" y=\"{:.1}\">{}</text>",
            top + day as f64 * cell + cell * 0.65,
            DAYS[day]
        );
        for (hour, value) in row.iter().enumerate() {
            let level = ((value / max) * 4.0).round() as u8;
            let _ = write!(
                svg,
                "<rect class=\"heat-{level}\" x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" rx=\"3\"><title>{} {hour}:00 — {value:.0}</title></rect>",
                left + hour as f64 * cell,
                top + day as f64 * cell,
                cell - 2.0,
                cell - 2.0,
                DAYS[day]
            );
        }
    }
    svg.push_str("</svg>");
    svg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_chart_has_series_and_escaped_labels() {
        let labels = vec!["#1".to_string(), "#2 <x>".to_string()];
        let svg = line_chart(
            "Hosty",
            &labels,
            &[Series {
                name: "hosty",
                css: "series-a",
                values: vec![3.0, 5.0],
            }],
        );
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
        assert_eq!(svg.matches("<circle").count(), 2);
        assert!(svg.contains("&lt;x&gt;"));
    }

    #[test]
    fn heatmap_has_168_cells() {
        let mut cells = [[0.0; 24]; 7];
        cells[0][10] = 4.0;
        let svg = heatmap("Aktywność", &cells);
        assert_eq!(svg.matches("<rect").count(), 168);
        assert!(svg.contains("heat-4"));
    }
}
