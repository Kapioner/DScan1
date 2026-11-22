//! Wizualizacja zmian w czasie (F10): liczba hostów i usług w przebiegach oraz mapa
//! aktywności hostów w godzinach i dniach tygodnia.

use askama::Template;
use axum::extract::State;
use axum::response::Html;
use chrono::{Datelike, Local, TimeDelta, Timelike, Utc};
use dscan_api::{ApiError, AppState};

use crate::charts::{Series, heatmap, line_chart};
use crate::pages::{render, user_bar};
use crate::session::WebUser;
use crate::views::UserBar;
use crate::{MenuItem, menu_for};

#[derive(Template)]
#[template(path = "trends.html")]
pub struct TrendsPage {
    pub user: UserBar,
    pub menu: Vec<MenuItem>,
    /// Gotowe SVG (wygenerowane w Ruście, wartości liczbowe i podpisy uciekane).
    pub counts_svg: String,
    pub heatmap_svg: String,
    pub runs: usize,
}

pub async fn trends_page(
    State(state): State<AppState>,
    WebUser(user): WebUser,
) -> Result<Html<String>, ApiError> {
    let totals = dscan_db::run_totals(&state.db, 60).await?;
    let labels: Vec<String> = totals.iter().map(|t| format!("#{}", t.run_id)).collect();
    let counts_svg = line_chart(
        "Hosty i usługi w kolejnych przebiegach",
        &labels,
        &[
            Series {
                name: "hosty",
                css: "series-a",
                values: totals.iter().map(|t| t.hosts as f64).collect(),
            },
            Series {
                name: "otwarte usługi",
                css: "series-b",
                values: totals.iter().map(|t| t.services as f64).collect(),
            },
        ],
    );
    // Średnia liczba odpowiadających hostów w danej godzinie i dniu (ostatnie 30 dni).
    let mut sums = [[0.0_f64; 24]; 7];
    let mut counts = [[0.0_f64; 24]; 7];
    for (at, responded) in
        dscan_db::responses_by_run(&state.db, Utc::now() - TimeDelta::days(30)).await?
    {
        let local = at.with_timezone(&Local);
        let (day, hour) = (
            local.weekday().num_days_from_monday() as usize,
            local.hour() as usize,
        );
        sums[day][hour] += responded as f64;
        counts[day][hour] += 1.0;
    }
    let mut cells = [[0.0_f64; 24]; 7];
    for day in 0..7 {
        for hour in 0..24 {
            if counts[day][hour] > 0.0 {
                cells[day][hour] = sums[day][hour] / counts[day][hour];
            }
        }
    }
    render(&TrendsPage {
        menu: menu_for(&user, "/trends"),
        user: user_bar(&user),
        heatmap_svg: heatmap("Średnia liczba odpowiadających hostów", &cells),
        counts_svg,
        runs: totals.len(),
    })
}
