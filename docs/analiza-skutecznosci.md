# DScan — skuteczność na laboratorium

Laboratorium organizatorów (`lab.zip`: 4 stacki + quickstart), skaner na `127.0.0.1`.
Konfiguracja: `analiza-lab/dscan-lab.toml`, wzorce: `analiza-lab/wzorce/`, nakładki: `analiza-lab/nakladki-compose/`.

## Wynik

| Miara | Przed poprawkami | Po poprawkach |
|---|---|---|
| Otwarte porty (31 w 4 stackach) | 31/31 | 31/31 |
| Fałszywe zmiany | 0 | 0 |
| Poprawna nazwa usługi | 18/20 | 20/20 |
| Rozpoznana aplikacja | 14/20 | 20/20 |
| Quickstart (8787 znika i wraca) | zaliczony | zaliczony |
| Czas odpowiedzi (Toxiproxy 500 ms) | brak | 71 ms → 1057 ms |
| DefectDojo import / eksport | działa | działa, wartości ciasteczek ukryte |

## Quickstart

| Krok | Wynik |
|---|---|
| skan 1 | 5/5 portów |
| `change`, skan 2 | `zniknęła: 8787`, kod 2 |
| `up`, skan 3 | `nowa: 8787`, kod 2 |
| skan 4 | `brak zmian`, kod 0 |

Skan hosta ok. 104 s, z czego narzut DScan ok. 3 s (reszta to `nmap -sV`).

## Luki znalezione i poprawione

| Problem | Poprawka |
|---|---|
| Gitea, httpbin źle nazwane przez nmap (`nessus?`, `tcpwrapped`) | próba HTTP dla usług niejednoznacznych, powrót HTTPS → HTTP |
| brak sygnatur: Gitea, httpbin, Nginx Proxy Manager, Traefik, Toxiproxy, DVWA, MongoDB | dodane |
| kreatory instalacji nieoznaczone | heurystyka „niedokończona instalacja” (+40 pkt) |
| brak czasu odpowiedzi | `response_ms` (migracja 0009) w CLI i UI |
| wartości ciasteczek w DefectDojo | maskowanie `***` |
| ocena liczyła tylko jedną starą wersję | każda osobno + punkty za FTP i wystawioną bazę |
| za mały limit sond | `max_probes_per_service = 20`, `http_requests_per_host = 150` |
| NPM i Adminer bez IPv6 nie startowały | nakładki compose |

Ranking (stack vulnerable): WordPress 4.7 — 135 pkt, DVWA — 130, Adminer — 85, FTP — 30.

## Test uogólnienia (usługi spoza labu)

Grafana 13.4.0, Jenkins 2.541.3, Portainer, MongoDB — 4/4 rozpoznane, wszystkie „nowe”, bez fałszywych zmian.

## Ograniczenia

- Nowe produkty bez sygnatury — tylko poziom nmap i heurystyk.
- Porty PASV FTP (21000–21010) to 11 osobnych usług `tcpwrapped`.
- Martwy kontener za docker-proxy widoczny jako `tcpwrapped`.
- HTTPS bez SNI (NPM 443) — brak odczytu certyfikatu.

## Odtworzenie

```bash
./run.sh -c docs/analiza-lab/dscan-lab.toml serve
./run.sh -c docs/analiza-lab/dscan-lab.toml scan 127.0.0.1
./run.sh -c docs/analiza-lab/dscan-lab.toml evaluate docs/analiza-lab/wzorce/custom-network.csv --details
```
