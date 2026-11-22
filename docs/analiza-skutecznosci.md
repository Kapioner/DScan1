# DScan - skuteczność na laboratorium

Laboratorium: 4 stacki Docker + scenariusz quickstart, skaner na `127.0.0.1`.
Konfiguracja: `analiza-lab/dscan-lab.toml`, wzorce: `analiza-lab/wzorce/`, nakładki: `analiza-lab/nakladki-compose/`.

## Wynik

| Miara | Wynik |
|---|---|
| Otwarte porty (31 w 4 stackach) | 31/31 - precyzja i czułość 100% |
| Fałszywe zmiany przy skanie bez zmian | 0 |
| Poprawna nazwa usługi | 20/20 |
| Rozpoznana aplikacja | 20/20 |
| Scenariusz quickstart (8787 znika i wraca) | zaliczony |
| Czas odpowiedzi przez Toxiproxy (opóźnienie 500 ms) | 71 ms → 1057 ms |
| DefectDojo: import XML i eksport obserwacji | 31 findingów, wartości ciasteczek maskowane |
| Usługi spoza laboratorium (Grafana, Jenkins, Portainer, MongoDB) | 4/4 rozpoznane z wersją |

## Quickstart

| Krok | Wynik |
|---|---|
| skan 1 | 5/5 portów |
| `change`, skan 2 | `zniknęła: 8787`, kod 2 |
| `up`, skan 3 | `nowa: 8787`, kod 2 |
| skan 4 | `brak zmian`, kod 0 |

Skan hosta ok. 104 s, z czego narzut DScan ok. 3 s (reszta to `nmap -sV`).

## Rozpoznawane usługi

| Stack | Porty | Rozpoznane |
|---|---|---|
| custom-network | 7 | OpenSSH, Gitea, RabbitMQ (AMQP i panel), nginx, httpbin, PostgreSQL |
| modern | 6 | WordPress, phpMyAdmin, Redis 7.4, Nginx Proxy Manager (OpenResty) |
| vulnerable | 15 | vsftpd 3.0.2, WordPress 4.7, Adminer, DVWA, Apache 2.4.10/2.4.25, PHP 5.6 |
| modern-proxy | 3 | WordPress za proxy, Traefik, Toxiproxy |

## Mechanizmy wpływające na wynik

| Mechanizm | Działanie |
|---|---|
| próba HTTP dla usług niejednoznacznych | `tcpwrapped` i błędne nazwy nmap weryfikowane zapytaniem HTTP, powrót HTTPS → HTTP |
| sygnatury | m.in. Gitea, httpbin, NPM, Traefik, Toxiproxy, DVWA, MongoDB |
| heurystyka „niedokończona instalacja” | kreatory WordPress i Gitea oznaczane jako ryzyko (+40 pkt) |
| czas odpowiedzi | `response_ms` w CLI i UI |
| ocena znalezisk | każda stara wersja osobno, punkty za FTP i wystawioną bazę |

Ranking (stack vulnerable): WordPress 4.7 - 135 pkt, DVWA - 130, Adminer - 85, FTP - 30.

## Ograniczenia

- Produkty bez sygnatury rozpoznawane na poziomie nmap i heurystyk.
- Porty PASV FTP (21000-21010) to 11 osobnych usług `tcpwrapped`.
- Martwy kontener za docker-proxy widoczny jako `tcpwrapped`.
- HTTPS bez SNI (NPM 443) - brak odczytu certyfikatu.
- Na hostach bez IPv6 NPM i Adminer wymagają nakładek compose.

## Odtworzenie

```bash
./run.sh -c docs/analiza-lab/dscan-lab.toml serve
./run.sh -c docs/analiza-lab/dscan-lab.toml scan 127.0.0.1
./run.sh -c docs/analiza-lab/dscan-lab.toml evaluate docs/analiza-lab/wzorce/custom-network.csv --details
```
