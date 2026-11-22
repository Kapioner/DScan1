<img src="img/logo-mark.png" alt="DScan" width="64" align="right">

# Analiza skuteczności DScan na laboratorium organizatorów

Środowisko: laboratorium z pliku organizatorów (`lab.zip`: 4 stacki Docker + scenariusz quickstart),
lokalny DefectDojo 3.5 (`scripts/defectdojo-setup.sh`), skaner na `127.0.0.1`.
Konfiguracja DScan: [`analiza-lab/dscan-lab.toml`](analiza-lab/dscan-lab.toml). Wzorce prawdy
(porty i aplikacje odczytane z plików compose): [`analiza-lab/wzorce/`](analiza-lab/wzorce/).
Zgodnie z zachętą organizatorów konfiguracja labu była modyfikowana — nakładki:
[`analiza-lab/nakladki-compose/`](analiza-lab/nakladki-compose/).

## Wynik w skrócie

| Miara | Przed poprawkami | Po poprawkach |
|---|---|---|
| Wykryte otwarte porty (4 stacki, 31 portów) | 31/31 — precyzja i czułość 100% | 31/31 — 100% |
| Fałszywe zmiany przy skanie bez zmian | 0 | 0 |
| Poprawna nazwa usługi | 18/20 (90%) | 20/20 (100%) |
| Rozpoznana aplikacja (produkt lub technologia) | 14/20 (70%) | 20/20 (100%) |
| Scenariusz quickstart (zniknięcie i powrót 8787) | zaliczony | zaliczony |
| Czas odpowiedzi usługi (Toxiproxy) | nie mierzony | mierzony: 71 ms → 1057 ms przy opóźnieniu 500 ms |
| DefectDojo: import XML nmap / eksport obserwacji | działa (31 findingów) / działa | działa / działa, wartości ciasteczek ukryte |

„Po poprawkach” dotyczy tych samych usług, pod które część poprawek była robiona (sygnatury), więc
osobno sprawdzono uogólnienie na usługach spoza labu — patrz punkt 6.

## 1. Scenariusz quickstart (znikająca i powracająca usługa)

| Krok | Oczekiwanie organizatorów | Wynik DScan |
|---|---|---|
| `quickstart.sh up`, skan 1 | porty 2223, 3001, 5673, 8787, 15673 otwarte | 5/5 wykryte |
| `quickstart.sh change`, skan 2 | 8787 zamknięty, reszta widoczna | „zniknęła: 127.0.0.1:8787/tcp”, nic więcej; kod wyjścia 2 |
| `quickstart.sh up`, skan 3 | 8787 wraca | „nowa: 127.0.0.1:8787/tcp”; kod wyjścia 2 |
| skan 4 bez zmian | — | „brak zmian”; kod wyjścia 0 |

Czas skanu jednego hosta: ok. 104 s, w całości po stronie `nmap -sV` (sam nmap na tych portach trwa
tyle samo — wolno odpowiadające usługi wydłużają sondy wersji). Narzut DScan: ok. 3 s.

## 2. Stacki laboratorium

| Stack | Porty | Co DScan wykrył przed poprawkami | Luki |
|---|---|---|---|
| custom-network | 7/7 | OpenSSH, RabbitMQ (AMQP i panel), nginx (strona domyślna), PostgreSQL | **Gitea (3001)** nmap nazwał `nessus?`, **httpbin (8888)** `tcpwrapped` → bez odpytania HTTP |
| modern | 6/6 | WordPress, phpMyAdmin, Redis 7.4, OpenResty | brak sygnatury **Nginx Proxy Manager** (81) |
| vulnerable | 15/15 (z 11 portami PASV FTP) | vsftpd 3.0.2, WordPress, Adminer, stare Apache 2.4.10/2.4.25, PHP 5.6 | **DVWA** tylko jako „panel”, bez nazwy |
| modern-proxy | 3/3 | WordPress za proxy | **Traefik (8086)**: nmap `ssl/http`, DScan dostał 404 po HTTPS i zgubił dashboard dostępny po HTTP; **Toxiproxy (8474)** tylko „Golang net/http” |

Przełączanie stacków (masowe zmiany) wykrywane poprawnie, np. custom-network → modern: 6 nowych,
7 zniknęło; modern → vulnerable: 14 nowych, 6 zniknęło.

Każdy wynik nmap był ponownie sprawdzany `curl`: Gitea i httpbin zwracają zwykły HTML (`200 text/html`),
więc to błąd rozpoznania nmap, który DScan przenosił dalej.

## 3. Modyfikacje i warianty

| Wariant | Co zrobiono | Wynik |
|---|---|---|
| NPM i Adminer bez IPv6 | kontenery nie startowały (`[::]:80 failed`), port przyjmował TCP przez docker-proxy → `tcpwrapped`; nakładki `DISABLE_IPV6`, `php -S 0.0.0.0:8080` | po naprawie: 80/81/443 **zmienione** (tcpwrapped → OpenResty), Adminer **nowy** z poprawną technologią |
| Toxiproxy z ghcr.io | host plików ghcr.io zablokowany w tym środowisku → obraz z Docker Hub (2.1.4, to samo API) | stack działa |
| Opóźnienie 500 ms | `ENABLE_LATENCY=true`, `LATENCY_MS=500` | brak fałszywych zmian; skan 16 s → 30 s; po poprawce czas odpowiedzi 71 ms → 1057 ms (dwa skoki przez przekierowanie) |
| Zmiana wersji usługi | 8787: nginx najnowszy → nginx 1.24 | **zmieniona** tylko 8787 |
| Nowe usługi spoza labu | Grafana, Jenkins, Portainer, MongoDB na porcie 8084 | patrz punkt 6 |

## 4. DefectDojo

- **Import (I4):** 4 przebiegi wysłane jako „Nmap Scan” → testy 1–4, 31 findingów „Open Port” z endpointami
  (komplet portów). Parser DefectDojo zamienia XML nmap tylko na otwarte porty — technologie i panele
  trafiają tam dopiero przez eksport obserwacji.
- **Eksport obserwacji (I5):** DVWA, Adminer, WordPress, vsftpd, phpMyAdmin, RabbitMQ Management, Gitea —
  findingi Info z dowodami (matchery, kod i tytuł HTTP, nagłówki).
- **Znaleziony problem bezpieczeństwa:** do dowodów trafiały wartości ciasteczek sesji (`Set-Cookie: PHPSESSID=…`),
  choć w DScan ciasteczka są daną poufną. Poprawione: wartość ciasteczek i nagłówków z tokenami → `***`
  (zostaje nazwa i atrybuty), z testem.

## 5. Poprawki wprowadzone na podstawie analizy

| # | Przyczyna | Poprawka |
|---|---|---|
| 1 | fingerprinting HTTP tylko dla usług nazwanych przez nmap „http” | próba HTTP dla usług niejednoznacznych (`tcpwrapped`, nierozpoznane, bez produktu) i powrót HTTPS → HTTP; nazwa usługi poprawiana z odpowiedzi |
| 2 | brak sygnatur | Gitea, httpbin, Nginx Proxy Manager, Traefik, Toxiproxy, DVWA, MongoDB |
| 3 | kreatory instalacji (WordPress, Gitea) nieoznaczone, a to ryzyko przejęcia aplikacji | heurystyka „Niedokończona instalacja” + waga w ocenie (`unfinished_setup = 40`); „Development” w tytule → środowisko testowe |
| 4 | brak czasu odpowiedzi (wymóg README labu przy Toxiproxy) | `response_ms` mierzony, zapisywany (migracja 0009) i pokazywany w CLI i UI |
| 5 | wartości ciasteczek w DefectDojo | ukrywanie wartości sekretów w dowodach |
| 6 | ocena liczyła tylko pierwszą starą wersję | każda stara wersja osobno (Apache 2.4.10 **i** PHP 5.6.30); punkty za protokół bez szyfrowania (FTP) i wystawioną bazę/broker |
| 7 | 16 ścieżek sond przy limicie 12 — ścieżki nowych sygnatur ucinane; 20 zapytań/host za mało przy kilku usługach WWW na hoście | domyślnie `max_probes_per_service = 20`, `http_requests_per_host = 150` |

Ranking najciekawszych usług po poprawkach (stack vulnerable): WordPress 4.7 — 135 pkt (niedokończona
instalacja, Apache 2.4.10 i PHP 5.6 przestarzałe, panel logowania, nietypowy port, nowa usługa),
DVWA — 130 pkt (panel, środowisko „Development”, Apache 2.4.25), Adminer — 85 pkt, FTP — 30 pkt.

## 6. Test uogólnienia (usługi, pod które nic nie stroiłem)

| Usługa | Wynik |
|---|---|
| Grafana (3000) | rozpoznana z wersją 13.4.0 (sygnatura sprzed analizy) |
| Jenkins (8082) | rozpoznany z wersją 2.541.3 z nagłówka `X-Jenkins` |
| Portainer (8083) | rozpoznany (sygnatura sprzed analizy) |
| MongoDB (8084) | nmap: `websnp?`. **Regresja poprawki nr 1:** próba HTTP przemianowała usługę na „http”. Naprawione: sygnatura MongoDB i nazwa protokołu z rozpoznanej technologii → `mongodb`, rozpoznanie 95% |

Wszystkie 4 nowe usługi oznaczone jako „nowe”, bez fałszywych zmian w pozostałych.

## 7. Ograniczenia i wnioski

- Skuteczność wykrywania portów zależy od nmap i była pełna. Słabym ogniwem było **rozpoznanie usług
  przez nmap** (4 z 27 usług źle nazwane w labie i 1 z 4 w teście uogólnienia) — po poprawce DScan
  weryfikuje to własną próbą HTTP.
- Wynik 100% rozpoznania aplikacji dotyczy usług labu, pod które dodano sygnatury. Test uogólnienia dał 4/4,
  ale to mała próba; nowe produkty bez sygnatury będą rozpoznawane tylko na poziomie nmap
  (produkt/wersja) i heurystyk (panel, instalacja, staging).
- Porty PASV FTP (21000–21010) są raportowane jako 11 osobnych „nowych usług” (`tcpwrapped`). To technicznie
  poprawne (porty są otwarte), ale zaszumia listę zmian — kandydat do grupowania zakresów.
- `tcpwrapped` przy martwym kontenerze (docker-proxy przyjmuje TCP) jest raportowany jako usługa otwarta —
  zgodnie z nmap, ale warto oznaczać „port przyjmuje połączenie, usługa nie odpowiada”.
- HTTPS bez SNI (NPM 443) odrzuca połączenie — DScan nie odczytuje wtedy certyfikatu.
- Czas skanu jednego hosta (~100 s) wynika z sond wersji nmap; przy większych sieciach dzieli się na
  równoległe podgrupy (test skali /18 w `crates/engine/tests/scale.rs`).

## Odtworzenie

```bash
./run.sh -c docs/analiza-lab/dscan-lab.toml serve          # serwer na 127.0.0.1:9080
docker compose -f docker-compose-custom-network.yml up -d  # w katalogu labu organizatorów
./run.sh -c docs/analiza-lab/dscan-lab.toml scan 127.0.0.1
./run.sh -c docs/analiza-lab/dscan-lab.toml evaluate docs/analiza-lab/wzorce/custom-network.csv --details
```
