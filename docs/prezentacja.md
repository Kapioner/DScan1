---
marp: true
title: DScan - Defect Scan
paginate: true
---

![w:220](img/logo.png)

# DScan - Defect Scan

Inwentaryzacja usług sieciowych z wykrywaniem zmian

- jedna binarka w Ruście: serwer WWW + API + CLI, PostgreSQL
- instalacja i start: `./install.sh`, kolejne uruchomienia: `./run.sh`

---

## Problem i rozwiązanie

- Co działa w dużej sieci, w jakiej wersji i **co się zmieniło** od ostatniego skanu?
- Skan nmap w podgrupach CIDR z limitem tempa, tylko dozwolone sieci i porty, okna czasowe
- Fingerprinting HTTP/HTTPS, ok. 50 sygnatur + własne, ranking najciekawszych usług
- Porównanie przebiegów, edycja wyników, 4 role, szyfrowanie danych, DefectDojo

---

## Skan z panelu WWW

- cel, profil i tryb w formularzu; postęp, czas i prognoza na żywo
- 16 384 adresów w 64 podgrupach - test z panelu

![Skan w toku](img/zrzuty/09-skan-w-toku.png)

---

## Wykrywanie zmian

- usługi nowe / zniknięte / zmienione między dowolnymi przebiegami

![Porównanie](img/zrzuty/03-porownanie.png)

---

## Fingerprinting HTTP/HTTPS

- tytuł, kod, przekierowania, ciasteczka, nagłówki, certyfikat; technologie z pewnością i dowodami

![Fingerprinting](img/zrzuty/11a-http-8088.png)

---

## Najważniejsze znaleziska

- ranking „ciekawości” z uzasadnieniem: panel, debug, stare wersje, staging, TLS

![Pulpit po skanie](img/zrzuty/10-pulpit-po-skanie.png)

---

## Edycja, import, eksport

- edycja wyniku przetrwa kolejne skany; import celów i wyników (XML, JSON, CSV), eksport CSV/JSON

![Import celów](img/zrzuty/07-cele-import.png)

---

## Role i audyt

- 4 role + własne; „odczyt” bez formularzy zmian, każda zmiana w dzienniku audytu

![Rola odczyt](img/zrzuty/16-rola-odczyt.png)

---

## Bezpieczeństwo i jakość

- tylko `nmap -sn/-sV`, bez NSE i logowania; zakres i porty wymuszone w kodzie; HTTP tylko GET
- AES-256-GCM dla danych poufnych, rotacja kluczy, hasła argon2id, wartości ciasteczek ukryte
- laboratorium: 31/31 portów, 100% precyzji i czułości, 0 fałszywych zmian
- CI: fmt, clippy `-D warnings`, ok. 400 testów, `cargo audit`

---

## Podsumowanie

![bg right:30% w:200](img/logo-mark.png)

- pełny cykl w panelu WWW: cele → skan → zmiany → edycja → role → eksport
- instrukcja dla jury: `hacknation.md`, zrzuty: `docs/pdf/zrzuty-ekranu.pdf`
- dokumentacja: `docs/architektura.md`, `docs/uruchomienie.md`, `docs/cli.md`
