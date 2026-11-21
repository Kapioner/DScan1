# Obraz DScan (zadanie D2). Domyślnie DScan działa natywnie (./run.sh) —
# ten obraz służy do wdrożenia całości w kontenerach: docker compose up --build

# --- Etap 1: kompilacja ------------------------------------------------------
FROM rust:1-slim-trixie AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --locked -p dscan

# --- Etap 2: obraz uruchomieniowy --------------------------------------------
FROM debian:trixie-slim

# nmap dostaje CAP_NET_RAW (surowe gniazda do skanów SYN) przez file capabilities,
# dzięki czemu aplikacja nie musi działać jako root. Skan SYN bez roota wymaga
# flagi `nmap --privileged`.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates libcap2-bin \
    && setcap cap_net_raw+eip /usr/bin/nmap \
    && apt-get purge -y libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --no-create-home dscan

COPY --from=builder /app/target/release/dscan /usr/local/bin/dscan
COPY dscan.example.toml /etc/dscan/dscan.toml

USER dscan
ENV DSCAN_CONFIG=/etc/dscan/dscan.toml \
    DSCAN_SERVER__LISTEN=0.0.0.0:8080
EXPOSE 8080

ENTRYPOINT ["dscan"]
CMD ["serve"]
