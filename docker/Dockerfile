FROM rust:1.83 AS builder
WORKDIR /app
RUN rustup update stable && rustup default stable
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release --locked && rm -rf src
COPY src ./src
COPY migrations ./migrations
COPY scripts ./scripts
RUN touch src/main.rs && cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates netcat-openbsd && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/rust-auth-template /app/
COPY migrations ./migrations
COPY scripts ./scripts
RUN chmod +x ./scripts/wait-for-db.sh
EXPOSE 8000
CMD ["/app/rust-auth-template"]
