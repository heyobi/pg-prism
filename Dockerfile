# Builder Stage
FROM rust:1.85-slim as builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev openssl
WORKDIR /app
COPY core/rust .
RUN cargo build --release --locked

# Final Stage
#
# The proxy shells out to the `openssl` CLI at startup to generate a self-signed
# certificate when none is present, so the runtime image must contain it. This was
# previously implicit: the image was based on python:3.12-slim and happened to
# inherit openssl as a transitive dependency.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/pg-prism-rust ./pg-prism

# Environment Defaults
ENV LISTEN_HOST=0.0.0.0
ENV LISTEN_PORT=5433
ENV PG_HOST=localhost
ENV PG_PORT=5432
ENV RUST_LOG=info

# Expose the proxy port
EXPOSE 5433

# Run as non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

CMD ["/app/pg-prism"]
