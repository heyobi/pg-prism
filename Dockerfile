# Builder Stage for Rust
FROM rust:1.85-slim as builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev openssl
WORKDIR /app
COPY core/rust .
RUN cargo build --release

# Final Stage (Python + Rust Binary)
FROM python:3.12-slim

WORKDIR /app

# Copy Python Core
COPY core/python/main.py ./python_core.py

# Copy Rust Binary from Builder
COPY --from=builder /app/target/release/pg-prism-rust ./rust_core

# Environment Defaults
ENV LISTEN_HOST=0.0.0.0
ENV LISTEN_PORT=5433
ENV PG_HOST=localhost
ENV PG_PORT=5432
ENV LOG_LEVEL=INFO
ENV CORE_TYPE=python  
# Options: "python" or "rust"

# Expose the proxy port
EXPOSE 5433

# Startup Script to choose core
RUN echo '#!/bin/bash\n\
    if [ "$CORE_TYPE" = "rust" ]; then\n\
    echo "Starting PG-Prism (Rust Core 🦀)..."\n\
    exec ./rust_core\n\
    else\n\
    echo "Starting PG-Prism (Python Core 🐍)..."\n\
    exec python3 -u python_core.py\n\
    fi' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Run as non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

CMD ["/app/entrypoint.sh"]
