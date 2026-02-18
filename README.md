# PG-Prism 💎

**PG-Prism** is a lightweight, high-performance sidecar proxy for PostgreSQL designed to solve a critical problem in proxied environments: **Loss of Client Identity.**

When using HAProxy, PgBouncer, or other load balancers, the database sees the proxy's IP address instead of the real client's IP. PG-Prism bridges this gap by transparently injecting the real client IP into the PostgreSQL `application_name` session variable.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.12-yellow.svg)
![Rust](https://img.shields.io/badge/rust-1.80-orange.svg)
![Status](https://img.shields.io/badge/status-beta-orange.svg)

## 🚀 Features

*   **Dual Core Architecture**: Choose between the flexible **Python Core** (default) or the high-performance **Rust Core** 🦀.
*   **Transparent IP Injection**: Appends the real client IP to `application_name` (e.g., `DBeaver - 192.168.1.50`).
*   **PROXY Protocol Support**: Native support for HAProxy `PROXY v1` header.
*   **Smart Lightweight Filter**: Inspects *only* small Query/Parse packets (< 1KB). Large data transfers (COPY, INSERTs, SELECTs) are blindly forwarded with **zero parsing overhead**.
*   **Protocol Aware**: Handles both Simple Query Protocol (`Q`) and Extended Query Protocol (`P`) used by JDBC/DBeaver.
*   **SSL Handling**: Forces plaintext connection (by handling `SSLRequest`) to allow packet inspection.

## 🛠 Architecture

```mermaid
graph LR
    Client["Client (DBeaver/App)"] -->|TCP| HAProxy
    HAProxy -->|PROXY Header| PGPrism[PG-Prism Sidecar]
    PGPrism -->|Modified Startup| Postgres
```

## 📦 Installation

### Option 1: Docker (Recommended)

The Docker image includes both Python and Rust cores. You can switch between them using `CORE_TYPE`.

```bash
# build the image
docker build -t pg-prism .

# run it (Default: Python)
docker run -d \
  -p 5433:5433 \
  -e PG_HOST=localhost \
  -e PG_PORT=5432 \
  --name pg-prism \
  pg-prism

# run it (High Performance: Rust 🦀)
docker run -d \
  -p 5433:5433 \
  -e PG_HOST=localhost \
  -e PG_PORT=5432 \
  -e CORE_TYPE=rust \
  --name pg-prism-rust \
  pg-prism
```

### Option 2: Systemd Service (Recommended for Linux)

To ensure PG-Prism runs reliably and restarts automatically on failure or reboot, create a Systemd service.

1.  **Move the project**:
    ```bash
    sudo mv pg-prism /opt/
    ```

2.  **Create the service file**:
    `sudo nano /etc/systemd/system/pg-prism.service`

    ```ini
    [Unit]
    Description=PG-Prism Sidecar Proxy
    After=network.target postgresql.service

    [Service]
    Type=simple
    User=postgres
    WorkingDirectory=/opt/pg-prism
    
    # Python Core (Default)
    ExecStart=/usr/bin/python3 core/python/main.py
    
    # Rust Core (Use instead if compiled)
    # ExecStart=/opt/pg-prism/target/release/pg-prism-rust

    Restart=always
    RestartSec=5
    
    # Environment Variables
    Environment=LISTEN_HOST=0.0.0.0
    Environment=LISTEN_PORT=5433
    Environment=PG_HOST=127.0.0.1
    Environment=PG_PORT=5432
    
    [Install]
    WantedBy=multi-user.target
    ```

3.  **Enable and Start**:
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable --now pg-prism
    sudo systemctl status pg-prism
    ```

## ⚙️ Configuration

| Variable | Default | Description |
| :--- | :--- | :--- |
| `LISTEN_HOST` | `0.0.0.0` | Binding address for the proxy |
| `LISTEN_PORT` | `5433` | Port to listen on |
| `PG_HOST` | `localhost`| Target PostgreSQL Host |
| `PG_PORT` | `5432` | Target PostgreSQL Port |
| `CORE_TYPE` | `python` | Proxy Engine: `python` or `rust` |

## 🔗 HAProxy Configuration

Configure your HAProxy to send traffic to PG-Prism using the `send-proxy` keyword.

```haproxy
backend postgres_backend
    mode tcp
    # Target port 5433 (PG-Prism) instead of 5432
    server pg01 10.0.0.1:5433 check port 8008 send-proxy
```

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
