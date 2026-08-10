# PG-Prism 💎

**PG-Prism** is a lightweight, high-performance sidecar proxy for PostgreSQL designed to solve a critical problem in proxied environments: **Loss of Client Identity.**

When using HAProxy, PgBouncer, or other load balancers, the database sees the proxy's IP address instead of the real client's IP. PG-Prism bridges this gap by transparently injecting the real client IP into the PostgreSQL `application_name` session variable.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.85-orange.svg)
![Status](https://img.shields.io/badge/status-beta-orange.svg)

## 🚀 Features

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

```bash
# build the image
docker build -t pg-prism .

docker run -d \
  -p 5433:5433 \
  -e PG_HOST=localhost \
  -e PG_PORT=5432 \
  --name pg-prism \
  pg-prism
```

### Option 2: Standalone binary (Manual Build)

Compile the proxy using Podman/Docker and run it as a standalone binary.

1.  **Compile with Podman/Docker**:
    ```bash
    # Build container
    podman build -t pg-prism .
    
    # Extract binary
    podman create --name temp-extract pg-prism
    podman cp temp-extract:/app/pg-prism ./pg-prism-rust
    podman rm temp-extract
    chmod +x pg-prism-rust
    ```

2.  **Install & Service**:
    Move the binary to `/opt/pg-prism/` and configure Systemd.

    `sudo nano /etc/systemd/system/pg-prism.service`

    ```ini
    [Unit]
    Description=PG-Prism Sidecar Proxy
    After=network.target postgresql.service

    [Service]
    Type=simple
    User=postgres
    WorkingDirectory=/opt/pg-prism
    
    ExecStart=/opt/pg-prism/pg-prism-rust

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

    **Important**: If you are using SELinux (e.g., Fedora/RHEL), ensure the context is correct:
    ```bash
    sudo restorecon -Rv /opt/pg-prism
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
| `TRUSTED_PROXIES` | `127.0.0.0/8,::1/128` | Comma-separated CIDRs allowed to send a PROXY header. Connections from anywhere else are refused without being read. |

> **`TRUSTED_PROXIES` is a security control, not a convenience setting.** The
> PROXY header is an unauthenticated claim about who the peer is talking to. Any
> peer allowed to send one can assert any client address, which both falsifies
> `pg_stat_activity` and satisfies Guardian `ips:` rules. List only the load
> balancers you operate. The proxy refuses to start if the list is malformed, and
> `TRUSTED_PROXIES=0.0.0.0/0,::/0` disables the protection entirely.

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
