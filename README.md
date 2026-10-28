# Forteca

**An async Rust-based reverse proxy with Web Application Firewall (WAF) capabilities, powered by Pingora, ModSecurity v3 (through the custom FFI integration), and the OWASP Core Rule Set.**

## Why I made this project?

I found interest in developing custom Rust FFI with ModSecurity and understanding how WAF works in tandem with Reverse Proxy.

## Listed Features

- **Reverse proxy:** HTTP request forwarding using Cloudflare's Pingora framework.
- **HTTPS support:** TLS termination with configurable certificate and private key paths.
- **Configurable upstream:** Backend address and protocol configured through TOML.
- **Web Application Firewall:** Integration with ModSecurity v3 through Rust FFI.
- **OWASP CRS:** Request inspection using the OWASP Core Rule Set v4.
- **Request inspection:** HTTP headers and request bodies are processed by ModSecurity.
- **Disruptive actions:** Support for allowing, blocking, and redirecting requests based on WAF decisions.
- **Request body limit:** Maximum buffered request body size of 1 MiB.

## Stack

| Component | Technology |
|---|---|
| Lang | Rust |
| Reverse proxy | Pingora |
| WAF engine | ModSecurity v3 |
| Security rules | OWASP Core Rule Set v4 |
| Native integration | Rust FFI, bindgen |
| Async communication | Tokio |
| Configuration | TOML, Serde |

## Configuration

The reverse proxy uses TOML configuration files for development and production environments.

Example:

```toml
[server]
listen = "127.0.0.1:3001"

[tls]
cert = "certs/dev.pem"
key = "certs/dev-key.pem"

[[routes]]
domain = "localhost"
upstream = "127.0.0.1:8080"
protocol = "http"
```

Configuration values include the proxy listening address, TLS certificate paths, and backend connection settings.

The current implementation uses the first configured upstream. Full host-based routing is not yet implemented.

## Building and Running

### Prerequisites

- Rust toolchain and Cargo
- ModSecurity v3 development library
- Clang/libclang for generating FFI bindings
- pkg-config
- ModSecurity native dependencies
- OWASP Core Rule Set files

ModSecurity must be installed in a location discoverable by `pkg-config`.

Verify installation:

```bash
pkg-config --modversion modsecurity
```

If installed in a custom location, configure `PKG_CONFIG_PATH` accordingly.

### Build

```bash
cargo build
```

### Run

```bash
cargo run
```

Configure the upstream backend and TLS certificate paths before starting the proxy.

For local HTTPS testing, a locally trusted certificate can be generated using `mkcert`.


## Roadmap

- [ ] Per-IP request rate limiting and burst control
- [ ] Connection limits and timeout hardening
- [ ] ModSecurity response inspection (phases 3 and 4)
- [ ] Prometheus metrics and monitoring
- [ ] Automated integration tests and GitHub Actions CI
- [ ] Load testing and performance benchmarking
- [ ] Fuzz testing for suitable Rust components
- [ ] Multi-domain routing and upstream management

## Third-Party Components

This project uses ModSecurity v3 and the OWASP Core Rule Set, both distributed under the Apache License 2.0.

Their respective licenses and notices should be retained when redistributing bundled components.

## Disclaimer

Forteca is an experimental security project. It should not be relied upon as the sole security control for a publicly exposed application without further testing, hardening, and operational review :).
