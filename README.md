# Vouch Conformance

Docker Compose test harness for running [OpenID Foundation Conformance Suite](https://gitlab.com/openid/conformance-suite) tests against a [Vouch](https://github.com/vouch-sh/vouch) OIDC server.

[![Conformance Tests](https://github.com/vouch-sh/conformance/actions/workflows/conformance.yml/badge.svg)](https://github.com/vouch-sh/conformance/actions/workflows/conformance.yml)

## Overview

This repository automates OpenID certification testing for Vouch. It runs the conformance suite locally via Docker Compose and exercises the full protocol flow -- including TLS, mTLS, Dynamic Client Registration, and automated browser interactions -- without needing the public `certification.openid.net` server.

Test coverage:

- **OIDC Connect** -- 4 certification plans (Basic OP, Config OP, Dynamic OP, Form Post OP)
- **FAPI 2.0 Security Profile** -- 4 variant combinations across `client_auth_type` (private_key_jwt, tls_client_auth) and `sender_constrain` (DPoP, mTLS)
- **FAPI 2.0 Message Signing** -- 4 variant combinations across client auth, sender constraint, and JARM response mode

Python scripts handle plan creation, client registration, test execution, and failure analysis against the conformance suite REST API.

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Docker & Docker Compose | v2+ | Compose V2 plugin (`docker compose`, not standalone `docker-compose`) |
| Python | 3.13+ | Required for FAPI 2.0 client registration and test runner |
| uv | latest | Python package runner; installs `cryptography` dependency |
| openssl | any | Generates self-signed TLS certificates |
| Git | any | Submodule support required |
| Vouch source | -- | Cloned at `../vouch` relative to this repo (override with `VOUCH_REPO_PATH`) |

> [!NOTE]
> The `cryptography` Python package is required for FAPI 2.0 tests (ES256 key generation and self-signed mTLS certificates). OIDC tests use dynamic client registration built into the conformance suite and need no extra dependencies.

## Quick Start

1. **Clone with submodules**

   ```bash
   git clone --recurse-submodules https://github.com/vouch-sh/conformance.git
   cd conformance
   ```

2. **Initialize submodules** (if already cloned without `--recurse-submodules`)

   ```bash
   make init
   ```

3. **Generate TLS certificates**

   ```bash
   make certs
   ```

4. **Build the conformance suite** (first build takes ~5 minutes; subsequent builds use the cached `m2/` directory)

   ```bash
   make build
   ```

5. **Start services and wait for healthy**

   ```bash
   make up && make wait
   ```

The conformance suite UI is available at `https://localhost.emobix.co.uk:8443` (accept the self-signed certificate warning).

## Running Tests

### OIDC Connect

OIDC plans use dynamic client registration internally -- no pre-registration step needed.

```bash
make test-oidc-basic      # Basic OP certification plan
make test-oidc-config     # Config OP certification plan
make test-oidc-dynamic    # Dynamic OP (discovery, dynamic registration, key rotation)
make test-oidc-formpost   # Form Post OP (response_mode=form_post)
```

### FAPI 2.0 Security Profile

FAPI 2.0 plans require pre-registering OAuth clients. Each `make` target handles this automatically via `register_client.py`, which generates ES256 key pairs and (for mTLS variants) self-signed client certificates.

| Target | `client_auth_type` | `sender_constrain` |
|--------|--------------------|--------------------|
| `make test-fapi2` | private_key_jwt | DPoP |
| `make test-fapi2-sp-mtls-mtls` | tls_client_auth | mTLS |
| `make test-fapi2-sp-mtls-dpop` | tls_client_auth | DPoP |
| `make test-fapi2-sp-pk-mtls` | private_key_jwt | mTLS |

### FAPI 2.0 Message Signing

| Target | `client_auth_type` | `sender_constrain` | `fapi_response_mode` |
|--------|--------------------|--------------------|----------------------|
| `make test-fapi2-ms` | private_key_jwt | DPoP | plain_response |
| `make test-fapi2-ms-jarm` | private_key_jwt | DPoP | jarm |
| `make test-fapi2-ms-mtls` | tls_client_auth | mTLS | plain_response |
| `make test-fapi2-ms-mtls-jarm` | tls_client_auth | mTLS | jarm |

### Grouped Targets

```bash
make test-fapi2-all-sp  # All 4 Security Profile variants
make test-fapi2-all-ms  # All 4 Message Signing variants
make test-fapi2-all     # All 8 FAPI 2.0 variants
make test-all           # Everything (OIDC + FAPI 2.0)
```

## Debugging

Test state is saved to `.last-run.json` after each run. The `debug.py` script and Make targets help iterate on failures.

### Failure Analysis

```bash
python3 scripts/debug.py failures              # Failure details with HTTP exchanges
python3 scripts/debug.py status                # Status of all modules from last run
python3 scripts/debug.py log <module-name>     # Full log for one module
python3 scripts/debug.py log <module-name> -v  # Verbose (all entries)
python3 scripts/debug.py vouch-logs            # Recent vouch Docker logs
python3 scripts/debug.py vouch-logs --grep error
```

### Rerunning Tests

```bash
make rerun-failures    # Rerun only failed modules from last run

# Run a single module from a plan
python3 scripts/run.py \
    --plan <plan-name> \
    --config <config-file> \
    --module <module-name>
```

### Vouch Server

```bash
make restart-vouch    # Rebuild and restart just the vouch container
make vouch-logs       # Stream vouch container logs
```

## Architecture

### Docker Services

All services communicate on the `conformance-net` Docker network.

| Service | Role | Ports |
|---------|------|-------|
| `mongodb` | Conformance suite state store | (internal) |
| `server` | OpenID Conformance Suite (Spring Boot, devmode) | (internal) |
| `nginx` | TLS reverse proxy for conformance suite | 8443 |
| `vouch` | Vouch OIDC server under test | 3000 (HTTP) |
| `vouch-proxy` | TLS + mTLS termination proxy for vouch | 9443 (TLS), 9444 (mTLS) |

The conformance suite reaches Vouch at `https://vouch-proxy` (Docker-internal DNS). The `vouch-proxy` nginx container provides TLS termination on port 443 (mapped to host 9443) and TCP passthrough on port 8443 (mapped to host 9444) for mTLS, where Vouch handles client certificate verification directly.

### Python Scripts

| Script | Purpose |
|--------|---------|
| `scripts/run.py` | Main test runner. Creates plans, starts modules, polls for completion, auto-dumps failure logs. Saves state to `.last-run.json`. |
| `scripts/register_client.py` | Dynamic Client Registration against Vouch. Generates ES256 key pairs (`private_key_jwt`) and self-signed certs (`tls_client_auth`). Outputs `export` statements consumed via `eval`. |
| `scripts/conformance.py` | HTTP client for conformance suite REST API (`/api/plan`, `/api/runner`, `/api/info`, `/api/log`). |
| `scripts/debug.py` | Debug helper with subcommands: `failures`, `log`, `status`, `vouch-logs`. Reads `.last-run.json`. |

### Config Templates

JSON config files in `config/` contain placeholder tokens (`{BASEURL}`, `{CLIENT_ID}`, `{CLIENT_JWKS}`, etc.) substituted at runtime by `run.py`. Each config defines a `variant` (test parameterization), a `browser` array (automated login/consent interactions), and optional `override` entries for module-specific browser behavior.

- **OIDC:** `oidcc-basic.json`, `oidcc-config.json`, `oidcc-dynamic.json`, `oidcc-formpost.json`
- **FAPI 2.0 Security Profile:** `fapi2-security-profile.json`, `fapi2-sp-mtls-mtls.json`, `fapi2-sp-mtls-dpop.json`, `fapi2-sp-pk-mtls.json`
- **FAPI 2.0 Message Signing:** `fapi2-message-signing.json`, `fapi2-ms-jarm.json`, `fapi2-ms-mtls.json`, `fapi2-ms-mtls-jarm.json`

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `VOUCH_REPO_PATH` | `../vouch` | Path to Vouch source directory for Docker build context |
| `CONFORMANCE_SERVER` | `https://localhost.emobix.co.uk:8443` | Base URL of the conformance suite API |
| `VOUCH_URL` | `https://localhost:9443` | Vouch URL used by `register_client.py` for client registration |
| `VOUCH_BASE_URL` | `https://vouch-proxy` | Vouch URL as seen by the conformance suite (Docker-internal) |

Most other variables (`CLIENT_ID`, `CLIENT_SECRET`, `CLIENT_JWKS`, `MTLS_CERT`, `MTLS_KEY`) are set automatically by `register_client.py` during FAPI 2.0 test runs.

## CI/CD

### Conformance Tests

The [`conformance.yml`](.github/workflows/conformance.yml) workflow runs on every push to `main`, on `repository_dispatch` from the Vouch repo (release events), and on manual dispatch. It builds the conformance suite JAR (cached by submodule commit SHA), then runs all 12 test plans in parallel using a matrix strategy. Two modes: build Vouch from source (`vouch_ref` input) or pull a pre-built GHCR image (`image` input).

### Certification

The [`certification.yml`](.github/workflows/certification.yml) workflow is manual-dispatch-only and runs against the public `certification.openid.net` server using a self-hosted EC2 runner with ports 443 and 8443 open to the internet. The EC2 instance is started before tests and stopped after to minimize costs. Supports a `--publish` flag to create formal OpenID certification packages.

## Cleanup

```bash
make down     # Stop all services
make clean    # Remove containers, volumes, certs, and build artifacts
```

## License

The Python scripts in this repository are licensed under Apache-2.0 OR MIT (see SPDX headers in `scripts/`). The [OpenID Foundation Conformance Suite](https://gitlab.com/openid/conformance-suite) included as a git submodule is licensed under the [MIT License](conformance-suite/LICENSE.txt).
