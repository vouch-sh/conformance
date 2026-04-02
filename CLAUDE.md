# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Docker Compose environment for running OpenID Foundation Conformance Suite tests against a local Vouch OIDC server. Validates OIDC Connect and FAPI 2.0 profiles offline without the public certification server.

The Vouch server source lives outside this repo (default `../vouch`, override with `VOUCH_REPO_PATH`).

## Setup and Build

```bash
make init          # Initialize git submodules (conformance-suite)
make certs         # Generate self-signed TLS certs in certs/
make build         # Build conformance suite JAR via Maven in Docker
make up            # Start all 5 Docker services
make wait          # Block until conformance suite + vouch are healthy
```

## Running Tests

OIDC plans use dynamic client registration internally. FAPI 2.0 plans require a separate `register_client.py` step first (the Makefile handles this via `eval`).

```bash
# OIDC plans (Vouch only supports code flow — no implicit/hybrid/formpost)
make test-oidc-basic
make test-oidc-config

# FAPI 2.0 Security Profile (registers client, then runs)
make test-fapi2                 # private_key_jwt + DPoP (default)
make test-fapi2-sp-mtls-mtls   # tls_client_auth + mTLS
make test-fapi2-sp-mtls-dpop   # tls_client_auth + DPoP
make test-fapi2-sp-pk-mtls     # private_key_jwt + mTLS

# FAPI 2.0 Message Signing
make test-fapi2-ms             # private_key_jwt + DPoP + plain response
make test-fapi2-ms-jarm        # private_key_jwt + DPoP + JARM
make test-fapi2-ms-mtls        # tls_client_auth + mTLS + plain response
make test-fapi2-ms-mtls-jarm   # tls_client_auth + mTLS + JARM

# Groups
make test-fapi2-all            # All FAPI 2.0 variants
make test-all                  # Everything
```

## Debugging and Iteration

Test state is saved to `.last-run.json` after each run. Use these to iterate:

```bash
make rerun-failures                            # Rerun only failed modules
python3 scripts/debug.py failures              # Show failure details with HTTP exchanges
python3 scripts/debug.py log <module-name>     # Full log for one module
python3 scripts/debug.py log <module-name> -v  # Verbose (all entries, not just failures)
python3 scripts/debug.py status                # Status of all modules from last run
python3 scripts/debug.py vouch-logs            # Recent vouch Docker logs
python3 scripts/debug.py vouch-logs --grep error
make vouch-logs                                # Stream vouch logs
make restart-vouch                             # Rebuild + restart just vouch
```

Run a single module from a plan:
```bash
python3 scripts/run.py --plan <plan-name> --config <config-file> --module <module-name>
```

## Architecture

### Docker Services (docker-compose.yml)

| Service | Role | Ports |
|---------|------|-------|
| mongodb | Conformance suite state | internal |
| server | OpenID Conformance Suite (Spring Boot, devmode) | internal |
| nginx | TLS reverse proxy for conformance suite | 8443 |
| vouch | Vouch OIDC server under test | 3000 (HTTP) |
| vouch-proxy | TLS + mTLS proxy for vouch | 9443 (TLS), 9444 (mTLS) |

All services communicate on the `conformance-net` Docker network. The conformance suite reaches Vouch at `https://vouch-proxy` (the Docker-internal hostname).

### Python Scripts (scripts/)

- **run.py** — Main test runner. Creates plans via conformance API, starts modules, polls for completion, auto-dumps failure logs. Saves state to `.last-run.json`.
- **register_client.py** — Dynamic Client Registration against Vouch. Generates ES256 key pairs (FAPI2 private_key_jwt) and self-signed certs (FAPI2 mTLS). Outputs shell `export` statements consumed via `eval`.
- **conformance.py** — HTTP client for conformance suite REST API (`/api/plan`, `/api/runner`, `/api/info`, `/api/log`). Handles SSL for self-signed certs.
- **debug.py** — Debug helper reading `.last-run.json`. Subcommands: `failures`, `log`, `status`, `vouch-logs`.

### Config Templates (config/)

JSON files with placeholder tokens substituted at runtime by `run.py`:

| Placeholder | Source |
|-------------|--------|
| `{BASEURL}` | `--base-url` arg (default `https://vouch-proxy`) |
| `{CLIENT_ID}`, `{CLIENT_SECRET}` | From `register_client.py` or env vars |
| `{CLIENT_JWKS}` | Generated ES256 private JWKS (FAPI2) |
| `{MTLS_CERT}`, `{MTLS_KEY}` | Generated self-signed cert (FAPI2 mTLS) |
| `{VERSION}` | `--version` arg |

Each config has a `variant` object (test parameterization), `browser` array (Selenium-style automation for login/consent), and optional `override` map for per-module browser behavior.

### Conformance Suite (conformance-suite/)

Git submodule pointing to the OpenID Foundation conformance suite (Java/Spring Boot). Built with Maven via Docker. Has its own `CLAUDE.md` with detailed architecture docs. Read-only mirror of https://gitlab.com/openid/conformance-suite.

## Key Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `VOUCH_REPO_PATH` | `../vouch` | Path to vouch source for Docker build |
| `CONFORMANCE_SERVER` | `https://localhost.emobix.co.uk:8443` | Conformance suite URL |
| `VOUCH_URL` | `https://localhost:9443` | Vouch URL for client registration |
| `VOUCH_BASE_URL` | `https://vouch-proxy` | Vouch URL as seen by conformance suite |

## Cleanup

```bash
make down          # Stop services
make clean         # Remove containers, volumes, certs, build artifacts
```
