## Phase 4: studge-relay

Closes #10

Implements the full zero-knowledge relay server per SPEC §7: OPAQUE registration and login, sessions, account/device management, vault ops (append-only) and vault heads (compare-and-swap).

### What's in this PR

| Area | Detail |
|---|---|
| Endpoints | All SPEC §7.4 endpoints (`POST /v1/register/start`, `.../finish`, `POST /v1/login/start`, `.../finish`, `DELETE /v1/session`, `GET /v1/account`, `POST /v1/devices`, `DELETE /v1/devices/{id}`, `POST /v1/vaults/{id}/ops`, `GET /v1/vaults/{id}/ops`, `GET /v1/vaults/{id}/head`, `PUT /v1/vaults/{id}/head`, `GET /health`) |
| OPAQUE | Registration and login via `opaque-ke v4.0.1` (ristretto255, KSF=Identity); server setup key never stored in database |
| Sessions | 24-hour bearer tokens, rate-limited per account and per IP |
| Storage | SQLite with `sqlx`; two migrations (accounts/devices/sessions/vaults/ops, login_states); append-only ops table |
| Zero-knowledge | Relay stores only ciphertext; SPEC §7.11 verified: relay never receives master password, Secret Key, MUK, auth secret, or plaintext item data |
| Security headers | `x-content-type-options`, `cache-control: no-store`, `referrer-policy`, `x-frame-options`, `content-security-policy` on every response |
| CORS | Strict allowlist via `CorsLayer` (no wildcard); configured via `[cors] allowed_origins` or `STUDGE_RELAY_CORS_ORIGINS`; omitted when empty |
| Rate limiting | `tower_governor` per-account and per-IP limiters on registration, login, push and read endpoints |
| Body limit | 8 MiB hard limit via `RequestBodyLimitLayer` |
| Request timeout | 30 s configurable timeout; stalled requests return `503 unavailable` |
| Config | TOML file + `STUDGE_RELAY_*` env overrides; strict reject-unknown policy |
| Deployment | Multi-stage `Dockerfile`, `docker-compose.yml`, `Caddyfile` reverse-proxy config |

### Tests

**301 passed, 0 failed, 2 ignored** across all workspace crates.

- 233 core unit tests
- 29 relay unit tests (config, error model, security headers, CORS wiring)
- 11 relay integration tests (full HTTP flows via `reqwest` against a real in-process relay)
- 28 other crate tests

### Docs added

- `docs/relay-api.md` — full API reference with request/response shapes
- `docs/relay-asvs.md` — OWASP ASVS 4.0 Level 3 walk
- `docs/THREAT_MODEL.md §18` — Phase 4 self-attack review (14 attack vectors, 12 blocked, 3 open risks + 1 new R-0405)

### Cargo deny

`advisories ok, bans ok, licenses ok, sources ok`

One advisory ignored: **RUSTSEC-2026-0387** — timing side-channel in `crypto-bigint 0.5.5` (transitive via `opaque-ke v4.0.1`). Not a plaintext-exposure flaw. Blocked on upstream release. Documented as R-0405 in `THREAT_MODEL.md`.

### Known gaps (follow-up issues)

- `relay_tour` runnable demo (`relay/examples/relay_tour.rs`) — #follow-up
- Postgres parity (`postgres` feature flag) — #follow-up
- Preview dashboard Relay section — #follow-up

### Self-attack summary (THREAT_MODEL.md §18)

| # | Attack | Status |
|---|---|---|
| 1 | Replay a registration message | Blocked: nonce; Finish fails without matching Start |
| 2 | Skip registration, forge `/register/finish` | Blocked: no login_state row |
| 3 | Brute-force OPAQUE password offline | Blocked: server holds only `RegistrationRecord`; client holds `ExportKey` |
| 4 | Session token forgery | Blocked: 32-byte OsRng token; compare with `ct_eq` |
| 5 | Session replay after expiry | Blocked: `expires_at < now()` check |
| 6 | Push oversize op list | Blocked: `max_ops_per_push` + 8 MiB body limit |
| 7 | Push to vault not owned | Blocked: `account_id` from session, not request |
| 8 | Race CAS head update | Blocked: CAS with `expected_lamport` |
| 9 | Enumerate valid usernames via timing | Blocked: constant-time OPAQUE; generic error messages |
| 10 | Flood registration | Blocked: `register_per_ip_hour` rate limit (429) |
| 11 | Flood login (account) | Blocked: `login_per_account_hour` (10/hr → lock) |
| 12 | Inject CBOR ops with wrong format | Blocked: strict `parse_ops`; tamper tests |
| 13 | Malicious relay: read plaintext vault data | Blocked: client-side encryption; relay only sees ciphertext |
| 14 | Malicious relay: forge account identity key | Open: R-0404 (Phase 11 key transparency) |
