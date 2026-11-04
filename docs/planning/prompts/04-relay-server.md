<!-- Phase 4: relay server. Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md and the docs. **Phase 4: the studge-relay server, per SPEC.md.**

- axum + tokio. sqlx with SQLite, with migrations in relay/migrations. An optional `postgres` feature.
- OPAQUE registration and login with opaque-ke (ristretto255, Argon2id KSF). Create the OPAQUE ServerSetup key file on first run, at a path set in config. Never store it in the database.
- Sessions: 256-bit random tokens, stored as SHA-256 only. They expire after 24 h, are bound to a device and can be revoked.
- Implement every endpoint in SPEC §4. Vault head updates use compare-and-swap on the previous head hash.
- Limits:
  - maximum body size (1 MiB for ops)
  - maximum ops per request
  - per-IP and per-account rate limiting (tower_governor)
  - per-account storage quota (default 100 MiB, configurable)
- Configuration: a TOML file plus STUDGE_RELAY_* environment variables. Default listen address 127.0.0.1:8787.
- Logging: tracing, never with bodies or tokens. IP logging can be turned off in config. JSON log output is optional.
- Security headers. CORS allows only configured origins (the desktop app and extension IDs). TLS terminates at a reverse proxy; document a Caddy example.
- A multi-stage Dockerfile running as a non-root user, and a docker-compose.yml with Caddy.
- docs/relay-api.md describing every endpoint, request and response.

Integration tests (reqwest against a relay spawned on a random port):
- register, login, wrong password
- token expiry and revocation
- append and fetch ops with cursors
- head compare-and-swap conflict
- quota exceeded
- rate limit hit
- another account's vault returns 404

Run every check, update PROGRESS.md with how to run the relay on Windows and in Docker, and commit with -s. Stop and report.
