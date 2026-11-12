# OWASP ASVS 4.0 Level 3 — relay compliance walk

> Phase 4 assessment of `studge-relay` against ASVS 4.0 Level 3. Each requirement is
> marked **MET**, **N/A** (not applicable to an API server with no browser surface),
> or **OPEN** (with a tracking reference). All OPEN items have GitHub issues.

---

## V1 Architecture, design and threat modelling

| # | Requirement | Status | Notes |
| --- | --- | --- | --- |
| 1.1.1 | Verify use of a secure SDLC | MET | AGENTS.md mandates threat model, self-attack review, security bar |
| 1.1.2 | Threat modelling | MET | `docs/THREAT_MODEL.md`, A1–A8 with mitigations |
| 1.1.3 | Design and security review before implementation | MET | SPEC.md reviewed by founder before any code |
| 1.1.6 | Centralized authentication | MET | All authentication in `extract.rs` Session extractor |
| 1.1.7 | Established security controls, not homebrew | MET | Only approved-list crates (AGENTS.md rule 1) |
| 1.2.1 | Unique low-privilege service account | MET | Docker image runs as `nobody`; process has no write access outside `/data` |
| 1.2.3 | Strong authentication mechanisms | MET | OPAQUE (ristretto255, Argon2id KSF); session tokens as SHA-256 hashes |
| 1.4.1 | Trusted enforcement points | MET | All enforcement in the relay; no client-enforced gate exists |
| 1.4.4 | Access decisions use the same module | MET | `Session` extractor is the single auth path |
| 1.5.1 | Input and output requirements | MET | SPEC §7.6; `extract.rs` validates before any work |
| 1.5.3 | Output encoding requirements | MET | `deny_unknown_fields`, strict CBOR re-encode check |
| 1.5.4 | Output encoding prevents injections | MET | No templating, no SQL string interpolation (sqlx bind params) |
| 1.6.1 | Key management policy | MET | SPEC §4, DECISIONS.md D-04xx |
| 1.6.2 | Key material not shared | MET | OPAQUE setup key in a separate file, 0600; never in the database |
| 1.6.4 | Cryptographic keys replaceable | MET | OPAQUE setup key is a file; vault keys wrap independently |
| 1.9.1 | Secure communication | MET | Reverse-proxy TLS; docs provide a Caddy example |
| 1.10.1 | Source code management | MET | GitHub; branch protection; PR required; signed commits |

---

## V2 Authentication

| # | Requirement | Status | Notes |
| --- | --- | --- | --- |
| 2.1.1 | Password minimum length | MET | OPAQUE takes `auth_secret = HKDF(MUK, …)` — a uniform 256-bit value |
| 2.1.5 | Password reset via email | N/A | No email-based reset; recovery is via the Secret Key (Phase 12) |
| 2.1.12 | Credential paste allowed | N/A | OPAQUE hides the credential; no paste-block possible |
| 2.2.1 | Brute-force mitigations | MET | 10/hour/account, 60/hour/IP; dummy exchange for unknown accounts |
| 2.2.2 | Anti-automation | MET | Rate limits per IP and per account, fixed-window counters |
| 2.2.3 | Account lockout notification | OPEN | R-0401: relay does not send email; notifications are a Phase 8/13 feature. Issue #46. |
| 2.2.4 | Auth bypass for testing disabled | MET | No test backdoors; `--test` flags do not exist |
| 2.3.1 | Initial credential strength | MET | OPAQUE enforces no initial credential; client enforces zxcvbn ≥ 3 (Phase 7) |
| 2.7.1 | OTP lookup code brute-force limited | N/A | No OTP on the relay; TOTP is client-side only |
| 2.8.1 | Session token entropy | MET | 256-bit OsRng; stored as SHA-256 |
| 2.8.2 | Token transmitted securely | MET | TLS-only; `Authorization` header, no cookie |
| 2.8.3 | Token not stored in logs | MET | `tracing` never logs headers or tokens; lint rule in place |
| 2.8.4 | Token expires | MET | 24-hour hard expiry; sweeper deletes expired rows |
| 2.8.5 | Session revocable | MET | `DELETE /v1/sessions/current`; device revocation deletes sessions |
| 2.8.6 | Inactivity timeout | OPEN | R-0402: no sliding inactivity window; tokens expire after 24 h regardless. Accepted for v1 (D-0112). |
| 2.8.7 | Session binding | MET | Token is bound to `(account_id, device_id)`; checked on every request |

---

## V3 Session management

| # | Requirement | Status | Notes |
| --- | --- | --- | --- |
| 3.2.1 | New token on login | MET | New 256-bit token per `login/finish` |
| 3.2.2 | Token unpredictable | MET | OsRng; 256 bits |
| 3.2.3 | Token not logged | MET | Tracing logs never include token values |
| 3.2.4 | Sufficient entropy | MET | 256 bits = ~2^256 guessing space |
| 3.3.1 | Logout invalidates server-side | MET | `DELETE sessions WHERE token_hash = ?` |
| 3.3.2 | Token idle timeout | OPEN | R-0402 (same as 2.8.6 above) |
| 3.5.2 | Token transmitted only in headers | MET | `Authorization: Bearer`; no query-string tokens |
| 3.7.1 | Step-up for sensitive actions | N/A | OPAQUE authentication is already the strongest available; no lower-assurance path exists |

---

## V4 Access control

| # | Requirement | Status | Notes |
| --- | --- | --- | --- |
| 4.1.1 | Enforce access control server-side | MET | Every authenticated handler uses the `Session` extractor |
| 4.1.2 | Deny by default | MET | Unauthenticated requests are `401`; unknown paths are `404` |
| 4.1.3 | Principle of least privilege | MET | A session can only access its own account's data; no cross-account path exists |
| 4.1.5 | Access control failures are logged | MET | `tracing::warn!` on rate-limit; auth failures return 401 silently (no enumeration) |
| 4.2.1 | Sensitive data behind authorization | MET | Every `/v1/*` endpoint requires a valid session |
| 4.2.2 | Directory browsing disabled | N/A | No file-serving |
| 4.3.1 | Admin consoles restricted | N/A | No admin UI |

---

## V5 Validation, sanitisation and encoding

| # | Requirement | Status | Notes |
| --- | --- | --- | --- |
| 5.1.1 | No HTTP parameter pollution | MET | axum parses exactly one body; query params are strict structs |
| 5.1.2 | Framework protects against mass-assignment | MET | `#[serde(deny_unknown_fields)]` on every request struct |
| 5.1.3 | Input validation on all trusted boundaries | MET | `extract.rs` validates every field before any handler logic |
| 5.1.4 | Structured data validated against schema | MET | CBOR validated with the strict `parse_strict` re-encode check |
| 5.2.1 | Sanitize against OS command injection | MET | No shell invocations |
| 5.2.3 | XSS escape context-aware | N/A | API-only, no HTML rendering |
| 5.3.1 | Output encoding for context | N/A | JSON only; no HTML/SQL template output |
| 5.3.4 | Data selection prevents injection | MET | sqlx bind parameters; no string interpolation in queries |
| 5.5.1 | Serialisation deserialisation safety | MET | `ciborium` with strict re-encode; serde with `deny_unknown_fields` |

---

## V6 Cryptography

| # | Requirement | Status | Notes |
| --- | --- | --- | --- |
| 6.2.1 | No weak primitives | MET | Only AGENTS.md approved-list crates; OpenSSL banned |
| 6.2.2 | Approved algorithms | MET | XChaCha20-Poly1305, HKDF-SHA256, Ed25519, OPAQUE (SPEC §11) |
| 6.2.3 | Verified against NIST | MET | Known-answer vectors in `core/tests/vectors/v1.json` |
| 6.2.5 | No insecure random | MET | Only OsRng; no software fallback |
| 6.2.6 | Nonce reuse impossible | MET | 24-byte XChaCha20 nonces from OsRng |
| 6.2.7 | Deprecated algorithms rejected | MET | `v1` suite only; unknown versions are hard errors |
| 6.3.1 | CSPRNG | MET | `OsRng` from `rand_core`/`getrandom` |
| 6.3.2 | Random entropy ≥ 128 bits | MET | 256-bit session tokens, 128-bit vault ids, 192-bit nonces |
| 6.4.1 | Key management | MET | SPEC §4.12, DECISIONS.md D-04xx |
| 6.4.2 | Key storage | MET | OPAQUE file 0600; session tokens never written to disk as plaintext |

---

## V7 Error handling and logging

| # | Requirement | Status | Notes |
| --- | --- | --- | --- |
| 7.1.1 | No credentials or sensitive data in logs | MET | Tracing logs only operation names and rate-limit events |
| 7.1.2 | No PII in logs by default | MET | IP logging can be disabled in `[logging] log_ip = false` |
| 7.2.1 | Error handling prevents information leakage | MET | Generic error codes; no stack traces; no account enumeration |
| 7.3.1 | Logging system cannot be injected | MET | Log values are typed (Rust `tracing` macros); no format-string injection |
| 7.4.1 | Error in context of security does not return detail | MET | `401 unauthorized` for everything authentication-related |

---

## V8 Data protection

| # | Requirement | Status | Notes |
| --- | --- | --- | --- |
| 8.1.1 | Sensitive data not cached | MET | `Cache-Control: no-store` on every response |
| 8.1.2 | Directory listing off | N/A | No file-serving |
| 8.2.2 | Sensitive data not in query strings | MET | Tokens are in headers; no sensitive data in URLs |
| 8.3.1 | Sensitive data not in HTTP GET | MET | Authenticated GETs are read-only; no sensitive data in query strings |
| 8.3.4 | Sensitive data identified and classified | MET | SPEC §3.2 and AGENTS.md rule 8 enumerate what the relay must never receive |

---

## V9 Communication

| # | Requirement | Status | Notes |
| --- | --- | --- | --- |
| 9.1.1 | TLS required | MET | Caddy terminates TLS; relay binds loopback only |
| 9.1.2 | Valid TLS certificates | MET | Caddy handles ACME certificates automatically |
| 9.1.3 | Modern cipher suites | MET | Caddy defaults; TLS 1.3 preferred |
| 9.2.1 | Connections to backends use TLS | N/A | SQLite is a local file; no backend connections |
| 9.2.2 | Authenticated backend connections | N/A | Same |

---

## V10 Malicious code

| # | Requirement | Status | Notes |
| --- | --- | --- | --- |
| 10.2.2 | No secret data in source | MET | `gitleaks` in CI; no secrets committed |
| 10.3.1 | No auto-updating functionality | MET | Binary is manually deployed; no self-updater |

---

## V11 Business logic

| # | Requirement | Status | Notes |
| --- | --- | --- | --- |
| 11.1.1 | Flow control enforces business rules | MET | OPAQUE two-step is enforced in order; login state is consumed exactly once |
| 11.1.4 | Anti-automation limits | MET | Rate limits per IP and account |
| 11.1.5 | Business logic limits | MET | 100 ops per push, quota per account |

---

## V12 Files and resources

| # | Requirement | Status | Notes |
| --- | --- | --- | --- |
| 12.1.1 | Stored files not executable | N/A | No file upload |
| 12.3.1 | Path traversal prevention | N/A | No file path inputs from users |

---

## V13 API and web services

| # | Requirement | Status | Notes |
| --- | --- | --- | --- |
| 13.1.1 | Same ASVS controls for APIs | MET | All controls implemented in `relay/src/` |
| 13.1.2 | Avoid exposing management APIs | MET | No admin endpoint; `/health` is read-only |
| 13.1.3 | Not using security-obscurity as control | MET | All security is cryptographic |
| 13.2.1 | RESTful HTTP verbs | MET | Separate routes for GET, POST, PUT, DELETE |
| 13.2.2 | JSON schema validation | MET | `deny_unknown_fields` + explicit type validation |
| 13.2.5 | REST services verify Content-Type | MET | JSON and CBOR media types are checked before parsing |
| 13.3.1 | Typed binding for XML/JSON | MET | serde with `deny_unknown_fields`; no untyped parsing |

---

## V14 Configuration

| # | Requirement | Status | Notes |
| --- | --- | --- | --- |
| 14.1.1 | Dependency scanner in CI | MET | `cargo audit` weekly, `cargo deny` on every PR |
| 14.1.2 | Release builds are hardened | MET | `opt-level=3`, strip symbols in Docker image |
| 14.1.3 | Review of third-party components | MET | `deny.toml` allowlist; every crate version pinned with justification |
| 14.2.1 | No unnecessary features | MET | Minimal feature flags; no debug or admin backdoors |
| 14.3.1 | Disable default error handling | MET | Generic errors, no stack traces |
| 14.4.1 | All HTTP responses include Content-Type | MET | axum sets Content-Type on every response |
| 14.4.2 | All security headers present | MET | Middleware adds all five required headers on every response |
| 14.4.6 | CSP | MET | `Content-Security-Policy: default-src 'none'` |
| 14.5.1 | Authorized HTTP methods enforced | MET | axum routing enforces method; unknown methods return 405 |

---

## Open items summary

| Risk ID | Requirement(s) | Issue | Description |
| --- | --- | --- | --- |
| R-0401 | 2.2.3 | #46 | No email notification on account lockout. Accepted for v1; Phase 8 adds notifications. |
| R-0402 | 2.8.6, 3.3.2 | — | No sliding inactivity timeout; 24-hour hard expiry only. Accepted (D-0112); revisit in Phase 8. |
