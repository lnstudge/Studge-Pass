# Studge Pass relay API (v1)

> Reference for `studge-relay` as implemented in Phase 4. The relay is **treated
> as an attacker**: it stores only ciphertext, public metadata and OPAQUE records.
> See SPEC §7 and `docs/THREAT_MODEL.md` for the security properties.

## Contents

1. [Transport and conventions](#1-transport-and-conventions)
2. [Authentication](#2-authentication)
3. [Error model](#3-error-model)
4. [Rate limits and quotas](#4-rate-limits-and-quotas)
5. [Registration](#5-registration)
6. [Login and sessions](#6-login-and-sessions)
7. [Account](#7-account)
8. [Devices](#8-devices)
9. [Vaults — operations](#9-vaults--operations)
10. [Vaults — heads](#10-vaults--heads)
11. [Health](#11-health)
12. [curl / PowerShell examples](#12-curl--powershell-examples)

---

## 1. Transport and conventions

| Property | Value |
| --- | --- |
| TLS | TLS 1.3 preferred, 1.2 minimum (terminate at a reverse proxy; see [Caddy example](#caddy-example)) |
| Default listen | `127.0.0.1:8787` (loopback only; put Caddy in front for the public internet) |
| Versioned prefix | All endpoints live under `/v1`. |
| JSON bodies | `application/json; charset=utf-8`; parsed strictly with unknown fields rejected. |
| CBOR bodies | `application/cbor` for op arrays and vault heads. |
| Binary fields in JSON | Base64 (standard alphabet, padding) for OPAQUE blobs; hex for ids and hashes. |
| Request body cap | 8 MiB absolute limit enforced before routing. |
| Request timeout | 30 s (configurable; enforced even for long-running handlers). |
| Unknown path/method | `404 {"error":"not_found"}` — same shape as every error. |
| Security headers | `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'`. |

---

## 2. Authentication

Send `Authorization: Bearer <token>` on every authenticated endpoint.

- `token` is 64 lowercase hex characters (32 random bytes from OsRng, returned once at login).
- The relay stores only `SHA-256(token)` and compares in constant time.
- Tokens expire 24 hours after creation.
- A token for a revoked device is rejected and deleted immediately.
- A token for a tombstoned account is rejected with `403 forbidden`.

Omitting the header, sending an unrecognisable header, or sending an expired or revoked token all
return `401 {"error":"unauthorized"}`. No message distinguishes these cases.

---

## 3. Error model

Every error response is `{"error": "<code>"}` — one field, no stack traces, no
request ids, no account identifiers echoed.

| HTTP status | `error` string | When |
| --- | --- | --- |
| 400 | `invalid_request` | Malformed input: unknown field, bad hex/base64, wrong media type, out-of-range value, missing required field. |
| 401 | `unauthorized` | Missing/bad/expired/revoked token, or wrong OPAQUE credentials. |
| 403 | `forbidden` | Authenticated but blocked: the account has been tombstoned. |
| 404 | `not_found` | No such path, vault not found, or vault belongs to another account (intentionally indistinguishable). |
| 409 | `conflict` | Duplicate `(vault_id, op_id)` with different bytes, head CAS mismatch, duplicate `account_id`. |
| 413 | `too_large` | Body over the per-endpoint cap (head > 16 KiB, op body > 1 MiB). |
| 429 | `rate_limited` | Exceeded a per-IP or per-account rate limit. Includes `Retry-After: <seconds>`. |
| 507 | `quota_exceeded` | Account's total storage would exceed the configured limit (default 100 MiB). |
| 503 | `unavailable` | Database or system call failed; retry with back-off. |

---

## 4. Rate limits and quotas

All limits are checked before any expensive work and logged without request content.

| Limit | Default | Config key |
| --- | --- | --- |
| Registrations per IP per hour | 5 | `register_per_ip_hour` |
| Login attempts per account per hour | 10 | `login_per_account_hour` |
| Login attempts per IP per hour | 60 | `login_per_ip_hour` |
| Op pushes per account per minute | 60 | `push_per_account_minute` |
| Reads per account per minute | 300 | `read_per_account_minute` |
| Ops per push request | 100 | `max_ops_per_push` |
| Storage per account | 100 MiB | `storage_quota_bytes` |
| Op body | 1 MiB + 4 KiB (overhead) | (fixed) |
| Vault head | 16 KiB | (fixed) |

Rate counters use a fixed window (one bucket per `floor(unix_seconds / window)`) and reset
automatically. Quota is total stored-byte usage; deleting the account clears it.

---

## 5. Registration

Registration is a two-message OPAQUE flow (SPEC §7.2). The client generates
`account_id`, `account_salt`, the Account Key and identity keys locally; none of them
reach the relay in the clear.

### `POST /v1/register/start`

**No auth required.** Rate-limited by IP.

**Request** `application/json`:
```json
{
  "account_id": "<32 hex chars — 16-byte UUID>",
  "registration_request": "<base64 — OPAQUE RegistrationRequest>"
}
```

**Response `200`** `application/json`:
```json
{
  "registration_response": "<base64 — OPAQUE RegistrationResponse>"
}
```

**Errors:** `400 invalid_request` (bad fields), `429 rate_limited`.

> The relay does **not** check whether the account exists; the response is identical
> for a new and an existing `account_id`. Account existence is only revealed at `/finish`.

---

### `POST /v1/register/finish`

**No auth required.**

**Request** `application/json`:
```json
{
  "account_id": "<32 hex>",
  "registration_upload": "<base64 — OPAQUE RegistrationUpload>",
  "account_record": {
    "account_id": "<32 hex>",
    "account_salt": "<32 hex — 16-byte random>",
    "kdf": { "version": 1, "m": 65536, "t": 3, "p": 1 },
    "ak_envelope": "<base64 — AEAD-encrypted Account Key>",
    "bundle_envelope": "<base64 — AEAD-encrypted key bundle>",
    "identity_keys": {
      "ed25519": "<64 hex — 32-byte public key>",
      "x25519": "<64 hex — 32-byte public key>",
      "mlkem768": "<2368 hex — 1184-byte encapsulation key>"
    },
    "version": 1
  },
  "first_device": {
    "device_id": "<32 hex>",
    "device_pubkey": "<64 hex — Ed25519 device public key>",
    "certificate": "<base64 — DeviceCertificate CBOR>"
  }
}
```

**Validation rules:**
- `account_id` in body and in `account_record` must agree.
- `kdf.m ≥ 65536`, `kdf.t ≥ 3`, `kdf.p ≥ 1`, `kdf.version = 1`.
- `account_record.version = 1`.
- The device certificate must verify against `identity_keys.ed25519`; `device_pubkey`
  and `device_id` in the certificate must match `first_device`.

**Response `201`** `application/json`:
```json
{ "account_id": "<32 hex>" }
```

**Errors:** `400 invalid_request`, `409 conflict` (duplicate `account_id`).

---

## 6. Login and sessions

Two-message OPAQUE login (SPEC §7.3). An unknown or tombstoned account receives a
dummy exchange: response shape and timing are identical; only `/finish` fails (SPEC D-0113).

### `POST /v1/login/start`

**No auth required.** Rate-limited by account id and IP.

**Request** `application/json`:
```json
{
  "account_id": "<32 hex>",
  "device_id": "<32 hex>",
  "credential_request": "<base64 — OPAQUE CredentialRequest>"
}
```

**Response `200`** `application/json`:
```json
{ "credential_response": "<base64 — OPAQUE CredentialResponse>" }
```

**Errors:** `400 invalid_request`, `429 rate_limited`.

---

### `POST /v1/login/finish`

**No auth required.**

**Request** `application/json`:
```json
{
  "account_id": "<32 hex>",
  "device_id": "<32 hex>",
  "credential_finalization": "<base64 — OPAQUE CredentialFinalization>"
}
```

**Response `200`** `application/json`:
```json
{
  "token": "<64 lowercase hex — 32 random bytes, returned once>",
  "expires_at": "2026-11-07T04:00:00Z"
}
```

**Errors:** `400 invalid_request`, `401 unauthorized` (wrong password, unknown account,
replayed finalization, revoked device — all identical).

---

### `DELETE /v1/sessions/current`

**Auth required.** Revokes the caller's own session immediately (SPEC D-0112).

**Response `204`** (no body).

---

## 7. Account

### `GET /v1/account`

**Auth required.** Returns the stored account record exactly as it was written.

**Response `200`** `application/json`: the full `account_record` object (same shape as
the `account_record` field in `/register/finish`).

---

### `PUT /v1/account`

**Auth required.** Replaces the account record (password change, KDF upgrade, new
key bundle). Uses optimistic concurrency: the client reads the version from the current
record and sends it as `If-Match`.

**Request** `application/json`:
```json
{
  "account_record": { ...full account record... }
}
```

**Headers:** `If-Match: <version>` — the `version` field from the current record (integer).

**Response `200`** (no body on success).

**Errors:** `400 invalid_request`, `409 conflict` (version mismatch — re-read and retry).

---

### `DELETE /v1/account`

**Auth required.** Tombstones the account; all rows are purged within 24 hours.

**Request** `application/json`:
```json
{ "confirmation": "delete" }
```

The literal string `"delete"` is required to prevent accidental deletion.

**Response `202`** (no body; deletion is asynchronous).

---

## 8. Devices

### `POST /v1/devices`

**Auth required.** Certifies a new device. The relay verifies the certificate against
the account's pinned identity key and that the enrolment proof binds to this account
and device (SPEC §4.7, D-0107).

**Request** `application/json`:
```json
{
  "certificate": "<base64 — DeviceCertificate CBOR>",
  "device_pubkey": "<64 hex — Ed25519 device public key>",
  "enrolment_proof": "<base64 — EnrolmentProof CBOR>"
}
```

**Response `201`** `application/json`:
```json
{ "device_id": "<32 hex>" }
```

**Errors:** `400 invalid_request` (bad certificate or proof), `409 conflict` (device
id already registered).

---

### `DELETE /v1/devices/{device_id}`

**Auth required.** Revokes a device. The caller must send a signed revocation record
(SPEC §4.8). The relay verifies the record's structure and that the signer is the
account's identity key, then marks the device revoked and deletes its sessions.

A device may revoke itself ("sign out everywhere else").

**Request** `application/json`:
```json
{ "revocation_record": "<base64 — DeviceRevocation CBOR>" }
```

**Response `200`** (no body).

**Errors:** `400 invalid_request` (bad revocation record).

---

## 9. Vaults — operations

### `POST /v1/vaults/{vault_id}/ops`

**Auth required.** Appends a batch of ops. Rate-limited per account.

**Request** `application/cbor`: a CBOR array of at most 100 stored-op byte strings.

Each op is validated: canonical CBOR, exact field set, `parents ≤ 16`, parents sorted
and unique, `lamport ≥ 1`, `created_at` within ±24 h of server time (SPEC §7.6).
Op bytes are stored exactly as received; the relay does not re-encode them.

**Idempotency:** re-sending the same bytes for an existing `(vault_id, op_id)` is
silently accepted. Re-sending different bytes under the same `op_id` is `409`.

**Response `200`** `application/json`:
```json
{
  "accepted": 12,
  "rejected": [
    { "op_id": "<64 hex>", "reason": "too_large" }
  ],
  "head": "<64 hex — current head hash, or empty string if none>"
}
```

**Errors:** `400 invalid_request`, `409 conflict`, `413 too_large`, `429 rate_limited`,
`507 quota_exceeded`.

---

### `GET /v1/vaults/{vault_id}/ops`

**Auth required.** Fetches ops in topological order (parents before children).

**Query parameters:**

| Parameter | Default | Notes |
| --- | --- | --- |
| `limit` | 100 | Clamped to 1–1000. |
| `since` | — | The last `op_hash` returned in a previous page (64 hex chars). |

**Response `200`** `application/cbor`: a CBOR map `{"ops": [<op bytes>, …]}`.

When more ops follow, the response includes `Next-Cursor: <op_hash hex>`. Re-fetch with
`since=<that hash>`. If `since` references an unknown hash, the relay returns `400`.

A client that loses its cursor may re-fetch from the beginning and re-verify; correctness
never depends on the cursor.

---

## 10. Vaults — heads

### `GET /v1/vaults/{vault_id}/head`

**Auth required.** Returns the current vault head.

**Response `200`** `application/json`:
```json
{
  "head": "<base64 — VaultHead CBOR bytes>",
  "head_hash": "<64 hex — BLAKE3 of the head>"
}
```

**Errors:** `404 not_found` (no vault or vault has no head yet).

---

### `PUT /v1/vaults/{vault_id}/head`

**Auth required.** Compare-and-swap the vault head. This is a **lost-update guard**,
not a security control (SPEC §6.8).

**Request** `application/cbor`: the new `VaultHead` CBOR bytes.

**Headers:** `If-Match: <head_hash hex>` — the hex hash of the head being replaced.
Use `*` for the very first head. Omitting `If-Match` is `400`.

**Response `200`** `application/json`:
```json
{
  "head_hash": "<64 hex>",
  "op_count": 42,
  "lamport_max": 55
}
```

**Errors:** `400 invalid_request`, `409 conflict` (head hash mismatch — re-read the
current head and retry).

---

## 11. Health

### `GET /health`

**No auth.** Always reachable, even when auth middleware rejects other requests.

**Response `200`** `application/json`:
```json
{ "status": "ok", "version": "0.1.0" }
```

---

## 12. curl / PowerShell examples

These examples assume the relay is running at `http://127.0.0.1:8787`.

### Check health

```powershell
Invoke-RestMethod http://127.0.0.1:8787/health
```

```bash
curl http://127.0.0.1:8787/health
```

### Register (start) — raw hex values are placeholders

```bash
curl -s http://127.0.0.1:8787/v1/register/start \
  -H "Content-Type: application/json" \
  -d '{"account_id":"aabbccddeeff00112233445566778899","registration_request":"<base64>"}'
```

### Login (start)

```bash
curl -s http://127.0.0.1:8787/v1/login/start \
  -H "Content-Type: application/json" \
  -d '{"account_id":"aabbccddeeff00112233445566778899","device_id":"11223344556677889900aabbccddeeff","credential_request":"<base64>"}'
```

### Fetch ops (paginated)

```bash
# First page
curl -s "http://127.0.0.1:8787/v1/vaults/vaultid_32_hex_chars/ops?limit=50" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/cbor"

# Next page
curl -s "http://127.0.0.1:8787/v1/vaults/vaultid_32_hex_chars/ops?limit=50&since=$CURSOR" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/cbor"
```

### Logout

```bash
curl -s -X DELETE http://127.0.0.1:8787/v1/sessions/current \
  -H "Authorization: Bearer $TOKEN"
```

---

## Caddy example

Place this in `Caddyfile` (Caddy 2.9+). The relay handles auth; Caddy terminates TLS.

```caddy
relay.example.com {
    encode gzip

    # Forward everything to the relay's loopback listener.
    reverse_proxy 127.0.0.1:8787

    # TLS-only security headers (the relay sets the application-level ones).
    header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
}
```

Run the relay with `STUDGE_RELAY_CONFIG=/etc/studge-relay/relay.toml studge-relay`.
See the [relay configuration reference](../relay/README.md) for all TOML keys.

---

## Running in Docker

See [`docker-compose.yml`](../docker-compose.yml) for the full stack (relay + Caddy).

```bash
# Build the image
docker build -t studge-relay .

# Quick smoke test
docker run --rm -p 8787:8787 studge-relay
curl http://localhost:8787/health
```

For production: mount a persistent volume at `/data` for the SQLite database and the
OPAQUE server-setup key file. The relay runs as a non-root user (`nobody`) inside the
image.
