# Studge Pass protocol specification (v1)

> **Status:** Phase 1 draft, 2026-11-05. This document is normative for the
> Phase 2–12 implementations once the founder approves the items marked
> **PROPOSED**. Those items are collected in `docs/DECISIONS.md` (D-01xx); the
> brief that fixed the rest of the design is `docs/planning/prompts/01-spec-threat-model.md`.

## 1. Purpose, scope and status

### 1.1 What this document is

This is the wire-level and cryptographic design of Studge Pass v1: how
identities and keys are derived, how vault data is encrypted and authenticated,
how changes form a verifiable history, what the relay is allowed to see, and what
clients must check before they trust anything. It is the source of truth for
implementers. Later phase prompts cite it; tests enforce it.

### 1.2 Design goals

| # | Goal | Consequence in this design |
| --- | --- | --- |
| G1 | **Confidentiality against the relay.** The relay never sees plaintext, the master password, the Secret Key, or any key material. | Everything stored on the relay is ciphertext under keys derived on the client (§4, §5). |
| G2 | **Integrity and authenticity of every byte.** | Every ciphertext is AEAD with bound context (§5.2–5.3); every operation is signed by a certified device key (§6.3). |
| G3 | **Attack detection.** Clients detect modification, reordering, rollback, forking and substitution. | Signed heads, pinned heads on clients, DAG descent checks, per-record AAD (§6.8–6.9). |
| G4 | **No vendor recovery.** The vendor cannot recover a vault, even under compulsion. | The Secret Key never leaves the user's devices and printed recovery kit (§4.2, §10.1). |
| G5 | **Multi-device, offline-first.** Every device can work without the relay and reconcile later. | Operation log with a DAG and deterministic conflict resolution (§6). |
| G6 | **Bring-your-own storage.** Hosted relay, self-hosted relay, or any synced folder. | The sync layer is a `Transport` trait with http, folder and memory implementations (§7.10). |
| G7 | **One cipher suite, no legacy, no downgrade.** | Exactly one suite id, `v1`; unknown versions are rejected (§11.2). |
| G8 | **Auditability.** Small, well-known primitives only. | The crypto inventory in §11; no invented cryptography. |

### 1.3 Non-goals

- **Hiding metadata from the relay.** The relay learns account and vault
  identifiers, device identifiers, operation counts, ciphertext sizes, and
  request timing. §3.2 lists this precisely; §8 of the threat model records the
  residual risk. Hiding it would need padding and cover traffic, which this
  version does not specify.
- **Defending a device that is compromised while unlocked.** See adversary A6 in
  `docs/THREAT_MODEL.md` for why this is out of scope and what it would take.
- **Anonymity.** The relay necessarily learns the client's IP address (unless
  self-hosted or behind a proxy the user controls).
- **Deniability.** A user who can be compelled to reveal the master password and
  the Secret Key reveals the vault. There is no duress mode in v1.
- **Hiding the existence of an account.** Registration is visible to the relay.

### 1.4 Conformance language

`MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT` and `MAY` are used as in RFC 2119.
Two rules apply everywhere and are not repeated per clause:

1. **Strict parsing.** Unknown fields, unknown enum values, unknown suite ids and
   non-canonical CBOR are rejected. A parser MUST NOT silently drop or coerce
   them.
2. **Fail closed.** Any authentication, decryption, signature, hash or
   head-descent failure is a hard error for the affected record or operation. A
   client MUST NOT continue with partially verified state, MUST NOT "repair"
   data, and MUST NOT fall back to an older format.

## 2. Terminology

| Term | Meaning |
| --- | --- |
| **Account** | One user identity: an `account_id`, a master password, a Secret Key, and the encrypted key bundle stored on the relay. |
| **Device** | One installation of a Studge Pass client with its own Ed25519 device key, certified by the account identity key. |
| **Vault** | A named container of items, with its own 256-bit vault key (VK) and its own operation log. A user has at least one personal vault. |
| **Item** | One record in a vault (login, note, card, identity, Aadhaar/PAN/UPI template, …) with its own 256-bit item key (IK). |
| **Field** | One encrypted attribute of an item (username, password, URL, notes, …). Fields are encrypted individually with the field name bound in the AAD. |
| **Op** | One signed, immutable operation in a vault's operation log: create, update, delete, move, membership or key rotation (§6.1). |
| **DAG** | The directed acyclic graph formed by ops and their `parents` references (§6.4). |
| **Head** | A signed statement of a vault's current tips, total op count and maximum Lamport clock (§6.8). |
| **Pinned head** | The last head a client verified and stored locally; the anchor for rollback and fork detection (§6.9). |
| **Relay** | The untrusted sync server. Stores ciphertext, enforces quotas and authentication, never interprets payloads. |
| **Transport** | The client-side interface through which ops and heads move: HTTP relay, a folder in any synced directory, or memory for tests (§7.10). |
| **MUK** | Master Unlock Key: the 256-bit key derived from the master password and the Secret Key (§4.3). |
| **Auth secret** | The value derived from the MUK and used as the OPAQUE password (§4.4). |
| **AK** | Account Key: a random 256-bit key that encrypts the account's key bundle (§4.5). |
| **VK / IK** | Vault Key and Item Key: random 256-bit keys, each wrapping the next level (§4.9–4.10). |
| **Secret Key** | 128 random bits created on the first device and printed in the recovery kit, formatted `SP1-…` (§4.2). Never sent to the relay. |
| **Recovery kit** | The printable sheet holding the Secret Key and recovery instructions (§10.1). |
| **Guardian** | A person who holds one share of a 2-of-3 recovery split (§10.2). |
| **Safety code** | A short human-comparable digest of two public keys, used to detect key substitution (§9.4). |
| **Key transparency log** | An append-only, Merkle-tree-backed log of public identity keys with consistency proofs (§9.3). |
| **Suite** | The fixed set of algorithms identified by `v1` (§11.2). |
| **Envelope** | The stored form of one ciphertext: suite id, nonce, ciphertext (§5.2). |
| **AAD** | Additional authenticated data: the canonical context that binds a ciphertext to its place (§5.3). |
| **PROPOSED** | A detail this document adds beyond the Phase 1 brief, awaiting founder approval (listed in D-01xx). |

## 3. Trust model

### 3.1 Parties and what is trusted

| Party | Trusted for | Not trusted for |
| --- | --- | --- |
| **The user** | Knowing the master password; keeping the Secret Key and recovery kit safe. | Perfect password hygiene (Argon2id compensates, slowly). |
| **The user's devices** | Holding keys in memory while unlocked; running this specification. | Being malware-free (A6); being physically safe (A5). |
| **The relay** | Availability only. | Confidentiality, integrity, freshness, ordering, completeness. It is treated as a fully malicious attacker (A1). |
| **The network** | Nothing. TLS is used for the HTTP transport, but **correctness never depends on TLS**: every record is authenticated end-to-end. | Confidentiality beyond what TLS provides; integrity. |
| **Other vault members** | Following the protocol for their own devices. | Not reading data they were not granted; not writing valid-looking garbage into a vault they share (A3). |
| **Guardians** | Keeping one recovery share private. | Access to the vault before a recovery is completed (§10.2). |
| **The browser page** | Nothing. Pages are hostile (A4). | Anything about the user's origin, credentials or intent. |

### 3.2 What the relay can see

The relay stores and therefore knows:

- `account_id`, the account's public salt, and the AEAD-wrapped Account Key;
- the list of certified `device_id`s, their public keys, certificates and
  revocation records;
- vault identifiers and, per vault, the number and sizes of operations, their
  Lamport clocks, parent hashes, and the signed heads;
- ciphertext for every op and every key bundle;
- session metadata: token hashes, device binding, expiry, request times, IP
  addresses, user agent.

The relay **never** receives: the master password, any password-equivalent
hash, the Secret Key, the MUK, the auth secret, the Account Key in plaintext,
vault keys, item keys, plaintext item data, plaintext URLs, or the plaintext of
any field. §7.11 restates this as a normative list for implementers.

![Relay trust boundary: devices hold every key; the relay stores ciphertext and
wrapped keys only](diagrams/relay-trust-boundary.svg)

### 3.3 Assumptions

| # | Assumption | If it fails |
| --- | --- | --- |
| A-1 | The OS provides a cryptographically secure random source; clients use `OsRng` only. | Nonce or key reuse could be catastrophic; there is no software fallback by design. |
| A-2 | TLS protects the HTTP transport against passive observers and simple tampering. | The design still detects tampering (AEAD + signatures + heads), but request metadata and availability are exposed. |
| A-3 | The user's master password has some strength; Argon2id at 64 MiB / t=3 / p=1 makes guessing expensive but not impossible for weak passwords. | An attacker with the relay database and the Secret Key can test guesses offline; §4.3 and the threat model quantify this. |
| A-4 | A device that is unlocked and malware-free runs an unmodified client. | A6: out of scope. |
| A-5 | The relay's clock is roughly correct; clients' clocks may drift. | Revocation effective-times and token expiry degrade gracefully; see §4.8 and R-0107. |
| A-6 | At least one device or the printed kit survives the loss of any other device. | Recovery (§10) is the only path back; losing everything is unrecoverable by design (G4). |

### 3.4 Failure policy

Every client MUST treat the following as fatal for the record concerned, and
MUST surface a clear, non-technical error that says what failed and what to do:

- AEAD decryption or tag failure, including AAD mismatch;
- signature verification failure on an op, a head, a certificate or a
  revocation record;
- a head that does not descend from the pinned head (§6.9);
- a non-canonical encoding, an unknown field, an unknown suite or an
  out-of-range length;
- a decrypted payload whose inner type does not match the AAD `record_type`.

A client MUST NOT retry with weaker parameters, MUST NOT accept an older suite,
and MUST NOT continue syncing that vault until the user is told. Data already
verified locally remains usable offline.

## 4. Identities and keys

All randomness in this section comes from `OsRng`. All secrets live in zeroizing
buffers, are never formatted into logs or errors, and are dropped as soon as they
are no longer needed (§11.4).

### 4.1 Identifiers

| Identifier | Size | Generation | Notes |
| --- | --- | --- | --- |
| `account_id` | 16 bytes | UUIDv4 from `OsRng` at registration | Never derived from user data; immutable for the life of the account. |
| `device_id` | 16 bytes | UUIDv4 at first launch of a client | Bound into the device certificate. |
| `vault_id` | 16 bytes | UUIDv4 at vault creation | **PROPOSED** (the brief fixes account and device ids only; D-0109). |
| `item_id` | 16 bytes | UUIDv4 at item creation | Stable across devices; chosen by the creating device. **PROPOSED** (D-0109) |
| `op_id` | 16 bytes | UUIDv4 at op creation | Used for idempotency on the relay (§7.6). **PROPOSED** (D-0109) |

Identifiers are rendered as lowercase UUID strings with hyphens. Uniqueness
relies on 122 random bits; a client MUST reject a duplicate `op_id` with
different content (§6.1).

### 4.2 The Secret Key

**Material.** The Secret Key is **128 random bits** (16 bytes) from `OsRng`,
generated once on the first device and never changed for the life of the
account. It is shown once at creation, printed in the recovery kit, and stored
on each device in the OS keystore where one exists. Because 128 bits need 26
base32 characters (130 bits), the two most significant bits are always zero and
a decoder MUST reject a string where either is set.

**Encoding.** Crockford base32 (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`),
upper-case on display. On input, hyphens are ignored, lower-case is accepted, and
the Crockford confusions are normalised (`I`, `L` → `1`; `O` → `0`); the letters
`U` is not part of the alphabet and MUST be rejected.

**Printed form.**

```
SP1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XX
```

That is 27 characters after the `SP1-` prefix: five groups of five data
characters and a final group of two. The first twenty-six characters are the
key (130 bits with the two most significant bits fixed to zero); the last
character is a check character. The final group is therefore the 26th key
character followed by the check.

> **Decided (D-0101, option b).** The founder chose the full 128-bit key with a
> 27-character display rather than a 125-bit key in 26 characters. The printed
> shape above and the checksum below are the result.

**Checksum.** `c = BLAKE3("studge/v1/secret-key-checksum" || ASCII of the 26
key characters)`; the check character is `c[0] mod 32` rendered in the alphabet
above. Decoding MUST reject a string whose checksum does not match, whose length
is not 27 characters after the prefix, whose high two bits are set, or which
contains a character outside the alphabet after normalisation.

**Rules.**

- The Secret Key MUST NOT be sent to the relay, embedded in any request, or
  derived into anything the relay sees.
- It MUST NOT be written to logs, crash reports, analytics or error messages.
- Losing it while keeping the master password still allows unlocking on a
  device that has it stored; losing both is unrecoverable by design (G4).
- It is displayed only at creation and from an explicit “show recovery kit”
  action that requires the master password.

### 4.3 Master Unlock Key (MUK)

**Salt.** `account_salt` is 16 random bytes generated on the client at
registration and stored in clear on the relay. It is public by design: its only
job is to make precomputation attacks account-specific.

**Argon2id.**

```
A = Argon2id(P = UTF8(NFKC(master_password)),
             S = account_salt,
             m = 65536 KiB, t = 3, p = 1, version = 0x13,
             tagLen = 32)
```

**MUK.**

```
ikm = A (32 bytes) || secret_key (16 bytes)      // 48 bytes
MUK = HKDF-SHA256(ikm = ikm, salt = "", info = "studge/v1/muk", L = 32)
```

**Versioning.** The account record stores `kdf = {version: 1, m, t, p}`. A
client MUST reject parameters weaker than the values above (no downgrade) and
MUST reject unknown versions. Raising parameters is a normal, forward-only
upgrade: the client re-derives the MUK with the new parameters and re-wraps the
Account Key (§4.12); the old parameters are then deleted.

**Why the Secret Key is concatenated into the HKDF input.** Argon2id output
alone is crackable offline by anyone who steals the relay database and knows the
salt. Mixing in 128 bits that never reach the relay means an attacker needs both
the database *and* the Secret Key before guessing a password is even possible.

### 4.4 Authentication secret (OPAQUE)

```
auth_secret = HKDF-SHA256(ikm = MUK, salt = "",
                          info = "studge/v1/opaque-password", L = 32)
```

`auth_secret` is the password input to OPAQUE (`opaque-ke`, ristretto255 OPRF,
`argon2` KSF). Because it is already a uniform 256-bit value, the KSF inside
OPAQUE is the **identity** KSF: stretching happened once, in §4.3, and doing it
twice would only hurt unlock time. This is a **PROPOSED** detail (D-0102).

Consequences:

- The relay stores an OPAQUE registration record from which the password cannot
  be recovered, and it never sees `auth_secret`.
- An attacker with the relay database cannot run a password-guessing campaign
  without also having the Secret Key, because `auth_secret` depends on the MUK.
- A wrong password fails at OPAQUE login, before any key material is touched.

### 4.5 Account Key (AK) and the key bundle

**AK** is 32 random bytes generated at registration.

**Wrapping key.**

```
k_ak = HKDF-SHA256(ikm = MUK, salt = "", info = "studge/v1/ak-wrap", L = 32)
AK_env = AEAD(k_ak, AK, nonce = 24 random bytes,
              aad = CBOR{suite: "v1", scope: account_id, record_type: "ak", schema_version: 1})
```

The brief writes this as `AEAD(MUK, AK, …)`; v1 derives `k_ak` first so that no
key is ever used for two purposes (AGENTS.md rule 3). This is a **PROPOSED**
clarification (D-0103).

**Key bundle.** A CBOR map, encrypted under
`k_bundle = HKDF(AK, salt = account_id, info = "studge/v1/key-bundle")`, holding:

| Entry | Contents |
| --- | --- |
| `identity_signing` | Ed25519 private key (§4.6) |
| `identity_encryption` | X25519 private key (§4.6) |
| `identity_kem` | ML-KEM-768 private key (§4.6) |
| `head_pins` | Last verified head per vault (§6.9), as a hint for new devices |
| `device_list` | Certified devices and revocations (§4.7–4.8) |
| `bundle_version` | `1` |

Each entry is its own AEAD envelope with `record_type = "bundle/<entry>"` and
the entry name in the AAD, so entries cannot be swapped or dropped silently. The
bundle is versioned; unknown entries or versions are rejected. Storing
`head_pins` in the bundle is **approved** (D-0104): it gives a brand-new device a
rollback anchor as soon as it fetches the account, with the first fetch being
trust-on-first-use (R-0102). Because that first fetch is unverified, the UI MUST
show **“not yet verified”** next to the vault until a second device or a safety
code confirms the head (Phase 5 implements and tests this).

### 4.6 Account identity keys

| Key | Algorithm | Purpose |
| --- | --- | --- |
| Identity signing key | Ed25519 | Certifies devices, signs revocations, signs key-transparency entries, signs sharing invitations (Phase 11). |
| Identity encryption key | X25519 | HPKE recipient key for wrapping vault keys to this account (Phase 11). |
| Identity KEM key | ML-KEM-768 | Reserved for hybrid post-quantum HPKE; generated and stored in v1, not used for wrapping yet (D-0105). |

Only the private halves live in the AK-encrypted bundle; the public halves are
published in the key-transparency log (§9.3) and carried in the account record.

### 4.7 Device keys and certification

Every client generates an Ed25519 **device key** on first launch. A device is
usable only once an already-unlocked device has certified it:

```
cert_body = CBOR{suite: "v1", type: "device-cert",
                 account_id, device_id, device_pubkey, created_at}
cert_sig  = Ed25519(identity_signing_key, BLAKE3(cert_body))
```

The `suite` and `type` fields are **PROPOSED** additions (D-0106) for domain
separation: the same identity key signs certificates, revocations and
transparency entries, and a signature must never be replayable in another role.

Enrolment is an explicit user action on the existing device (show a code, scan
or type it, confirm the new device's name). The new device proves possession of
its private key by signing the **BLAKE3 digest** of
`CBOR{suite, type: "device-enroll", account_id, device_id, nonce}` with a
single-use `nonce` issued by the approving device. Every signature in this
protocol covers a digest (D-0207), matching the op hash in §6.3. **PROPOSED**
(D-0107).

A client MUST verify, before trusting any device-signed object: the certificate
signature against the pinned identity key, that `account_id` matches, that the
device is not revoked, and that `created_at` is not in the future beyond a small
skew allowance (5 minutes).

### 4.8 Device revocation

A revocation is an append-only record signed by the **identity signing key**:

```
rev_body = CBOR{suite: "v1", type: "device-revocation",
                account_id, device_id, revoked_at, reason}
rev_sig  = Ed25519(identity_signing_key, BLAKE3(rev_body))
```

Rules:

- Clients MUST reject every op and every head whose `created_at` is at or after
  `revoked_at` for that device, and MUST reject any certificate for the device
  issued after `revoked_at`.
- A device MAY revoke itself (signing with its own device key as well), which is
  what a “sign out everywhere else” flow uses.
- Revocations are never deleted. Re-adding a revoked device id is forbidden; a
  reinstalled device gets a new `device_id`.
- Because clocks drift, an attacker-controlled device can backdate or forward-
  date a few ops around the revocation instant; the residual risk is R-0107.

### 4.9 Vault keys (VK)

A vault key is 32 random bytes created with the vault.

**Owner wrapping.**

```
k_vk = HKDF-SHA256(ikm = AK, salt = vault_id, info = "studge/v1/vk-wrap", L = 32)
VK_env = AEAD(k_vk, VK, nonce,
              aad = CBOR{suite, scope: vault_id, record_type: "vk-owner", schema_version})
```

Salting with `vault_id` gives every vault its own wrapping key, so a nonce
collision in one vault cannot affect another. **PROPOSED** (D-0108).

**Shared wrapping (Phase 11).** For a shared vault, the VK is wrapped with HPKE
(RFC 9180) to each member's identity encryption key; the HPKE `info` field
carries `CBOR{suite, scope: vault_id, record_type: "vk-share", member_id,
key_epoch}` so a wrapped key cannot be replayed to another member or epoch.

### 4.10 Item keys (IK) — reserved in v1

The key hierarchy defines an item key so that one item can be shared, moved or
re-keyed without touching the vault:

```
k_ik = HKDF-SHA256(ikm = VK, salt = item_id, info = "studge/v1/ik-wrap", L = 32)
IK_env = AEAD(k_ik, IK, nonce,
              aad = CBOR{suite, scope: vault_id, item_id, record_type: "ik", schema_version})
```

Under that key, fields would be encrypted with
`k_field = HKDF-SHA256(ikm = IK, salt = item_id, info = "studge/v1/item-field")`,
with the field name in the AAD (§5.3), so moving a field to another item fails
authentication and rekeying an item is a 32-byte rewrap rather than a
re-encryption of all its fields.

**In v1 these records are not written.** An op carries the whole item — one
self-contained snapshot sealed under the vault's `op-payload` key (§6.1) — so
there is no item key envelope and no per-field ciphertext on the wire or on
disk (D-0303). The derivations above and the `ik` / `item-field` record types
stay implemented and tested in the crypto layer, and Phase 5 introduces the
records themselves when per-item records travel between devices. A future
version that writes them does so behind a schema-version bump, never silently.

### 4.11 Key hierarchy

```
master password ──► Argon2id ──┐
                               ├──► HKDF ──► MUK ──► k_ak ──► AEAD ──► AK
Secret Key (128 bits) ─────────┘              │                        │
                                              └──► auth secret         ├──► account identity keys
                                                  (OPAQUE)             │    (Ed25519, X25519, ML-KEM)
                                                                       │
                                                                       └──► k_vk(vault) ──► AEAD ──► VK
                                                                                                     │
                                                                              k_ik(item) ──► AEAD ──► IK
                                                                                                     │
                                                                                    k_field ──► AEAD ──► field ciphertext
```

See `docs/diagrams/key-hierarchy.svg` for the rendered diagram:

![Key hierarchy: password + Secret Key to MUK to AK to vault keys to item
keys](diagrams/key-hierarchy.svg)

### 4.12 Rotation and lifecycle

| Event | What happens |
| --- | --- |
| Password change | New `account_salt`, new Argon2id run, new MUK; the AK envelope is re-wrapped and the old one deleted. The Secret Key is unchanged. |
| KDF parameter upgrade | Same flow as a password change, with stronger parameters. Forward-only. |
| Adding a device | New device key + certificate; the AK is *not* rotated (the new device receives the bundle through the normal encrypted sync). |
| Revoking a device | Signed revocation; no key rotation (a revoked device already had the keys). |
| Removing a vault member | VK rotation (§9.5); new `key_epoch`; history encrypted under the old epoch stays readable to whoever had it (R-0105). |
| Item edit | Field values re-encrypted with fresh nonces under the existing IK; IK wrapped again only if the vault key changed. |
| Account deletion | Relay-side delete request; local data wiped separately by the client. |

## 5. Encryption format

### 5.1 Suite `v1`

| Role | Algorithm | Parameters |
| --- | --- | --- |
| AEAD | XChaCha20-Poly1305 | 24-byte nonce, 16-byte tag appended to ciphertext |
| Password KDF | Argon2id | v=0x13, m=64 MiB, t=3, p=1, 32-byte output (§4.3) |
| Sub-key derivation | HKDF-SHA256 | labels below |
| Hashing | BLAKE3-256 | unkeyed, domain-separated by a label prefix or a `type` field |
| Signatures | Ed25519 (RFC 8032) | 32-byte public key, 64-byte signature |
| PAKE | OPAQUE (ristretto255, identity KSF) | §4.4 |
| Public-key encryption | HPKE (RFC 9180) | X25519 / HKDF-SHA256 / ChaCha20-Poly1305 (§9.2) |
| Serialisation | Deterministic CBOR (RFC 8949 §4.2.1) | strict parser |

The suite id is the string `v1`. Every envelope, op, head, certificate and
revocation carries it. A client MUST reject any object whose suite is missing,
unknown, or not exactly `v1`.

### 5.2 The envelope

Every ciphertext is stored as a CBOR map with exactly three fields:

```cddl
envelope = { "suite": "v1", "nonce": bstr .size 24, "ct": bstr }
```

- `ct` is the XChaCha20-Poly1305 output **including** the 16-byte tag, so the
  minimum length is 16 bytes.
- The nonce is 24 bytes from `OsRng` for every encryption. Nonces are never
  counters, never derived from content, and never reused with the same key. With
  192 random bits, the birthday bound is irrelevant for any realistic vault.
- The map is canonical CBOR; parsers MUST reject extra fields, duplicate keys,
  wrong lengths and non-canonical encodings.

### 5.3 Additional authenticated data (AAD)

The AAD binds a ciphertext to exactly one place in the data model. It is
**reconstructed from local context**, never copied from the message being
verified:

```cddl
aad = { "suite": "v1",
        "scope": bstr,            ; account_id or vault_id
        "item_id": bstr / null,   ; null when the record is account- or vault-level
        "record_type": tstr,
        "field_name": tstr / null,
        "schema_version": uint }
```

`record_type` is a closed enumeration: `ak`, `bundle/<entry>`, `vk-owner`,
`vk-share`, `ik`, `item-field`, `op/item`, `op/item-delete`, `op/item-move`,
`op/membership`, `op/key-rotation`, `recovery-share`, `emergency-grant`,
`kt-entry`. Anything else is rejected.

Rules:

- The AAD MUST contain the suite, the account or vault id, the item id (or an
  explicit `null`), the record type and, for per-field encryption, the field
  name.
- Two records that differ only by field name, item, vault or type produce
  different AADs and therefore cannot be swapped without a tag failure.
- The `schema_version` lets a future record shape coexist; v1 is `1` and a
  client MUST reject records with a version it does not implement.

### 5.4 HKDF labels

All purpose labels are `studge/v1/<purpose>` and live as constants in exactly
one file (`core/src/crypto/labels.rs`, Phase 2):

| Label | Used for | Salt |
| --- | --- | --- |
| `studge/v1/muk` | MUK from Argon2id output + Secret Key | empty |
| `studge/v1/opaque-password` | auth secret from MUK | empty |
| `studge/v1/ak-wrap` | AK wrapping key from MUK | empty |
| `studge/v1/key-bundle` | key-bundle key from AK | `account_id` |
| `studge/v1/vk-wrap` | VK wrapping key from AK | `vault_id` |
| `studge/v1/ik-wrap` | IK wrapping key from VK | `item_id` |
| `studge/v1/item-field` | field key from IK | `item_id` |
| `studge/v1/op-payload` | op payload key from VK | `vault_id` |
| `studge/v1/vk-share` | HPKE `info` context for shared vaults | — |
| `studge/v1/recovery-share` | guardian share encryption context | — |
| `studge/v1/emergency-grant` | emergency-access grant context | — |
| `studge/v1/kt-entry` | key-transparency leaf context | — |
| `studge/v1/safety-code` | safety-code digest | — |
| `studge/v1/secret-key-checksum` | printed Secret Key checksum | — |
| `studge/v1/device-cert`, `-enroll`, `-revocation` | signature domain strings | — |

No key is used for two labels; no label is derived from another label's output
except along the hierarchy in §4.11.

### 5.5 What is encrypted where

| Stored object | Protection |
| --- | --- |
| Account record: `account_id`, `account_salt`, `kdf` params | plaintext, public by design |
| Account record: AK envelope, key bundle | AEAD under MUK-derived and AK-derived keys |
| Device list, certificates, revocations | Ed25519 signatures (public data) |
| Vault ops | payload AEAD under the vault's `op-payload` key; op header signed |
| Vault head | Ed25519 signature (public data) |
| Item key envelopes | *reserved, not written in v1* (§4.10, D-0303); AEAD under the vault's `ik-wrap` key when introduced |
| Item fields | *reserved, not written in v1* (§4.10, D-0303); in v1 the field map travels inside the op payload |
| Vault key for shared members | HPKE to each member (Phase 11) |

What remains visible to the relay: ids, sizes, counts, `lamport`, `created_at`,
`kind`, parent hashes. That is the metadata surface recorded as R-0101.

### 5.6 Field-level rules

- In v1 an op carries the item's whole field map as one snapshot under the
  vault's `op-payload` key (§4.10, D-0303). The per-field rule below describes
  the record format reserved for Phase 5: when field records travel, every field
  is encrypted separately, and empty fields are omitted from the map, never
  stored as empty ciphertext.
- The field name is authenticated but **not** encrypted, because the relay never
  needs it and clients need it to render; it is part of the AAD and the op's
  encrypted payload, never of the relay-visible header. (If a future version
  wants to hide field names from a local attacker, it can encrypt the map keys
  as an opaque blob.)
- A field value is at most 1 MiB; an item has at most 256 fields; an op payload
  at most 1 MiB. Limits per D-0110 (approved), enforced by clients and the relay.
  These per-record caps sit inside the account storage quota in §7.7.
- Field names come from the item template (`password`, `username`, `url`, …),
  not from free text. Clients MUST render the template's label for a known field
  name and MUST NOT display an unknown field name as a trusted label; an unknown
  name is shown inside a generic “additional field” area with the name quoted
  (R-0114).

### 5.7 Hashing

BLAKE3-256 everywhere for our own structures: op hashes, head hashes,
certificate and revocation bodies, the Secret Key checksum, safety codes. SHA-256
appears only inside primitives that specify it (OPAQUE, HKDF, HPKE, TLS). A
digest is never compared with `==`; comparisons use `subtle` (§11.4).

### 5.8 Decryption failure

A tag failure, an AAD mismatch, a wrong inner type, a bad length or a
non-canonical encoding is fatal for that record: the client zeroizes any partial
plaintext, reports a clear error, and refuses to use the record. It MUST NOT try
another key, another nonce, another suite or a “repair” path.

## 6. Vault operation log

### 6.1 The operation

```cddl
op = { "suite": "v1",
       "vault_id": bstr .size 16,
       "op_id": bstr .size 16,
       "parents": [* bstr .size 32],   ; sorted ascending, 0..16 entries
       "lamport": uint,
       "device_id": bstr .size 16,
       "created_at": tstr,             ; RFC 3339 UTC, e.g. 2026-11-05T09:30:00Z
       "kind": tstr,                   ; closed enum below
       "item_id": bstr .size 16 / null,
       "schema_version": uint,
       "payload": bstr }               ; an envelope (§5.2)
```

`kind` is one of `create`, `update`, `delete`, `move`, `membership`,
`key_rotation`. The payload's inner `record_type` MUST match the kind
(`op/item`, `op/item-delete`, `op/item-move`, `op/membership`,
`op/key-rotation`); a mismatch is fatal.

A stored op is the canonical CBOR of `op` followed by a `sig` field of 64 bytes.
The signature is computed over the op **without** `sig`.

### 6.2 Canonical encoding and hashing

- Deterministic CBOR per RFC 8949 §4.2.1: shortest integer forms, definite
  lengths only, map keys sorted by encoded length and then bytewise, no duplicate
  keys, no tags, no floats, no indefinite strings.
- `parents` are sorted ascending bytewise before encoding, so two clients that
  merge the same history produce identical bytes.
- `op_hash = BLAKE3(canonical_bytes(op without sig))` — exactly as the brief
  specifies; the `suite` field inside the op prevents cross-protocol reuse.

### 6.3 Signatures

```
sig = Ed25519(device_signing_key, op_hash)
```

Verification is against the device key in the device's certificate (§4.7) after
checking that the certificate chains to the pinned identity key and that the
device is not revoked at `created_at` (§4.8). A client MUST verify the signature
before using any field of the op, including its `parents`.

### 6.4 The DAG

- The first op of a vault (genesis) has `parents = []`.
- Every later op references between 1 and 16 parents that the client has already
  verified. A client MUST reject an op whose parent is unknown; a relay that
  withholds a parent therefore produces a detectable error, not a silent gap.
- The vault state is the set of all ops reachable from the current heads.
- A client that has never seen a vault accepts the genesis op only from a head
  that chains to it; it does not accept a “middle” of a history as a start.

### 6.5 Lamport clocks

- Genesis: `lamport = 1`.
- Otherwise `lamport = 1 + max(lamport of parents)`.
- A client MUST reject an op whose `lamport` differs from that rule (no
  inflation, no reuse).
- `created_at` is advisory: it is used for display and for revocation cut-offs,
  never for ordering.

### 6.6 Conflict resolution

Two item versions conflict when neither is an ancestor of the other. The winner
is the op with the highest `(lamport, device_id)` tuple, comparing `device_id` as
16 raw bytes. The rule is total, deterministic and identical on every client, so
all devices converge without coordination.

### 6.7 History

Losing versions are never deleted: they remain ops in the DAG and are shown in
the item's history. The UI MAY collapse them, but the protocol keeps them, which
is what makes “an attacker cannot make a change disappear” true.

### 6.8 Vault heads

```cddl
head = { "suite": "v1",
         "type": "vault-head",
         "vault_id": bstr .size 16,
         "heads": [1* bstr .size 32],
         "op_count": uint,
         "lamport_max": uint,
         "device_id": bstr .size 16,
         "created_at": tstr }
head_sig = Ed25519(device_signing_key, BLAKE3(canonical(head)))
```

- `heads` lists the current tips of the DAG (at least one).
- `op_count` is the number of ops in the vault; `lamport_max` the highest
  Lamport clock seen.
- The head is replaced with compare-and-swap: `PUT /v1/vaults/:id/head` carries
  the hash of the head it replaces; the relay answers `409` if it disagrees
  (§7.4). This prevents two devices from silently overwriting each other on the
  relay, but it is **not** a security control: the relay can still serve an old
  head, which §6.9 detects.

### 6.9 Head pinning, rollback and fork detection

A client stores the last verified head per vault (`pinned_head`), locally and as
a hint in the key bundle. On every sync it MUST check, in this order:

1. The returned head verifies (signature, suite, vault id, device not revoked).
2. Every `heads` entry exists among the ops the client now has.
3. Each pinned head hash is **reachable by following parents** from some new
   head. If it is not, the relay is serving a history that does not descend from
   what the client saw — a rollback — and the client MUST refuse to sync.
4. `op_count` and `lamport_max` are not lower than the pinned values.
5. Every new op verifies: canonical encoding, hash, signature, parents known,
   Lamport rule, kind/inner-type match, payload AEAD under the vault key.

If two different heads with the same `op_count` appear (for example from two
relays or two accounts of the same vault), neither descending from the other,
that is a fork: the client MUST stop, keep its pinned head, and tell the user.

A brand-new device has no pin. It takes the `head_pins` hint from the account
bundle (§4.5) and verifies internal consistency, but the *first* fetch is
trust-on-first-use; see R-0102. Until a second device or a safety code confirms
the head, the UI labels the vault **“not yet verified”** (D-0104, Phase 5); it
MUST NOT present a first-sync vault as verified.

**Freeze.** A relay can also do nothing: keep serving the pinned head forever
while newer ops exist elsewhere. That is indistinguishable from “no changes”
without a second channel, so it is listed as R-0106; a second device or the
folder transport is the practical detection path.

### 6.10 Compaction (deferred)

v1 keeps every op forever. Clients MAY cache a materialised state locally, but
there is no server-side compaction and no snapshot op kind. A future version can
add snapshots behind a new `kind` and a schema-version bump; doing it now would
add a second way to reconstruct history and a second way to get it wrong
(D-0111). Quotas (§7.7) bound growth per vault.

### 6.11 Limits

| Limit | Value |
| --- | --- |
| Ops per push request | 100 |
| Parents per op | 16 |
| Op payload (plaintext) | 1 MiB |
| Head size | 16 KiB |
| `created_at` skew accepted | ±5 minutes |

## 7. Relay API

### 7.1 Transport profile

- HTTPS (TLS 1.3 preferred, 1.2 minimum) for the hosted relay; a self-hosted
  relay MAY run behind a reverse proxy that terminates TLS. Correctness never
  depends on TLS (§3.1).
- Control messages are JSON (`application/json; charset=utf-8`), parsed strictly
  with unknown fields rejected. Ops and heads are CBOR
  (`application/cbor`).
- Authentication is a bearer token in `Authorization`; there are no cookies and
  no CSRF surface.
- Everything lives under `/v1`. A request to an unknown path, method or media
  type is rejected with the generic error shape (§7.8).
- Request bodies are capped at 8 MiB and every array has an explicit maximum
  (§7.7).

### 7.2 Registration (OPAQUE)

Registration is a two-message OPAQUE flow (`opaque-ke`, ristretto255). The
client generates `account_id`, `account_salt`, the AK and the identity keys
before it starts; the relay never sees any of them in the clear.

1. `POST /v1/register/start` with the OPAQUE `RegistrationRequest` for
   `auth_secret` (§4.4). Response: the server's `RegistrationResponse`.
2. `POST /v1/register/finish` with the OPAQUE `RegistrationUpload` and the
   account record: `account_salt`, `kdf` parameters, AK envelope, key bundle,
   identity public keys, the first device's certificate.

The relay creates the account atomically and answers `201`. A duplicate
`account_id` is `409`. Registration is rate-limited per IP; there is no account
enumeration because the response shape is identical for “created” and “could
not be created”.

### 7.3 Login and session tokens

1. `POST /v1/login/start` with `account_id`, `device_id` and the OPAQUE
   `CredentialRequest`. Response: `CredentialResponse`.
2. `POST /v1/login/finish` with the `CredentialFinalization`. Response:
   `{token, expires_at}`.

Token rules:

- 256 random bits from `OsRng`, returned exactly once, never logged.
- The relay stores only `SHA-256(token)` and compares in constant time.
- Lifetime 24 hours; a new login replaces the previous token for that device.
- Bound to `device_id`; a token for a revoked device is rejected and deleted.
- `DELETE /v1/sessions/current` ends a session early. **PROPOSED** endpoint
  (D-0112); without it, logout is only client-side.
- Failed logins are counted per account and per IP; after the limits in §7.7 the
  relay answers `429` or the generic `401`, never a message that distinguishes
  “wrong password” from “no such account”. For an unknown account the relay runs
  a dummy OPAQUE exchange with a random secret so timing does not reveal
  existence. **PROPOSED** (D-0113).

### 7.4 Endpoints

| Method & path | Auth | Request | Response |
| --- | --- | --- | --- |
| `POST /v1/register/start` | — | `{account_id, registration_request}` | `{registration_response}` |
| `POST /v1/register/finish` | — | `{account_id, registration_upload, account_record}` | `201 {account_id}` |
| `POST /v1/login/start` | — | `{account_id, device_id, credential_request}` | `{credential_response}` |
| `POST /v1/login/finish` | — | `{account_id, device_id, credential_finalization}` | `{token, expires_at}` |
| `GET /v1/account` | token | — | account record (§7.5) |
| `PUT /v1/account` | token | full account record + `If-Match: version` | `200` or `409` |
| `POST /v1/devices` | token | `{certificate, device_pubkey, enrolment_proof}` | `201` |
| `DELETE /v1/devices/:device_id` | token | `{revocation_record}` | `200` |
| `POST /v1/vaults/:vault_id/ops` | token | CBOR array of ops (≤ 100) | `{accepted, rejected:[{op_id, reason}], head}` |
| `GET /v1/vaults/:vault_id/ops?since=<cursor>&limit=<n>` | token | — | CBOR array + `next_cursor` header |
| `GET /v1/vaults/:vault_id/head` | token | — | `{head, head_hash}` |
| `PUT /v1/vaults/:vault_id/head` | token | head + `If-Match: <head_hash>` | `200` or `409` |
| `DELETE /v1/account` | token | `{confirmation: "delete"}` | `202` |

Semantics that matter:

- **Ops are append-only.** The relay never updates or deletes an op except when
  the whole account is deleted. `(vault_id, op_id)` is unique; re-sending the
  same bytes is idempotent (`accepted`), re-sending different bytes under the
  same `op_id` is `409`.
- **Ordering.** `GET ops` returns ops in an order where every parent precedes its
  children. The cursor is the last returned `op_hash`; a client that loses its
  cursor re-fetches from the beginning and re-verifies — correctness never
  depends on the cursor.
- **Head compare-and-swap.** `PUT head` requires `If-Match` with the hash of the
  head it replaces (`*` only for the first head). A mismatch is `409` and the
  client re-reads the head. This is a lost-update guard, not a security control.
- **Device removal** requires a signed revocation record (§4.8); the relay
  verifies the record's structure and that the signer is the account identity
  key, then marks the device revoked and deletes its sessions.
- **Account deletion** is a two-step, async wipe: the account is tombstoned
  immediately and all rows are deleted within 24 hours. Backups age out on the
  operator's schedule.
- Phase 11 adds the key-directory endpoints (`GET /v1/keys/:account_id`,
  `POST /v1/keys`); they are not part of v1.

### 7.5 Account record shape

```cddl
account_record = { "account_id": bstr .size 16,
                   "account_salt": bstr .size 16,
                   "kdf": { "version": 1, "m": uint, "t": uint, "p": uint },
                   "ak_envelope": bstr,
                   "bundle_envelope": bstr,
                   "identity_keys": { "ed25519": bstr .size 32,
                                      "x25519": bstr .size 32,
                                      "mlkem768": bstr .size 1184 },
                   "version": uint }
```

The relay stores this as opaque bytes with the JSON envelope around it. It MUST
reject a record whose `account_salt` or `kdf` are outside the allowed ranges
(§4.3) and whose `version` it does not implement.

### 7.6 What the relay validates

The relay validates **structure, sizes, authentication, quotas and rate limits**
and nothing else:

- media type, JSON/CBOR well-formedness, exact field sets, id lengths, enum
  values, array bounds, integer ranges;
- `parents` ≤ 16, sorted, no duplicates; `lamport` ≥ 1 and ≤ 2^63−1;
- `created_at` parseable RFC 3339, within ±24 h of server time (clients apply the
  stricter ±5 min rule where it matters, §6.11);
- op bytes are stored exactly as received; the relay MUST NOT re-encode them;
- token validity, device binding, revocation status;
- quotas and rate limits.

The relay does **not** verify op signatures, decrypt anything, or interpret
payloads. Signature checking is the client's job and the client never trusts the
relay's word for it.

### 7.7 Quotas and rate limits

| Limit | Value (D-0110, approved) |
| --- | --- |
| Vaults per account | 100 |
| Ops per vault | 250,000 |
| Op payload | 1 MiB |
| Ops per push | 100 |
| Vault data per account | **100 MiB** on the free hosted relay; 1 GiB once attachments ship; self-hosters may raise it |
| Request body | 8 MiB |
| Login attempts | 10/hour/account, 60/hour/IP |
| Registrations | 5/hour/IP |
| Op pushes | 60/minute/account |
| Reads | 300/minute/account |

Exceeding a quota is `413`/`429` with `Retry-After` where meaningful. Limits are
enforced before any expensive work, and every limit is logged (without content)
for abuse analysis.

### 7.8 Error model

```json
{ "error": "invalid_request" }
```

Closed set of codes: `invalid_request`, `unauthorized`, `forbidden`,
`not_found`, `conflict`, `too_large`, `quota_exceeded`, `rate_limited`,
`unavailable`. No field explains *why* authentication failed, no account
identifiers are echoed, no stack traces, no internal ids. `401` for both “bad
token” and “unknown account”; `404` for both “no such vault” and “not yours”.

### 7.9 Relay storage

SQLite by default (Postgres optional), WAL mode, foreign keys on.

| Table | Contents |
| --- | --- |
| `accounts` | account record bytes, version, created_at, quotas |
| `devices` | account_id, device_id, public key, certificate bytes, created_at, revoked_at |
| `vaults` | account_id, vault_id, head bytes, head_hash, op_count, lamport_max |
| `ops` | vault_id, op_hash, op_id, lamport, parents, kind, item_id, device_id, created_at, raw bytes; unique `(vault_id, op_id)` |
| `sessions` | token_hash, account_id, device_id, expires_at |
| `kt_log` | key-transparency entries (Phase 11) |
| `audit` | rate-limit and abuse counters, no content |

Ops are never updated. Account deletion cascades. Every byte stored is either
public metadata or ciphertext; a database dump reveals no secret (§3.2).

### 7.10 Transports

Core talks to storage through one trait; every implementation must pass the same
contract tests (Phase 3 and Phase 5).

| Transport | Where data lives | Notes |
| --- | --- | --- |
| `http` | the relay | §7.1–7.9; token auth; server-enforced quotas |
| `folder` | any directory the OS syncs (OneDrive, iCloud Drive, Syncthing, a USB stick) | one file per op named by hash, atomic write (temp file + rename), advisory lock; no authentication — the folder's ACLs are the user's responsibility |
| `memory` | process memory | tests and demos only |

The folder layout (PROPOSED, D-0114):

```
<root>/account.cbor
<root>/devices.cbor
<root>/vaults/<vault_id>/ops/<op_hash>.cbor
<root>/vaults/<vault_id>/head.cbor
<root>/lock
```

A folder transport MUST detect edits the same way the HTTP client does:
hashes, signatures and head descent. It MUST NOT trust file mtimes or names.

### 7.11 What the relay must never receive

The relay MUST NOT receive, store, log or derive: the master password, any
password-equivalent hash, the Secret Key, the MUK, the auth secret, the Account
Key in clear, any vault or item key, plaintext item data, or plaintext URLs.
Any relay code path that would accept such a value is a defect (AGENTS.md rule 8).

### 7.12 Relay threat notes

A relay that follows this API can still: withhold ops (detected as a missing
parent or a head that does not advance), serve an old head (detected by §6.9),
correlate timing and sizes (R-0101), and deny service. It cannot read, forge,
swap, reorder undetectably, or roll back a client that has a pin. The threat
model (A1) works through the list.

## 8. Health scoring

The security dashboard (Phase 10) turns a vault into one number. The formula is
fixed here so the Rust core and every client agree:

```
score = round( 100 × Σ(w_i × p_i) / Σ w_i )
```

### 8.1 Protection values

| `p` | Condition (the best method available on the item) |
| --- | --- |
| 1.0 | Passkey or security key, with no password left on the item |
| 0.8 | Passkey plus a strong, unique fallback password |
| 0.6 | Password plus TOTP or a security key as second factor |
| 0.3 | Password plus SMS or email one-time code |
| 0.1 | Strong, unique password only |
| 0.0 | Weak, reused, or breached password |

### 8.2 Item weights

| `w` | Class | Examples |
| --- | --- | --- |
| 5 | Recovery roots | Email, phone carrier, Apple/Google/Microsoft account |
| 3 | Money | Banks, UPI, cards, brokers, crypto exchanges |
| 1 | Everything else | Shopping, forums, streaming |

An item belongs to exactly one class; if it matches several, the highest weight
wins. Classification comes from the item template and user-editable tags; it is
never inferred from the URL by a third party (no favicon or reputation lookups).
**PROPOSED** rule (D-0116).

### 8.3 Computation rules

- Empty vault: score `100`, displayed with an explicit “nothing to score yet”
  state rather than a perfect score. **PROPOSED** (D-0116).
- Breach and reuse checks run locally: a bundled list of breached password
  hashes (offline, no network) and an in-vault reuse scan. No range queries to
  third-party services in v1; a future k-anonymity lookup would be a Transport
  call and a product decision.
- The score is recomputed on unlock and after every vault change; it never leaves
  the device.
- Rounding is half-up to the nearest integer; the dashboard shows the integer and
  the underlying counts.

## 9. Sharing (summary; full design in Phase 11)

### 9.1 Model

A vault has members. Membership changes are ordinary ops (`kind =
membership`), signed by an authorised device, so they are as verifiable as any
other change. Each member's access is a wrapped copy of the current vault key.

**Write authorisation (D-0117, approved).** v1 membership is write-or-nothing:
a member device that holds the vault key can publish ops, and peers accept them
because they are signed by a certified device. **Phase 11 MUST add owner-signed
capabilities so that view-only sharing can be enforced** (tracked on issue #18).
Until that lands, the UI MUST NOT offer a “view only” share, and this limitation
is listed as R-0113.

### 9.2 Key wrapping

- HPKE (RFC 9180), base mode, ciphersuite X25519 / HKDF-SHA256 /
  ChaCha20-Poly1305, to the member's identity encryption key (§4.6).
- The HPKE `info` field carries
  `CBOR{suite, scope: vault_id, record_type: "vk-share", member_id, key_epoch}`,
  so a wrapped key cannot be replayed to another member or another epoch.
- The brief allows hybrid X25519 + ML-KEM-768 “if a maintained crate supports it
  cleanly”. v1 uses X25519 only; the ML-KEM-768 identity key is generated and
  stored now, and a later suite can switch the wrap to hybrid without changing
  the vault or item format. **Approved (D-0105)** on the condition that **Phase
  11 re-checks for a maintained hybrid HPKE or X-Wing crate and switches to it
  if one exists**. Tracked as R-0116.

### 9.3 Key transparency

- The relay operates an append-only Merkle log of
  `{account_id, ed25519, x25519, mlkem768, epoch}` entries. Each entry is signed
  by the account identity key (`kt-entry` label).
- Clients verify inclusion proofs for the keys they use, and consistency proofs
  between successive signed tree heads (STHs) they have pinned.
- Because the log is run by the same untrusted party, a split view is possible;
  devices gossip STHs between themselves and the safety code (§9.4) is the
  ultimate check. Residual risk R-0110.

### 9.4 Safety codes

`safety_code = BLAKE3("studge/v1/safety-code" || account_id_A || key_A ||
account_id_B || key_B)`, rendered as six groups of five Crockford characters.
Two people compare it out of band once; afterwards key substitution by the relay
is detectable.

### 9.5 Removing a member

Removal publishes a `key_rotation` op: new VK (`key_epoch + 1`), wrapped to the
remaining members. The removed member keeps whatever they already had — history
under older epochs cannot be un-shared — but cannot read anything written after
the rotation. This is stated plainly because pretending otherwise would be a
security claim the design cannot back (R-0105).

## 10. Recovery and emergency access (summary; full design in Phase 12)

### 10.1 The recovery kit

A printable page holding: the `account_id`, the `SP1-…` Secret Key, the date, and
instructions. It never holds the master password. Losing the kit but keeping a
device is fine; losing every device *and* the kit is unrecoverable by design (G4).

### 10.2 Guardian recovery (2-of-3)

**Primitive.** Replicated XOR secret sharing, built only from approved
primitives: `OsRng` and XOR. No third-party crate is used (D-0115, approved).

**Sharing.** At setup the client generates a random 256-bit **Recovery Key** `S`
and stores an additional AK envelope under
`k_rec = HKDF(S, "studge/v1/recovery-ak")` on the relay. Recovery therefore
restores the account key, not the old password; the user sets a new password
afterwards. Then:

1. Draw two 32-byte pads `R1`, `R2` from `OsRng`; compute `R3 = R1 ⊕ R2 ⊕ S`.
2. Guardian `i` (`i` ∈ {1, 2, 3}) receives the pair `(R_i, R_(i+1 mod 3))` —
   two of the three pads, 64 bytes, labelled with `share_index = i`.
3. Each share is sealed with HPKE (RFC 9180, X25519 / HKDF-SHA256 /
   ChaCha20-Poly1305) to that guardian's identity encryption key, with
   `aad = CBOR{suite, account_id, guardian_id, share_index,
   record_type: "recovery-share"}`. The sealed share is stored on the relay.

**Reconstruction.** Any two guardians hold all three pads between them: XOR the
three pads and the result is `S`. A single share is two uniform 32-byte values
and reveals nothing about `S` — the scheme is information-theoretically 2-of-3.
A wrong or corrupted combination fails the AEAD on the `k_rec` envelope, which is
a hard error; there is no partial recovery and no “try another pair” path that
silently accepts bad data.

**Approval flow.** Two guardians approve; the client reconstructs `S`, unwraps
the account key, and re-wraps it to the recovering device after the cancellation
window (§10.3).

**Test vectors (Phase 12).** Phase 12 MUST publish known-answer vectors: a fixed
`S`, `R1` and `R2` with the expected `R3`, the exact share bytes for each index,
the HPKE AAD bytes, and reconstruction results for pairs (1,2), (2,3) and (3,1).
The vectors live in the Phase 12 tests, not in this document.

### 10.3 The 72-hour cancellation window

After two guardian approvals, every other device of the owner is notified and
has 72 hours to cancel. Only after the window does the recovering device receive
the re-wrapped key. The window is enforced by the relay (it withholds the
wrapped key until it expires) **and** by clients (a device that sees a recovery
in progress warns the user). A malicious relay can shorten the wait; the client
warning is the backstop.

### 10.4 Emergency access

An owner-defined contact receives a copy of the account key wrapped to their
identity key, sealed until a waiting period the owner chose (for example 7 days)
has passed without cancellation. Same cancellation rule as §10.3. Details in
Phase 12.

### 10.5 Recovery threat notes

Guardians never hold the vault key, only shares of a recovery key that is
useless without a second guardian. A guardian who is compromised contributes one
share; two colluding guardians can recover — that is the design. The printed kit
is the weakest link against physical theft (R-0109).

## 11. Crypto inventory and versioning

### 11.1 Inventory

| Purpose | Crate (approved list) | Where used |
| --- | --- | --- |
| AEAD | `chacha20poly1305` (XChaCha20-Poly1305) | every envelope |
| KDF | `hkdf` + `sha2` | hierarchy, labels |
| Password KDF | `argon2` | MUK |
| Hashing | `blake3` | ops, heads, checksums, safety codes |
| Signatures | `ed25519-dalek` | devices, identity, ops, heads |
| Key agreement | `x25519-dalek` | HPKE, sharing |
| Public-key encryption | `hpke` | vault key wrapping |
| Post-quantum KEM | `ml-kem` | reserved identity key, later hybrid wrap |
| PAKE | `opaque-ke` | relay authentication |
| Randomness | `rand_core` / `getrandom` (`OsRng` only) | everything |
| Secrets | `zeroize`, `secrecy` | key material |
| Constant time | `subtle` | tag/token comparisons |
| CBOR | `ciborium` | every structure |
| Unicode | `unicode-normalization` | password NFKC |
| TOTP | `totp-rs` | second-factor items (Phase 3) |
| Strength | `zxcvbn` | scoring (Phase 3) |

Exact versions are pinned in `Cargo.lock` and justified in `docs/DECISIONS.md`
as each crate is added (Phase 2 onward). No crate outside this list may be used
for cryptography without the founder's approval.

### 11.2 One suite, no negotiation

There is exactly one suite, `v1`. Clients and relays do not negotiate: every
object names the suite it was produced under, and anything that is not `v1` is
rejected. There is no “compatibility mode”, no legacy reader, and no fallback
when a primitive fails.

### 11.3 KDF parameters are versioned and forward-only

`kdf.version` is `1`. A client MUST reject parameters below the minimum in §4.3
and MUST reject unknown versions. Upgrading parameters re-derives the MUK and
re-wraps the AK; there is no downgrade path and no “try both” behaviour.

### 11.4 Handling of secrets

- All key material lives in `Zeroizing`/`SecretBox`; `Debug` is implemented
  manually and redacts.
- Secrets are never serialised into errors, logs, telemetry, crash reports or
  the clipboard history.
- Comparisons of tags, tokens and hashes use `subtle::ConstantTimeEq`.
- Buffers are zeroized on lock, on error and on drop.

<!-- SPEC-END -->
