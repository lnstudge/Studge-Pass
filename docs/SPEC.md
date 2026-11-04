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
| `vault_id` | 16 bytes | UUIDv4 at vault creation | **PROPOSED** (the brief fixes account and device ids only). |
| `item_id` | 16 bytes | UUIDv4 at item creation | Stable across devices; chosen by the creating device. **PROPOSED** |
| `op_id` | 16 bytes | UUIDv4 at op creation | Used for idempotency on the relay (§7.6). **PROPOSED** |

Identifiers are rendered as lowercase UUID strings with hyphens. Uniqueness
relies on 122 random bits; a client MUST reject a duplicate `op_id` with
different content (§6.1).

### 4.2 The Secret Key

**Material.** The Secret Key is generated once, on the first device, from
`OsRng` and never changes for the life of the account. It is shown once at
creation, printed in the recovery kit, and stored on each device in the OS
keystore where one exists.

**Encoding.** Crockford base32 (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`),
upper-case on display. On input, hyphens are ignored, lower-case is accepted, and
the Crockford confusions are normalised (`I`, `L` → `1`; `O` → `0`); the letters
`U` is not part of the alphabet and MUST be rejected.

**Printed form.**

```
SP1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-X
```

That is 26 characters after the `SP1-` prefix: five groups of five data
characters and one final check character. Twenty-five data characters carry 125
bits; the check character carries no key material.

> **PROPOSED (D-0101).** The brief asks for 128 random bits and this exact
> printed shape. 128 bits do not fit into 25 base32 characters, so v1 defines
> the Secret Key as **125 bits of entropy** (16 random bytes with the top three
> bits cleared), displayed exactly as above, with a 5-bit checksum. 125 bits is
> still far above the 112-bit floor used for “secure today”. The alternative is
> a 27-character display (26 data characters + 1 check character) if a full 128
> bits is required. The founder should pick one; v1 as written uses 125 bits.

**Checksum.** `c = BLAKE3("studge/v1/secret-key-checksum" || ASCII of the 25
data characters)`; the check character is `c[0] mod 32` rendered in the alphabet
above. Decoding MUST reject a string whose checksum does not match, whose length
is wrong, or which contains a character outside the alphabet after
normalisation.

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
salt. Mixing in 125 bits that never reach the relay means an attacker needs both
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
`head_pins` in the bundle is **PROPOSED** (D-0104): it gives a brand-new device a
rollback anchor as soon as it fetches the account, with the first fetch being
trust-on-first-use (R-0102).

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
its private key by signing
`CBOR{suite, type: "device-enroll", account_id, device_id, nonce}` with a
single-use `nonce` issued by the approving device. **PROPOSED** (D-0107).

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

### 4.10 Item keys (IK)

Every item has its own 32 random bytes:

```
k_ik = HKDF-SHA256(ikm = VK, salt = item_id, info = "studge/v1/ik-wrap", L = 32)
IK_env = AEAD(k_ik, IK, nonce,
              aad = CBOR{suite, scope: vault_id, item_id, record_type: "ik", schema_version})
```

Fields are encrypted under
`k_field = HKDF-SHA256(ikm = IK, salt = item_id, info = "studge/v1/item-field")`,
with the field name in the AAD (§5.3). Two consequences worth stating: moving a
field to another item fails authentication, and rekeying an item is a 32-byte
rewrap rather than a re-encryption of all its fields.

### 4.11 Key hierarchy

```
master password ──► Argon2id ──┐
                               ├──► HKDF ──► MUK ──► k_ak ──► AEAD ──► AK
Secret Key (125 bits) ─────────┘              │                        │
                                              └──► auth secret         ├──► account identity keys
                                                  (OPAQUE)             │    (Ed25519, X25519, ML-KEM)
                                                                       │
                                                                       └──► k_vk(vault) ──► AEAD ──► VK
                                                                                                     │
                                                                              k_ik(item) ──► AEAD ──► IK
                                                                                                     │
                                                                                    k_field ──► AEAD ──► field ciphertext
```

See `docs/diagrams/key-hierarchy.svg` for the rendered diagram.

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

<!-- SPEC-END -->
