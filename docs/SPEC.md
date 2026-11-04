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

<!-- SPEC-END -->
