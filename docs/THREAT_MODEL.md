# Studge Pass threat model

> **Status:** Phase 1, 2026-11-05. This file is normative alongside
> `docs/SPEC.md`: every mitigation names the SPEC section that implements it, and
> every gap ends up in **Open risks** with an id (R-01xx) so later phases can
> close it or accept it explicitly.

## 1. How to read this

The security promise is narrow and testable: **the relay is treated as an
attacker, and it must not be able to read, modify, reorder, roll back or
substitute data without clients detecting it.** Everything below is either an
argument that a promise holds, or an honest statement of where it stops.

Each adversary section is a table of *asset at risk → attack → mitigation →
residual risk*. "Residual" is what remains after the mitigation, not something
the next section fixes. Residual risks are numbered and repeated in §13.

## 2. Assets

| Asset | Why it matters | Where it lives |
| --- | --- | --- |
| Vault plaintext (passwords, notes, URLs, TOTP seeds) | The whole point of the product | Encrypted on the relay; plaintext only in device memory while unlocked |
| Key material (MUK, AK, VK, IK, device keys) | Reading or forging anything | Device memory and OS keystore; wrapped copies on the relay |
| Secret Key and recovery kit | Unlocking without a device; recovery | Printed paper, OS keystore; never the relay |
| History integrity (nothing silently changed, reordered, dropped) | Trust in the vault | Signed op DAG + heads |
| Availability of the sync service | Multi-device use | Relay and transports |
| Metadata (who, when, how much) | Correlation, targeting | Relay (unavoidable, see R-0101) |
| User intent (what they meant to click or approve) | Phishing, clickjacking | Browser and OS UI surfaces |

## 3. Adversaries at a glance

| Id | Adversary | Capability assumed | In scope |
| --- | --- | --- | --- |
| A1 | Fully malicious relay | Reads, writes, reorders, withholds, forks, rolls back, colludes | Yes |
| A2 | Network attacker | Observes and modifies traffic, replays requests | Yes |
| A3 | Malicious sharee or removed member | Valid account, valid device keys, inside a shared vault | Yes |
| A4 | Malicious web page | Full control of a page the user visits | Yes |
| A5 | Thief with a locked device | Physical possession, offline attacks | Yes |
| A6 | Malware on an unlocked device | Code execution as the user while unlocked | **No**, by design (§9) |
| A7 | Supply-chain attacker | Compromised dependency, action or build | Yes |
| A8 | Hostile browser extension | Another extension with page access | Partly (§11) |

## 4. A1 — Fully malicious relay

The relay is the primary adversary. It stores every ciphertext, sees every
request, and can lie about anything it returns.

| Asset at risk | Attack | Mitigation (SPEC) | Residual |
| --- | --- | --- | --- |
| Vault plaintext, keys | Read stored data, dump the database | Everything is AEAD under client-held keys; the relay never receives a password, the Secret Key, the MUK, AK, VK, IK or plaintext (§3.2, §7.11) | None for confidentiality of stored data; metadata remains (R-0101) |
| Record integrity | Flip bytes, swap two fields, move a field to another item, replay an old record | AAD binds suite, account/vault id, item id, record type, field name and schema version (§5.3); any mismatch is a hard error (§5.8) | None |
| Vault history | Delete an op, reorder ops, splice two histories | Hash-chained DAG with signed ops (§6.2–6.3); missing parents are a hard error (§6.4) | Withholding is detectable but not preventable (R-0106) |
| Freshness | Serve an old head or an old op set (rollback) | Clients pin the last verified head and require descent (§6.9, checks 2–4) | A device with no pin yet is TOFU (R-0102) |
| Single view of history | Show two different valid histories (split view / equivocation) | Head pinning, fork detection, multi-device heads, key-transparency consistency proofs (§6.9, §9.3) | A single device talking to a single relay can be shown one consistent lie; the safety code is the cross-device check (R-0110) |
| Account substitution | Serve another account's record, swap identity keys | `account_id` in the AK AAD (§4.5); identity keys pinned and published in the transparency log (§9.3); safety codes (§9.4) | First contact before verification (R-0104) |
| Sharing | Substitute a member's public key and receive the wrapped vault key | Key transparency inclusion proofs + safety codes (§9.3–9.4) | Unverified first contact (R-0104) |
| Sessions | Steal or replay tokens | Tokens are 256 random bits, stored only as SHA-256, 24 h expiry, device-bound, revoked with the device (§7.3) | A token stolen in transit from a compromised TLS endpoint is usable until expiry |
| Availability | Delete data, refuse service | Offline-first clients; folder transport; self-hosting (§7.10) | Availability is the relay's to give (out of cryptographic scope) |

## 5. A2 — Network attacker

| Asset at risk | Attack | Mitigation (SPEC) | Residual |
| --- | --- | --- | --- |
| Session token | Read it from the wire, replay it | TLS for the HTTP transport; bearer token only in a header (§7.1); 24 h expiry and device binding (§7.3) | Traffic analysis; a TLS-terminating proxy sees metadata |
| Request/response integrity | Modify JSON or CBOR in flight, downgrade to plain HTTP | Every object is end-to-end authenticated (AEAD + signatures); correctness never depends on TLS (§3.1) | None for content integrity |
| Plaintext | Capture plaintext | No plaintext ever crosses the wire (§7.11) | None |
| Causality | Replay an old response | Ops are content-addressed; heads are pinned; duplicate `op_id` rejected (§7.4) | None |

## 6. A3 — Malicious sharee or removed member

| Asset at risk | Attack | Mitigation (SPEC) | Residual |
| --- | --- | --- | --- |
| Vault they were granted | Read everything, forever | They were granted the vault key; nothing can un-share what they already saw | R-0105 |
| Future vault data | Keep reading after removal | VK rotation on removal, new `key_epoch` (§9.5) | Old epochs stay readable to them (R-0105) |
| Membership | Add themselves back, invite others, escalate | Membership ops require an authorised device and are visible in history (§9.1); the owner can revoke devices (§4.8) | A member with write access can make changes within their rights; the history shows exactly what they did |
| Other members' keys | Read wrapped keys meant for others | Per-member HPKE wrapping with `member_id` in the info (§9.2) | None |
| Identity | Impersonate the owner in the key log | Log entries are signed by the identity key; a sharee does not have it (§9.3) | None |

## 7. A4 — Malicious web page

This is the adversary that attacks the *user*, not the cryptography: look-alike
domains, invisible overlays, fake fill prompts, fake WebAuthn requests.

| Asset at risk | Attack | Mitigation (SPEC / AGENTS.md rule 11) | Residual |
| --- | --- | --- | --- |
| Credentials | Trick the user into typing them into a look-alike page | The extension never types into a page on its own; fill requires an explicit user action on a page whose origin the browser reports; the UI shows the full origin, not a favicon | User approves a homograph domain; the UI shows punycode and the full ASCII origin to make that harder |
| Fill/save prompts | Render a fake prompt inside page-controlled DOM (the DEF CON 33 class) | All prompts live in extension-owned surfaces (popup, sidebar, in-page *browser* overlay that pages cannot style or move); nothing is injected as page DOM | See §12.2 |
| User intent | Overlay a transparent element so a click lands on “allow” | Extension UI is not part of the page's stacking context; the browser draws it; clicks on it cannot be intercepted by page CSS | None for extension-drawn UI |
| Passkeys | Fake WebAuthn request, origin confusion | WebAuthn RP IDs are enforced by the browser; the extension never proxies a page's assertion without the browser's origin binding | None at the protocol level |
| Session | Page reads the extension's storage or messages | Extension storage is origin-isolated; no `externally_connectable`; no page-accessible resources | A hostile *extension* is A8 |

## 8. A5 — Stolen locked device

| Asset at risk | Attack | Mitigation (SPEC) | Residual |
| --- | --- | --- | --- |
| Vault at rest | Read the disk, copy the profile | Vault data is ciphertext under AK-derived keys; the MUK is never stored (§4.3) | A weak master password plus a stolen Secret Key can be guessed offline (R-0108) |
| Secret Key | Extract it from the OS keystore | Stored in the platform keystore when available, protected by the OS lock; Argon2id still gates the MUK | OS-level extraction on a rooted/jailbroken device |
| Recovery kit | Photograph the printed sheet | Kit holds the Secret Key but not the password; both are needed | R-0109 |
| Unlock oracle | Repeated guesses against the device | Argon2id at 64 MiB / t=3 per attempt; OS-level rate limiting | Offline guessing if the ciphertext and Secret Key are both extracted (R-0108) |

## 9. A6 — Malware on an unlocked device (out of scope)

**Why out of scope.** While the vault is unlocked, the plaintext has to be in
the process's memory to be shown, copied and edited, and the keys have to be
usable. Any code running as the same user — a keylogger, a screen recorder, a
memory scraper, a malicious accessibility service — can read all of it. No
client-side design fixes that: the OS gives no trusted display or trusted input
path to an ordinary application. Pretending otherwise would be a security claim
this design cannot back.

What the design *does* do, and tests:

- zeroize keys on lock, on error and on drop (§11.4);
- never write plaintext to disk, swap files or logs;
- reveal one field at a time, with the clipboard cleared after a timeout;
- keep secrets out of crash reports and telemetry (there is no telemetry).

What would actually help is OS-level: secure boot, EDR, least-privilege user
accounts, hardware-backed keystores. That is a product boundary, stated plainly
in the UI rather than hidden.

## 10. A7 — Supply-chain attacker

| Asset at risk | Attack | Mitigation (SPEC / repo) | Residual |
| --- | --- | --- | --- |
| Build integrity | Malicious crate or npm postinstall script | Approved crypto crates only (§11.1); `ignore-scripts=true`; lockfiles committed; `cargo deny` (advisories, licences, bans, sources); `pnpm audit --audit-level high` | An approved crate can still be compromised upstream (R-0112) |
| CI | Hijacked action tag, over-privileged token | Every action pinned to a commit SHA; `permissions: contents: read`; no `pull_request_target`; policy tests enforce it | A compromised pinned SHA is still a compromise (R-0112) |
| Secrets | Committed key or token | gitleaks on every push/PR; manual staged-diff scan before every commit | Novel formats (R-0004) |
| Releases | Tampered binary | Builds from source; lockfiles; signed tags planned in Phase 15 | No reproducible builds yet |

## 11. A8 — Hostile browser extension

| Asset at risk | Attack | Mitigation | Residual |
| --- | --- | --- | --- |
| Page content, keystrokes | Another extension reads pages and passwords | Browser extension isolation; Studge requests minimal permissions; no page-accessible resources | A hostile extension with page access can still phish the user; we cannot detect it |
| Studge's own UI | Impersonate the Studge popup | The browser draws extension UI; a page cannot fake it, another extension cannot draw inside ours | User confusion between a fake *web page* and the real popup — addressed by the calm, origin-first UI |
| Clipboard | Read passwords copied by the user | Clipboard is OS-wide by design; auto-clear after a timeout; no background clipboard reads by Studge | The OS clipboard manager may retain history |

<!-- THREAT-END -->
