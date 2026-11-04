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

## 12. Attack-class mappings

### 12.1 ETH Zurich 2026 malicious-server classes

These are the four classes that paper names for password managers whose server
is honest-but-compromised-then-malicious. Each maps to a concrete control here.

| Class | How it works | Our mitigation | Residual |
| --- | --- | --- | --- |
| **Unauthenticated metadata and field swapping** | The server moves ciphertext between fields, items or records, or changes associated metadata the client does not authenticate | Every ciphertext carries AAD binding suite, scope id, item id, record type, field name and schema version (§5.3); ops are signed over their full header and payload hash (§6.2–6.3); a mismatch is a hard error (§5.8) | None for stored records |
| **Key substitution during sharing and org joining** | The server hands out its own public key as the contact's, receives the wrapped vault key, and decrypts | Key-transparency log with inclusion and consistency proofs (§9.3); safety codes compared out of band (§9.4); per-member `info` binding so a wrap cannot be replayed (§9.2) | Unverified first contact (R-0104) |
| **Legacy-crypto downgrade** | The server claims the client must use an older, weaker suite or KDF parameters | Exactly one suite, `v1`; unknown versions rejected (§11.2); `kdf.version` forward-only with hard minimums (§4.3, §11.3); no “compatibility mode” | None |
| **Rollback** | The server serves an older but internally valid state | Signed heads with `op_count`/`lamport_max` (§6.8); clients pin the last verified head and require every new head to descend from it (§6.9); a fresh device uses the bundle hint and is TOFU (R-0102) | R-0102 for a device with no pin |

### 12.2 DEF CON 33 DOM-based extension clickjacking

The attack: a page styles or overlays elements that an extension has injected
into the page's own DOM — for example with `opacity: 0`, `pointer-events`, or a
stacking-context trick — so that a click the user aims at the page activates an
extension control (a fill button, a “save password” prompt), or a look-alike
overlay sits where the extension's UI is expected.

| Requirement | Our control |
| --- | --- |
| Never render fill or save prompts inside page-controlled DOM | AGENTS.md rule 11. Prompts live in browser-drawn surfaces: the extension popup, the sidebar, or a browser-level overlay outside the page's document. Nothing the page can style is part of a security decision. |
| Take the origin from the browser, never from page data | `sender.origin`/`sender.tab.url` from the browser's message metadata; page-provided strings are display-only and never used for matching. |
| No silent fill | Filling requires an explicit user action in extension UI; there is no auto-fill on page load and no programmatic fill triggered by page script. |
| Passkeys | WebAuthn origin and RP ID binding is enforced by the browser; the extension never forwards a page's request without that binding. |
| Visual honesty | The prompt shows the full ASCII origin (punycode where relevant), not a favicon fetched from the site (AGENTS.md privacy rule). |

Residual: a page can still present a convincing *web* login form; that is
phishing (A4), mitigated by the origin display and user education, not by DOM
isolation.

## 13. Open risks

Ids are stable; later phases close them by referencing the id in a commit and
moving the status. Severity is about impact × likelihood for a real user, not
about how interesting the bug is.

| Id | Risk | Severity | Status | Mitigation / what closes it |
| --- | --- | --- | --- | --- |
| R-0001 | CodeQL code scanning skipped while the repository is private (no GHAS) | medium | Open (#23) | Make the repo public or enable GHAS |
| R-0002 | Link targets in `status.json` are trusted from the repository | low | Accepted | Reviewed in every PR; revisit if the file becomes writable by anything else |
| R-0003 | Preview dev server needs `style-src 'unsafe-inline'` for Vite HMR | low | Accepted | Loopback only, no third-party data; must not be copied into product UI |
| R-0004 | gitleaks can miss novel secret formats | low | Accepted | Manual staged-diff scan before every commit |
| R-0005 | `minimatch` advisory in dev-only ESLint tooling | low | Accepted | CI fails on high/critical; Dependabot tracks the fix |
| R-0101 | The relay learns metadata: ids, ciphertext sizes, op counts, timing, IP | low | Accepted | Padding and cover traffic are out of scope for v1; self-hosting removes the third party |
| R-0102 | A device with no pinned head can be rolled back before its first verification (TOFU) | medium | Accepted | Head pins in the key bundle (§4.5) narrow the window; a second device or a safety-code check closes it. Phase 5 tests the exact behaviour |
| R-0103 | A cloned VM snapshot or broken RNG could repeat a 24-byte nonce | low | Accepted | `OsRng` only, no software fallback; nonce reuse under XChaCha20-Poly1305 is catastrophic but requires an RNG failure the OS should prevent |
| R-0104 | Key substitution on first contact before a safety code is verified | medium | Accepted | Safety codes (§9.4) and transparency proofs (§9.3); the first contact is explicitly marked unverified in the UI |
| R-0105 | A removed member keeps history they already saw; rotation only protects future data | medium | Accepted by design | Stated in the UI at removal time; the alternative (re-encrypting all history per member) is not affordable |
| R-0106 | A malicious relay can withhold ops (censorship); clients detect a gap but cannot obtain the missing data elsewhere | low | Accepted | Missing-parent error (§6.4) plus a second relay or the folder transport as an escape hatch |
| R-0107 | Device revocation is time-based; clock skew lets a malicious device place ops just before `revoked_at` | low | Accepted | ±5 min rule (§6.11); revoke from another device immediately; history shows what happened |
| R-0108 | A weak master password plus a stolen Secret Key allows offline guessing | medium | Accepted | Argon2id 64 MiB/t=3/p=1, zxcvbn warnings, and the Secret Key requirement; password policy is a product decision in Phase 7 |
| R-0109 | The printed recovery kit can be photographed or stolen | medium | Accepted | It holds the Secret Key but not the password; both are required to unlock |
| R-0110 | The key-transparency log is run by the same untrusted relay, so a split view is possible | medium | Open | Consistency proofs between devices and safety codes (§9.3–9.4); an independent log operator is a Phase 11 design question |
| R-0111 | The 72-hour recovery window is enforced by the relay, which could shorten it | low | Open | Client-side warning to every device (§10.3); Phase 12 designs the notification path |
| R-0112 | An approved crate or a pinned action SHA can still be compromised upstream | medium | Accepted | `cargo deny`, `cargo audit`, Dependabot, pinned SHAs, review of every diff; no auto-merge |

## 14. Appendix — Phase 0 self-attack review (historical)

Recorded during Phase 0 against the repository, CI and the preview dashboard.
Full detail and test names: `docs/PROGRESS.md` (Phase 0) and the Phase 0 PR.

| # | Vector | Control | Status |
| --- | --- | --- | --- |
| 1 | Stored XSS through `status.json` | `textContent`-only rendering, ESLint sink bans, static-scan tests, CSP without `unsafe-eval` | Blocked |
| 2 | Screenshot path traversal / other origins | Schema pattern + `screenshotUrl()` allowlist + existence check | Blocked |
| 3 | npm install-script RCE | `ignore-scripts=true`, policy test | Blocked |
| 4 | Hijacked action tag | Every `uses:` pinned to a 40-char SHA, policy test | Blocked |
| 5 | `pull_request_target` / write-token escalation | No target, `contents: read`, policy tests | Blocked |
| 6 | Committed secret | gitleaks on every push/PR + manual diff scan | Blocked (one false positive triaged) |
| 7 | Vulnerable or yanked crate | `cargo deny` (advisories, yanked), weekly `cargo audit` | Blocked |
| 8 | Licence contamination | `cargo deny` licence allowlist | Blocked |
| 9 | LAN exposure of relay/dashboard | Constant `127.0.0.1` binds, tests | Blocked |
| 10 | `unwrap`/`expect`/`panic!` on future input paths | Production-source scan test + clippy `-D warnings` | Blocked |
| 11 | Hostile link in `status.json` | PR review | R-0002 (accepted) |
| 12 | Reading files outside `docs/` via the dev server | `server.fs.allow` limited to the repo, loopback only | R-0003 (accepted) |
| 13 | `pnpm shot` pointed at a hostile page | Helper only renders and screenshots; no credentials | Accepted |
| 14 | Secret format gitleaks does not know | Manual diff review | R-0004 (accepted) |
| 15 | High-severity npm advisory | `pnpm audit --audit-level high` in CI | Blocked (moderate tracked as R-0005) |

<!-- THREAT-END -->
