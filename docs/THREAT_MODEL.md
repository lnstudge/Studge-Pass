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
| R-0106 | A malicious relay can withhold ops — or freeze a vault by serving the pinned head forever; clients detect a gap but cannot obtain missing data | low | Accepted | Missing-parent error (§6.4) catches withholding; freeze is indistinguishable from “no changes” without a second channel (a second device or the folder transport), documented in §6.9 |
| R-0107 | Device revocation is time-based; clock skew lets a malicious device place ops just before `revoked_at` | low | Accepted | ±5 min rule (§6.11); revoke from another device immediately; history shows what happened |
| R-0108 | A weak master password plus a stolen Secret Key allows offline guessing | medium | Accepted | Argon2id 64 MiB/t=3/p=1, zxcvbn warnings, and the Secret Key requirement; password policy is a product decision in Phase 7 |
| R-0109 | The printed recovery kit can be photographed or stolen | medium | Accepted | It holds the Secret Key but not the password; both are required to unlock |
| R-0110 | The key-transparency log is run by the same untrusted relay, so a split view is possible | medium | Open | Consistency proofs between devices and safety codes (§9.3–9.4); an independent log operator is a Phase 11 design question |
| R-0111 | The 72-hour recovery window is enforced by the relay, which could shorten it | low | Open | Client-side warning to every device (§10.3); Phase 12 designs the notification path |
| R-0112 | An approved crate or a pinned action SHA can still be compromised upstream | medium | Accepted | `cargo deny`, `cargo audit`, Dependabot, pinned SHAs, review of every diff; no auto-merge |
| R-0113 | v1 membership is write-or-nothing: a member device holding the vault key can publish ops, so a “view only” share cannot be enforced | medium | Open | **Phase 11 MUST add owner-signed capabilities** so view-only sharing can be enforced (D-0117 approved, issue #18); the UI must not claim view-only today |
| R-0114 | A malicious member can name an extra field with a look-alike label (for example a Cyrillic “о” in “password”) to phish another member | low | Open | Clients render labels from item templates and quote unknown field names (§5.6); a test in Phase 3 covers the rendering rule |
| R-0115 | An attacker can talk the owner into approving *their* device during enrolment; the possession proof does not stop social engineering | medium | Open | Enrolment UI must show device name, platform and key fingerprint, and require an explicit confirmation on the already-trusted device (§4.7); Phase 7/8 implement and test it |
| R-0116 | Vault-key wrapping is X25519-only; no post-quantum protection for shared vaults yet | low | Open | The ML-KEM-768 identity key is stored from v1 (§4.6); **Phase 11 must re-check for a maintained hybrid HPKE / X-Wing crate and switch if one exists** (D-0105 condition). `hpke` 0.15.1 now ships X-Wing, so the re-check should pass |
| R-0117 | The `test-vectors` feature exposes fixed-nonce sealing; enabling it in a release build would weaken nonce handling | low | Accepted | The feature is documented test-only, `seal` has no nonce parameter, and CI enables it only in a dedicated test step |
| R-0118 | The Secret Key check character is 5 bits: a typo that stays inside the alphabet has a 1-in-32 chance of passing and then surfaces as a wrong MUK | low | Accepted | The failure is safe (no data loss, the recovery flow aborts with a clear error); a longer check would cost another printed character |
| R-0119 | HPKE base mode gives no sender authentication; anyone holding a public key can seal to it | low | Accepted | Correct for wrapping a vault key to a member — the recipient does not need to know who wrapped it. Phase 11 must not present it as authentication |
| R-0301 | A plaintext CSV or JSON export opened in a spreadsheet can execute a value: a password beginning with `=`, `+`, `-` or `@` is a formula (CSV injection). Our own importer reads raw CSV, so silently prefixing cells would corrupt round-trips | medium | Open | Export is opt-in, labelled `PLAINTEXT` and documented; a later export format that cannot execute (or an explicit “safe for spreadsheets” mode) closes it. Tracked as a follow-up issue |
| R-0302 | The KeePass XML importer ignores elements it does not recognise, so a foreign extension field is dropped rather than reported | low | Accepted | Only the KeePass 2.x element set is read and an unknown element is never turned into a field name (which would be R-0114); a dropped custom extension is the safer failure |
| R-0303 | A vault containing an op kind this build does not implement (`move`, `membership`, `key_rotation`) cannot be materialised at all | low | Accepted by design | Fail-closed: refusing the whole history beats silently ignoring an access-control or key-rotation op (D-0305). Phase 11 introduces the kinds with their payloads |
| R-0304 | The local SQLite file holds no plaintext, but its size, row counts and file times reveal how many items and ops a vault has | low | Accepted | The same metadata class as R-0101, on a device the attacker already had to access; nothing readable is stored (tested) |
| R-0305 | An importer that assembles a value piecewise (for example one that overwrites the field on every XML text event) silently truncates or rewrites it — a data-loss bug that looks like a successful import. Found in the PR #41 review: `<Value>p&lt;a&amp;s&gt;s"1</Value>` imported as `1` | medium | Fixed | Importers must be byte-exact and round-trip tested: KeePass XML values are accumulated (text + resolved entity references) and committed when the element closes, and export→import round-trip tests exist for the KeePass XML, JSON and CSV paths; every future importer ships with one too. Finding filed as issue #42 |

## 14. Phase 1 self-attack review (design level)

Attacking the document rather than a running system: for each vector, either a
named clause blocks it, or it is a recorded risk that later phases must close.

| # | Attack on the design | Where it lands | Verdict |
| --- | --- | --- | --- |
| 1 | Swap ciphertext between two fields of the same item | AAD carries `field_name` (§5.3) | Blocked |
| 2 | Move a field to another item that has the same field name | AAD carries `item_id` (§5.3) | Blocked |
| 3 | Copy an op into another vault | `vault_id` is signed and inside the AAD (§6.1–6.3) | Blocked |
| 4 | Modify an op and re-sign it | Requires the device's Ed25519 key (§6.3) | Blocked |
| 5 | Inflate the Lamport clock to win a conflict | `lamport = 1 + max(parents)` is mandatory (§6.5); a *member* can still win last-writer-wins by chaining ops they are allowed to make (§9.1) | Partly — R-0113 context |
| 6 | Serve an older head (rollback) | Descent from the pinned head is mandatory (§6.9) | Blocked, except first sync (R-0102) |
| 7 | Freeze: serve the pinned head forever while newer ops exist | Indistinguishable from “no changes” without a second channel (§6.9) | R-0106 |
| 8 | Truncate the tail of history | `op_count` and head descent (§6.8–6.9) | Blocked |
| 9 | Substitute a contact's public key during sharing | Transparency log + safety codes (§9.3–9.4) | Blocked after verification (R-0104) |
| 10 | Replay a recovery or emergency grant | Context binding via HPKE `info` and `key_epoch` (§9.2, §10.4) | Blocked; the relay can still shorten the wait (R-0111) |
| 11 | Brute-force the password from a stolen relay database | Needs the Secret Key to form the MUK (§4.3) | Blocked; kit theft changes that (R-0108) |
| 12 | Smuggle a non-canonical CBOR encoding past a signature check | Strict deterministic parsing and hashing (§1.4, §6.2) | Blocked |
| 13 | Spoof a field label in a shared vault with a look-alike name | Template labels, quoted unknown names (§5.6) | R-0114 |
| 14 | Talk the owner into approving the attacker's device | Possession proof only proves key possession, not intent (§4.7) | R-0115 |
| 15 | A “view only” sharee publishes ops | No read-only roles in v1 (§9.1) | R-0113 / D-0117 |

## 15. Appendix — Phase 0 self-attack review (historical)
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

## 16. Phase 2 self-attack review (crypto module)

Attacking `core/src/crypto` the way a malicious relay or a malicious member
would. Every "blocked" row names the test that fails if the protection is
removed; the rest are the three new risks above.

| # | Attack | Where it lands | Verdict |
| --- | --- | --- | --- |
| 1 | Flip any byte of the ciphertext | AEAD tag (`tamper::flipping_any_ciphertext_byte_fails`) | Blocked |
| 2 | Flip any byte of the 16-byte tag | AEAD tag (`flipping_any_tag_byte_fails`) | Blocked |
| 3 | Flip any byte of the nonce | AEAD tag (`flipping_any_nonce_byte_fails`) | Blocked |
| 4 | Truncate the ciphertext | Length check + tag (`truncating_the_ciphertext_fails`) | Blocked |
| 5 | Open a password field as the username field | AAD field name (`swapping_two_fields_of_the_same_item_fails`) | Blocked |
| 6 | Move a field to another item, vault or record type | AAD (`changing_any_aad_field_fails`) | Blocked |
| 7 | Open with the wrong key | AEAD (`wrong_key_fails`, property `a_wrong_key_never_opens`) | Blocked |
| 8 | Claim an older or unknown suite | Suite check (`unknown_suite_fails_at_parse`) | Blocked |
| 9 | Smuggle non-canonical CBOR past the parser | Strict re-encode (`non_canonical_envelope_fails_at_parse`, `strict_parser_rejects_non_canonical_maps`) | Blocked |
| 10 | Move a wrapped vault key to another vault or account | AAD + per-object salt (`wrapping_a_key_into_another_slot_fails`) | Blocked |
| 11 | Type the Secret Key with one wrong character | 5-bit checksum (`rejects_a_bad_checksum`); padding (`rejects_set_padding_bits`) | Blocked, with a 1-in-32 escape (R-0118) |
| 12 | Downgrade the KDF parameters recorded with an account | `derive_muk` minimums (`rejects_weak_parameters_and_unknown_versions`) | Blocked |
| 13 | Present a certificate for another account, in the future, or after revocation | Signing checks (`certificate_rejects_wrong_identity_account_and_time`, `certificate_respects_revocation_cutoff`) | Blocked |
| 14 | Open an HPKE seal with another recipient, info or AAD; tamper `enc` or `ct` | HPKE binding (`wrong_recipient_fails`, `wrong_info_or_aad_fails`, `tampered_enc_or_ciphertext_fails`) | Blocked |
| 15 | Read a secret out of a `Debug` print | Manual redaction on every key type (`debug_redacts_every_key_type`, `debug_never_prints_the_key`) | Blocked |
| 16 | Use fixed-nonce sealing in a release build | Opt-in feature only, `seal` always random (D-0203) | R-0117 |
| 17 | Forge a Secret Key typo into a working key | 5-bit check character | R-0118 |
| 18 | Treat HPKE sealing as proof of who sent it | Base mode has no sender auth | R-0119 |

## 17. Phase 3 self-attack review (vault, op log, storage, import/export)

Attacking the phase the way a malicious relay, a malicious member and a hostile
file would. Each "blocked" row names the test that fails if the protection is
removed; the rest are the four new risks above.

| # | Attack | Where it lands | Verdict |
| --- | --- | --- | --- |
| 1 | Edit a stored op payload and let the relay serve it | The payload is inside the signed op, so the hash changes (`oplog::materialise::tests::editing_the_payload_breaks_the_signature`) | Blocked |
| 2 | Publish a valid ciphertext under another item id (a malicious member with the vault key) | AAD binds vault and item (`a_tampered_payload_fails_materialisation`) | Blocked |
| 3 | Drop an op from the middle of the history | Missing parent is a hard error (`a_dropped_parent_is_a_hard_error`) | Blocked |
| 4 | Reorder ops or inflate the Lamport clock to win a conflict | `lamport = 1 + max(parents)` is enforced on insert (`rejects_a_wrong_lamport_clock`) | Blocked |
| 5 | Reuse an `op_id` with different content | Duplicate id with a different hash is refused (`rejects_a_replayed_op_id_with_new_content`) | Blocked |
| 6 | Serve an older head (rollback) | Descent from the pinned head is required (`a_rollback_is_detected`) | Blocked, except a device with no pin (R-0102) |
| 7 | Show two valid histories for one vault (fork) | Same counters and no descent is a fork (`a_fork_is_detected`) | Blocked |
| 8 | Sign ops with a revoked device | The registry refuses anything at or after `revoked_at` (`an_op_from_a_revoked_device_is_rejected`, `a_certified_device_is_usable_before_its_revocation`) | Blocked |
| 9 | Present a head signed by an uncertified device | Device key lookup before signature (`a_head_from_an_unknown_device_fails`) | Blocked |
| 10 | Inject a look-alike field name into an item (R-0114) | Field names are validated against the template on build and on parse (`rejects_unknown_and_look_alike_field_names`) | Blocked |
| 11 | Make a change disappear from the history | Losing ops stay in the DAG; the winner is only a display choice (`the_higher_lamport_wins_a_conflict`, `the_higher_device_id_breaks_a_lamport_tie`) | Blocked |
| 12 | Read plaintext from the local database of a locked device | The store has no plaintext column; a test greps the database file (`the_database_file_contains_no_plaintext`) | Blocked |
| 13 | Read plaintext from a `.studgevault` backup | Every record in it is already ciphertext (`the_file_contains_no_plaintext`) | Blocked |
| 14 | Swap two key-bundle entries, or drop one | Each entry has its own AAD (`every_bundle_entry_is_bound_to_its_name`, `a_dropped_entry_is_rejected`) | Blocked |
| 15 | Downgrade the KDF parameters recorded with an account | `derive_muk` refuses anything below the floor (`a_downgraded_kdf_is_rejected_at_unlock`) | Blocked |
| 16 | XML external entity, entity expansion or a deeply nested document in a KeePass import | DOCTYPE/entity/PI refused, depth capped at 64, value at 1 MiB (`rejects_doctype_and_entities`, `refuses_deep_nesting`) | Blocked |
| 17 | Memory bomb: a huge CSV, JSON or XML file | Size, row, column, depth and item caps (`check_input_size`, reader limits) | Blocked |
| 18 | Smuggle a non-canonical CBOR op past the parser | Strict re-encode and compare (`rejects_non_canonical_or_unknown_keys`) | Blocked |
| 19 | Executable value in a plaintext CSV opened in a spreadsheet | Nothing in core prevents it | R-0301 |
| 20 | Unsupported op kind used to smuggle an ACL change | Rejected with `UnsupportedOpKind` (D-0305) | R-0303 |
| 21 | An XML entity reference splits a value so the last piece wins (found in review: `p&lt;a&amp;s&gt;s"1` imported as `1`) | Values accumulate across `Text` and `GeneralRef` events and commit on the element close; round trips are byte-exact (`entity_references_no_longer_truncate_values`, `keepass_export_import_round_trip_is_byte_exact`) | Blocked (was R-0305, now fixed) |

## 18. Phase 4 self-attack review (relay server)

Attacking the relay as a malicious client and as a malicious relay operator.
Each "Blocked" row names the test that verifies it.

| # | Vector | Attacker | Mitigation | Verdict |
| --- | --- | --- | --- | --- |
| 1 | Send a `POST /v1/login/finish` before doing `POST /v1/login/start`, or replay a finalization | Malicious client | `take_login_state` is atomic DELETE-RETURNING; a replayed or orphaned finalization finds no state and returns 401 (`logout_and_token_revocation`, integration test) | Blocked |
| 2 | Brute-force passwords from different IPs to avoid per-account limits | Malicious client | Per-IP rate limit (60/hour) is enforced independently from per-account limit (10/hour); both fire (`state::tests::rate_counters_refuse_after_the_limit`) | Blocked, residual R-0401 (no lockout email) |
| 3 | Register with a fake `account_id` and certificate pointing to a different identity key, to impersonate another account | Malicious client | `register/finish` verifies the certificate against `identity_keys.ed25519` from the same request; a mismatch is 400 (`the_account_record_rejects_every_wrong_field`) | Blocked |
| 4 | Push ops to another account's vault (`account_id A` with `vault_id` of `account_id B`) | Malicious client | Vault ownership is checked before every op; a missing or foreign vault is 404, indistinguishable (`another_accounts_vault_is_404`) | Blocked |
| 5 | Send a `PUT /v1/vaults/:id/head` with `If-Match: *` to overwrite an existing head silently | Malicious client | `*` is only accepted when no head row exists; an existing head with a non-matching hash is 409 (`head_compare_and_swap_conflict`) | Blocked |
| 6 | Inject a token in a query string or URL to capture it in server logs | Malicious client | Bearer token is only accepted in the `Authorization` header; the relay never logs headers (SPEC §7.8); query string tokens are not parsed | Blocked |
| 7 | Submit an op with a `created_at` 25 hours in the past to slip under revocation cut-offs | Malicious client | `parse_ops` rejects any `created_at` outside ±24 h of server time (`extract::tests::parents_must_be_sorted_and_unique`, `append_and_fetch_ops_with_cursors`) | Blocked, residual R-0107 (±24 h still permits some post-revocation ops) |
| 8 | Submit an op with a future `created_at` to survive a later revocation | Malicious client | Same ±24 h check catches future timestamps too | Blocked (same residual) |
| 9 | Replay a valid `op_id` with different bytes to corrupt a vault | Malicious client | `op_hash_for_id` compares hashes; different bytes for the same `op_id` is 409 (`idempotent_op_push_is_accepted`) | Blocked |
| 10 | Send a non-canonical CBOR op body to exploit a differential parser | Malicious client | `StoredOp::from_cbor` uses a strict re-encode check; any deviation is 400 | Blocked |
| 11 | Serve a stale (old) head to a client to roll back its view | Malicious relay operator | A client that pins its last verified head detects rollback via `check_head_update` (§6.9); recorded as R-0106 | Partially blocked (requires client enforcement; relay side cannot prevent it) |
| 12 | Serve a subset of ops (withhold some) to hide an edit | Malicious relay operator | Missing parents are detected by the client on the next sync; the relay cannot make a missing parent invisible | Blocked at client layer |
| 13 | Delete the OPAQUE password file and reset a user's credential | Malicious relay operator | The relay controls the OPAQUE file; clients have no way to detect this without out-of-band notification | R-0403 (open) |
| 14 | Forge the account record to change `identity_keys.ed25519` and revoke all devices | Malicious relay operator | New devices verify the certificate chain; a forged key would fail certificate verification on any future `POST /v1/devices`. Existing sessions still work until they expire or are revoked | R-0404 (open, low — requires relay to simultaneously forge and the user to notice) |

### New risks recorded

| Risk | Severity | Status |
| --- | --- | --- |
| R-0401 — No email notification on account lockout (2.2.3) | low | Open — Phase 8 |
| R-0402 — No sliding inactivity timeout; 24-hour hard expiry only (D-0112) | low | Accepted |
| R-0403 — A malicious relay operator can delete the OPAQUE password file, forcing re-registration or account abandonment | medium | Open — Phase 13 (OPAQUE credential transparency) |
| R-0404 — A malicious relay operator can serve a forged account record with a different identity key; new device enrolments would fail, but existing sessions continue | low | Open — Phase 11 (key transparency) |
| R-0405 — `crypto-bigint v0.5.5` (transitive via `opaque-ke v4.0.1`) has a timing side-channel in big-integer arithmetic (RUSTSEC-2026-0387). Not a plaintext-exposure flaw. For our ristretto255 suite the hot cryptographic paths go through `curve25519-dalek`, not `crypto-bigint`; see D-0402. Ignored in `deny.toml` with justification. | low | Open — upgrade when opaque-ke ships fix |

## 19. Phase 5 self-attack review (sync engine and evil-relay harness)

Attacking the sync engine as a malicious relay that controls the bytes returned
from `pull`.  Every row names the test in `test-harness/tests/evil_relay_tests.rs`
that verifies the claim.

| # | Vector | Attacker | Transport-layer behaviour | Detection mechanism | Test | Verdict |
|---|---|---|---|---|---|---|
| 1 | Rollback the head to a previous snapshot after new ops exist | Malicious relay | Serve an old (signed) `VaultHead` with all ops | `check_head_update` detects the rollback (new head is an ancestor of pinned) | `evil_relay_rollback_is_detected` | **Blocked** |
| 2 | Ghost tip: head references an op hash the client has never seen | Malicious relay | Return honest ops + head pointing to `0xEE…EE` | Engine checks every tip in the head against the staged DAG | `evil_relay_ghost_head_entry_is_detected` | **Blocked** |
| 3 | Reorder ops (children before parents) | Malicious relay | Reverse the op list | DAG `add` rejects an op whose parent is not yet in the DAG → `MissingParent` | `evil_relay_reordered_ops_cause_missing_parent` | **Blocked** |
| 4 | Drop all ops but return the honest head | Malicious relay | Return empty op list + current head | Head references ops we don't have → `HeadReferencesUnknownOp` | `evil_relay_drop_ops_is_detected` | **Blocked** |
| 5 | Truncate op list (return only first n ops) | Malicious relay | Return ops[0..n] + honest head | Head references ops beyond n → `HeadReferencesUnknownOp` | `evil_relay_truncate_ops_is_detected` | **Blocked** |
| 6 | Swap the CBOR bytes of two ops | Malicious relay | ops[0] ← raw(op[1]), ops[1] ← raw(op[0]) | CBOR re-encode check: op_id / vault_id fields disagree with body → `MalformedPayload`; or child arrives before parent → `MissingParent` | `evil_relay_swapped_ciphertext_is_detected` | **Blocked** |
| 7 | Flip a bit in an op's payload (AEAD ciphertext) | Malicious relay | Flip a byte near end of raw CBOR | Re-encode check detects modified bytes → `MalformedPayload`; or AEAD decryption fails | `evil_relay_flipped_bit_is_detected` | **Blocked** |
| 8 | Strip the Ed25519 signature (zero all 64 sig bytes) | Malicious relay | Zero sig bytes in raw CBOR | Re-encode check catches the discrepancy, or `verify()` fails on the zeroed sig | `evil_relay_stripped_signature_is_detected` | **Blocked** |
| 9 | Substitute device certificate (flip head sig byte) | Malicious relay | Flip byte 40 in the head's raw CBOR (inside the Ed25519 signature) | `VaultHead::verify()` fails → `OpVerificationFailed` | `evil_relay_substitute_device_cert_is_detected` | **Blocked** |
| 10 | Replace vault_id in op bodies (cross-vault substitution) | Malicious relay | Replace 16-byte vault_id in raw CBOR of every op | Re-encode check: vault_id in AAD disagrees with body bytes → `MalformedPayload` | `evil_relay_wrong_vault_id_is_detected` | **Blocked** |
| 11 | Downgrade the suite id (`v1` → `v0`) in the head | Malicious relay | Replace CBOR text `"v1"` with `"v0"` in head bytes | `VaultHead::from_cbor` rejects unknown suite → `MalformedPayload` | `evil_relay_downgrade_suite_is_detected` | **Blocked** |
| 12 | Replay an old op (append it again after the stream) | Malicious relay | Append ops[0] again at the end of the op list | DAG `add` is idempotent: duplicate hash is silently ignored; client state unchanged | `evil_relay_replay_old_op_is_harmless` | **Harmless** (idempotent) |
| 13 | Withhold the head when a pin exists | Malicious relay | Return `None` head after client has a pin | Engine detects no-head-with-pin as a rollback → `RollbackDetected` | `evil_relay_withheld_head_is_detected` | **Blocked** |
| 14 | Withhold a subset of ops from one device to cause a fork | Malicious relay | Return ops[0..k] only + honest head | Missing parents → `MissingParent`; head references unknown ops → `HeadReferencesUnknownOp` | `evil_relay_truncate_ops_is_detected` | **Blocked** |
| 15 | ForkHead: head references ghost op hash | Malicious relay | Return honest ops + a head whose first tip is a ghost hash | Engine checks all tips against staged DAG → `HeadReferencesUnknownOp` | `evil_relay_fork_head_is_detected` | **Blocked** |
| 16 | Staged ops discarded on bad head (DAG atomicity) | Malicious relay | Inject a valid-sig op with unknown parent, plus a head pointing to it | Staged DAG rejects the op at step 2 (MissingParent); committed DAG unchanged | `fork_in_staged_ops_leaves_dag_unchanged` | **Blocked** |
| 17 | Push failure loses pending ops | n/a (I/O error) | `transport.push()` returns `Io` error | Engine restores `pending` queue before returning the error | `pending_ops_restored_on_push_failure` | **Fixed** |
| 18 | TOFU vault accepted without second-device confirmation | Malicious relay (or logic bug) | First sync pins the head but `is_tofu` stays true until `confirm_head()` | UI must call `confirm_head()` after verification; engine never auto-clears | `is_tofu_true_until_confirm_head_is_called` | **Fixed** |

### Phase 5 Review Fixes (2026-11-15)

The following bugs were found in the PR review and fixed before merge:

| Fix | Description | Named test |
|---|---|---|
| Fix 1 | `pub use folder::FolderTransport` in mod.rs was unconditional, breaking the wasm build | (build check) |
| Fix 2 | `FolderTransport` / `HttpRelayTransport` moved to `studge-sync-transports`; `reqwest` removed from core; `sync()` takes `now: Timestamp` parameter | (build check + all tests) |
| Fix 3a | Pending ops were drained before `transport.push()` and lost on `Io` error | `pending_ops_restored_on_push_failure` |
| Fix 3b | Withheld head (None) was silently accepted when a pin exists | `withheld_head_is_detected_when_pin_exists`, `evil_relay_withheld_head_is_detected` |
| Fix 3c | Pulled ops merged into the committed DAG before head checks | `fork_in_staged_ops_leaves_dag_unchanged` |
| Fix 3d | TOFU flag cleared on first sync instead of requiring `confirm_head()` | `is_tofu_true_until_confirm_head_is_called` |
| Fix 3e | Pull cursor used only the first DAG head, missing concurrent branches | `sync_with_two_concurrent_heads_fetches_all_ops` |
| Fix 4 | `ForkHead`, `DropOps`, `WrongVaultId` had no named evil-relay tests | `evil_relay_fork_head_is_detected`, `evil_relay_drop_ops_is_detected`, `evil_relay_wrong_vault_id_is_detected` |
| Fix 5 | D-0501 incorrectly said "Approved by founder" | `docs/DECISIONS.md` updated to "Status: Proposed" |

### Risks

| Risk | Severity | Status |
|---|---|---|
| R-0501 — A malicious relay that withholds ops indefinitely can delay convergence, but cannot forge or corrupt data; a future Phase 13 pull-proof mechanism is the mitigation | low | Open — Phase 13 |
| R-0502 — `FolderTransport` conflicted-copy files accumulate on disk if two writers collide; the engine tolerates them but disk quota can fill | low | Accepted (no production use until Phase 9) |
| R-0503 — `HttpRelayTransport` does not retry on transient network errors; the engine retries on the next sync cycle, which may be minutes later | low | Accepted (offline-first design handles this) |

<!-- THREAT-END -->
