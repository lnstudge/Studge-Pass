<!-- Helper: red-team attack. Copy everything below this line into a new AutoClaw task. -->

Act as an elite, hostile red team hired to break Studge Pass. Do NOT fix anything in this task. Read AGENTS.md, docs/SPEC.md and docs/THREAT_MODEL.md, then study the code on main.

Attack it from every angle:
- malicious relay server
- network attacker
- malicious website against the extension (phishing look-alike domains, clickjacking, iframes, fake WebAuthn requests, postMessage tricks)
- malicious shared-vault member
- stolen locked device
- hostile browser extension
- poisoned dependency or CI workflow
- malicious import files (zip bombs, huge CSVs, malformed CBOR or JSON)
- side channels (timing, logs, clipboard, crash reports, swap files)

For each real weakness, write a failing test or a proof-of-concept under test-harness/redteam/ that demonstrates it. Put them on a branch named `redteam-<date>`, commit and push following AGENTS.md, and open a pull request titled "Red team findings <date>". Open a GitHub issue for each finding (labels: security, severity:<level>, redteam) and record each one in Notion "Risks and findings". Save this prompt in Notion Prompts first. Use any security or testing skills you have.

Report a ranked list: severity, attack steps, affected file:line, proof (test name) and suggested fix. Be ruthless and specific. Never report a weakness without a proof or a precise reasoning chain.
