<!-- Helper: security review. Copy everything below this line into a new AutoClaw task. -->

Act as a strict security reviewer, not as the author. Read AGENTS.md, docs/SPEC.md and docs/THREAT_MODEL.md. Then review all changes since commit <START-COMMIT>: run `git log --oneline <START-COMMIT>..HEAD` and `git diff <START-COMMIT>..HEAD`.

Check for:
1. deviations from SPEC.md
2. secrets that could be logged, printed, serialised, stored or left in memory
3. missing AAD bindings, unchecked signatures, or trusting relay or page data
4. unwrap, expect or panic on untrusted input
5. missing tamper or negative tests
6. new dependencies not justified in DECISIONS.md
7. TODOs hiding security work
8. anything that breaks the rules in AGENTS.md

Do NOT change any code. Save this prompt in Notion Prompts. Record each finding in Notion "Risks and findings" and open a GitHub issue for each one (labels: security, severity:<level>). Output a numbered list of findings. For each, give: severity (critical/high/medium/low), file:line, what is wrong, why it matters, and the fix. End with "Ship / Fix first" and one sentence of reasoning.
