# Notion back-fill queue (Phase 0)

Created on 2026-11-04 while the Notion API key was missing, per the AGENTS.md fallback
rule: keep working, log locally, back-fill Notion when it works again.

Processed into the Notion **Studge Pass: Build Log** on 2026-11-04. The page and
database IDs that were created are recorded in `docs/notion.json`. Future Notion
outages log to `docs/PROGRESS.md` per AGENTS.md; this file is the Phase 0 back-fill
queue and is kept as the record of what was back-filled.

No secrets in this file: it contains prompt text only (the master prompt already
lives in the repository at `docs/planning/prompts/00-master-setup.md`).

## Prompts to archive (word for word)

### P1 — Founder task message: "Start Phase 0 of Studge Pass." (2026-11-04)

<!-- backfill prompt start id="p1" -->
```text
Start Phase 0 of Studge Pass.

1. Read these files completely before doing anything:
   - docs/planning/prompts/00-master-setup.md (your full instructions for this task)
   - AGENTS.md (the project rulebook; it applies to every step). Pay special attention to "Development environment": run every cargo, pnpm and node command through .\x.ps1, never directly in PowerShell, and never use sudo.
2. Follow 00-master-setup.md exactly. Where it conflicts with anything else, AGENTS.md wins.
3. First, before writing any code:
   a. List the skills and connectors (Notion, GitHub) available to you and say which you will use.
   b. Save this message AND the full text of 00-master-setup.md, word for word, in the Notion "Prompts" database once you have created the Build Log.
   c. Post your plan as a numbered checklist.
4. Then work step by step, following "Show your work", "Connected tools" and the "Git workflow" in AGENTS.md: narrate each step, commit and push after every step on branch phase-00-setup, log every step in Notion, and keep docs/preview/status.json updated.
5. Never push to main, never merge, never put secrets in Notion. Stop when the Phase 0 pull request is open, and give me the summary the prompt asks for.
```
<!-- backfill prompt end id="p1" -->

### P2 — Master prompt: docs/planning/prompts/00-master-setup.md (full text, 2026-11-04)

Archived word for word from the repository file `docs/planning/prompts/00-master-setup.md`
(the single source of truth; the text is not duplicated here).

### P3 — Founder continuation message: Notion key, parent page, gh (2026-11-04)

<!-- backfill prompt start id="p3" -->
```text
The Notion key is now saved at ~/.config/notion/api_key (Windows home: C:\Users\lnstu\.config\notion\api_key), for the notion skill. Never print, log, copy or commit it.
Use ONLY the private page "Studge Pass" in my Notion workspace as the parent: create the "Studge Pass: Build Log" structure under it (Start here page + the six databases from AGENTS.md), save docs/notion.json with the page and database IDs, and never read or edit any other page in my workspace.
Then back-fill the Notion log from docs/notion-backfill.md and continue Phase 0.
gh: run it from Windows PowerShell, where it is signed in as lnstudge. If gh still fails from your shell, stop and tell me; do not log in or use tokens.
```
<!-- backfill prompt end id="p3" -->

## Phases row to create

- Phase 0 — Repository setup, rules and preview dashboard. Status: In progress.
  Branch: phase-00-setup. Start date: 2026-11-04.

## Execution log entries to create

### E1 — Step 1: Branch and phase plan (Pass)

- What and why: Read AGENTS.md and the Phase 0 master prompt in full, verified that
  AGENTS.md on disk matches the master prompt's target content exactly, then created
  the phase branch and recorded the 12-step Phase 0 plan in chat and in
  docs/preview/status.json before writing any code.
- Commands run: `git pull`; `git switch -c phase-00-setup`;
  `git push --dry-run -u origin phase-00-setup` (auth check);
  `git add docs/preview/status.json`; `git commit -s`; `git push -u origin phase-00-setup`.
- Key output: `Switched to a new branch 'phase-00-setup'`;
  `1 file changed, 121 insertions(+)`;
  `* [new branch] phase-00-setup -> phase-00-setup`.
- Result: Pass
- Commit: 13a26e249ccb88d7697648165a22e1059492d185
  (https://github.com/lnstudge/Studge-Pass/commit/13a26e249ccb88d7697648165a22e1059492d185)
- Skills used: —
