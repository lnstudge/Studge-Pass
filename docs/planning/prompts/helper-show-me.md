<!-- Helper: show me where we are (live preview). Copy everything below this line into a new AutoClaw task. -->

Pause and show me where we are. Do not write new features in this task.
1. Read docs/preview/status.json, docs/PROGRESS.md and `git log --oneline -15`.
2. Run `pnpm preview:update` and start `pnpm preview`, then give me the URL.
3. Start every dev server that exists for the current phase (Storybook, the desktop app, the relay, the fixture site, the test relying party) and list their URLs.
4. Take fresh light and dark screenshots of everything visible and add them to the preview gallery.
5. Tell me in plain language: what works now, what I should click or run to see it, what is half-done, and what comes next.
If you changed status.json or screenshots, commit and push them following AGENTS.md.
