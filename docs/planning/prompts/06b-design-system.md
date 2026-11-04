<!-- Phase 6b: design system and brand. Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md (especially the Design bar) and the docs. **Phase 6b: the Studge Pass design system and brand.** Do this before any app UI exists. Every later screen is built from it.

1. Research first. Write docs/DESIGN.md with a short written UX teardown of 1Password, Bitwarden, Proton Pass, Dashlane and Apple Passwords: what each does well, where each frustrates users, and exactly how Studge Pass will beat each one. Do not copy their visual identity.
2. Brand:
   - Personality: calm, confident, warm and trustworthy, with Indian roots but a global feel.
   - A simple SVG logo mark plus wordmark, and app icons for Windows, macOS, Linux, the browser extension (16–128 px) and Android (adaptive icon).
   - Avoid purple gradients and anything resembling Proton Pass.
3. Tokens: create a pnpm workspace package `@studge/design` in /design. Source the tokens in JSON (Style Dictionary) and generate CSS variables, TypeScript constants and Jetpack Compose colour/type files. Include:
   - colour: a deep teal primary, warm neutrals with a slight teal bias, semantic good, warning and critical, and a data-viz set. Light and dark palettes are designed separately and all pairs are contrast-checked.
   - type: an open-licence (OFL) variable UI font paired with Noto Sans Devanagari, Tamil, Telugu and Bengali. Use a modular type scale and bundle the fonts locally (no Google Fonts requests at runtime).
   - spacing (8-pt), radius, elevation, borders, motion durations and easing, z-index and breakpoints (including the 360×600 extension popup).
4. Components: a React library built on Radix UI primitives for accessibility, styled only with the tokens:
   - Button, IconButton, Input, Select, Checkbox, Switch, Tabs, Dialog, Sheet, Toast, Tooltip, Menu, Badge/Pill, Card, Banner (info/warning/critical), Skeleton, EmptyState
   - PasswordField (reveal toggle and strength meter)
   - CopyButton (with a 30 s clipboard countdown)
   - TotpCode (countdown ring)
   - MonogramAvatar
   - VaultListRow
   - ScoreRing (animated, reduced-motion aware)
   - ProgressBar (stacked)
   Use Lucide icons.
5. Storybook with light and dark modes and the a11y (axe) addon, showing every component and these full-page mockups at desktop width and at extension-popup width:
   - onboarding (create account, show Secret Key, choose sync)
   - unlock
   - vault list
   - item detail
   - item editor
   - generator
   - security dashboard
   - empty vault
6. Quality gates: zero axe violations, Playwright visual-regression snapshots of every story, and Vitest tests for component logic.
7. Self-critique: compare your mockups against the teardown in DESIGN.md, list the 5 weakest points, and fix them.

Checks for me: `pnpm --filter @studge/design storybook` opens Storybook in the browser.
Commit and push following AGENTS.md, run the self-attack review (for UI: XSS through item fields, clickjacking, leaking secrets into the DOM or logs), open the pull request, stop and report with screenshots.

Preview for me: keep Storybook running and give me its URL after every component batch. Put a screenshot of every component and mockup (light and dark) in the preview gallery as you go, not only at the end.
Follow "Show your work" in AGENTS.md: post your plan, narrate every step, and update docs/preview/status.json after each one.
