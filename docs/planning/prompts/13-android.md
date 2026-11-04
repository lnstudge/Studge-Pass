<!-- Phase 13: Android app. Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md and the docs. **Phase 13: the Android app** in /android (Kotlin, Jetpack Compose, minSdk 28, targetSdk latest stable). Use core through a new core-ffi crate with UniFFI bindings, built with cargo-ndk for arm64-v8a, armeabi-v7a and x86_64.

Features:
- Onboarding and unlock: BiometricPrompt, with the unlock key wrapped by Android Keystore (StrongBox when available).
- Vault list, search, detail and editor for all item types, including the India templates.
- Generator, TOTP and the Health tab.
- Sync via the relay, or a folder chosen through the Storage Access Framework.
- Passwords: an AutofillService with inline suggestions on Android 11+ keyboards, plus save prompts.
- Passkeys: a CredentialProviderService (androidx.credentials) for create and get, using the core authenticator. Verify callingAppInfo origins against Google's published privileged-browser allowlist.
- Passkey import/export through Credential Manager where the APIs exist.

Security (OWASP MASVS L2):
- FLAG_SECURE on every screen that shows secrets.
- Exclude the vault from cloud backup and device transfer (dataExtractionRules / allowBackup=false).
- No exported components except the autofill and credential provider services, each guarded by its system permission.
- Clipboard marked sensitive (ClipDescription EXTRA_IS_SENSITIVE) and cleared after 30 s.

Targets:
- APK at most 20 MB.
- Cold start under 1.5 s on a 3 GB RAM phone.
- Hindi strings included.

Tests: unit tests, plus instrumentation tests for autofill and the credential provider on an emulator. Document Android Studio setup on Windows. Commit and push following AGENTS.md, run the self-attack review, and open the pull request. Stop and report.

Design: use the @studge/design tokens and components from Phase 6b and follow the Design bar in AGENTS.md. Finish with light and dark screenshots in docs/screenshots/phase-13/ and a self-critique of where it falls short of the bar, then fix the top 3 issues before opening the PR.
