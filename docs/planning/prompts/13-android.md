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

Targets:
- APK at most 20 MB.
- Cold start under 1.5 s on a 3 GB RAM phone.
- Hindi strings included.

Tests: unit tests, plus instrumentation tests for autofill and the credential provider on an emulator. Document Android Studio setup on Windows. Commit with -s. Stop and report.
