<!-- Phase 14: iOS app (needs a Mac). Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md and the docs. **Phase 14: the iOS app** in /ios (SwiftUI, iOS 17+). This needs a Mac with Xcode and an Apple Developer account.

- Build core as an XCFramework with UniFFI.
- Credential Provider Extension (ASCredentialProviderViewController) for passwords, one-time codes and passkeys.
- Unlock key wrapped by the Secure Enclave, with Face ID.
- ASCredentialImportManager and ASCredentialExportManager for passkey transfer on iOS 26.
- The same feature set as Android.

Commit and push following AGENTS.md, run the self-attack review, and open the pull request. Stop and report.
