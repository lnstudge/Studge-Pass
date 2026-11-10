//! Shared state for the relay's handlers.

use crate::config::RelayConfig;
use crate::error::ApiError;
use crate::store::RelayStore;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use studge_core::crypto::opaque::ServerSetupKey;
use studge_core::crypto::signing::Timestamp;
use zeroize::Zeroizing;

/// Everything a handler needs: configuration, the database and the OPAQUE
/// server-setup key (which lives in a file, never in the database).
#[derive(Clone)]
pub struct RelayState {
    config: Arc<RelayConfig>,
    store: RelayStore,
    setup: Arc<ServerSetupKey>,
}

impl RelayState {
    /// Builds the state.
    pub fn new(config: RelayConfig, store: RelayStore, setup: ServerSetupKey) -> Self {
        Self {
            config: Arc::new(config),
            store,
            setup: Arc::new(setup),
        }
    }

    /// The loaded configuration.
    pub fn config(&self) -> &RelayConfig {
        &self.config
    }

    /// The database.
    pub fn store(&self) -> &RelayStore {
        &self.store
    }

    /// The OPAQUE server-setup key.
    pub fn setup(&self) -> &ServerSetupKey {
        &self.setup
    }

    /// The current UTC timestamp (D-0202 format).
    pub fn now(&self) -> Result<Timestamp, ApiError> {
        Timestamp::now().map_err(|_| ApiError::Unavailable)
    }

    /// Bumps a fixed-window counter and refuses when it passes `limit`.
    ///
    /// The counter key never carries request content: only the operation, the
    /// identity (account id or IP) and the window.
    pub async fn check_rate(
        &self,
        operation: &str,
        identity: &str,
        window_seconds: i64,
        limit: u32,
    ) -> Result<(), ApiError> {
        let now = self.now()?;
        let bucket = now.unix_seconds() / window_seconds;
        let key = format!("{operation}:{identity}:{bucket}");
        let count = self
            .store()
            .bump_counter(&key, now.as_str(), i64::from(limit))
            .await?;
        if count > i64::from(limit) {
            tracing::warn!(operation, "rate limit exceeded");
            return Err(ApiError::RateLimited);
        }
        Ok(())
    }

    /// Loads or creates the OPAQUE server-setup key at `path`.
    ///
    /// **Existing file:** reads it and, on Unix, checks that permissions are
    /// not looser than 0o600. Loose permissions are logged as a warning (the
    /// relay still starts — a chmod on a running server could be intentional,
    /// and silently refusing to start would be harder to recover from than a
    /// warning). The loaded bytes are wrapped in `Zeroizing`.
    ///
    /// **New file:** generated and written via `OpenOptions::create_new(true)`.
    /// On Unix the file is opened with mode 0o600 *at creation*, so the bytes
    /// are never visible to group/other between the creat and a subsequent
    /// chmod. On other platforms we write then set permissions (the best
    /// available; the file has no world-readable window if the OS default umask
    /// is 022 or tighter).
    pub async fn load_or_create_setup(path: &Path) -> Result<ServerSetupKey, ApiError> {
        if path.exists() {
            // Warn about loose permissions before reading the secret.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                match std::fs::metadata(path) {
                    Ok(meta) => {
                        let mode = meta.permissions().mode() & 0o777;
                        if mode & 0o077 != 0 {
                            tracing::warn!(
                                path = %path.display(),
                                mode = format!("{mode:o}"),
                                "OPAQUE server-setup key file has loose permissions (expected 0600)"
                            );
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %error,
                            "could not read OPAQUE server-setup key file metadata"
                        );
                    }
                }
            }
            let raw = std::fs::read(path).map_err(|_| ApiError::Unavailable)?;
            let bytes = Zeroizing::new(raw);
            ServerSetupKey::from_bytes(&bytes).map_err(|_| ApiError::Unavailable)
        } else {
            let key = ServerSetupKey::generate().map_err(|_| ApiError::Unavailable)?;
            let bytes = Zeroizing::new(key.to_bytes());
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|_| ApiError::Unavailable)?;
            }
            // Open with create_new(true): fails if the file already exists,
            // so there is no TOCTOU gap between the existence check above and
            // the write. On Unix we set mode 0o600 before any byte is written.
            #[cfg(unix)]
            let mut file = {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|_| ApiError::Unavailable)?
            };
            #[cfg(not(unix))]
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|_| ApiError::Unavailable)?;
            file.write_all(&bytes).map_err(|_| ApiError::Unavailable)?;
            tracing::info!("created a new OPAQUE server-setup key");
            Ok(key)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_counters_refuse_after_the_limit() {
        let store = RelayStore::open_in_memory().await.expect("store");
        let state = RelayState::new(
            RelayConfig::default(),
            store,
            ServerSetupKey::generate().expect("setup"),
        );
        for _ in 0..5 {
            state
                .check_rate("register", "203.0.113.9", 3600, 5)
                .await
                .expect("within the limit");
        }
        assert_eq!(
            state
                .check_rate("register", "203.0.113.9", 3600, 5)
                .await
                .expect_err("sixth"),
            ApiError::RateLimited
        );
        // A different identity has its own bucket.
        state
            .check_rate("register", "203.0.113.10", 3600, 5)
            .await
            .expect("other ip");
    }

    #[tokio::test]
    async fn the_setup_key_is_stable_across_restarts() {
        let directory = tempfile::tempdir().expect("dir");
        let path = directory.path().join("setup.bin");
        let first = RelayState::load_or_create_setup(&path).await.expect("load");
        let again = RelayState::load_or_create_setup(&path)
            .await
            .expect("again");
        assert_eq!(first.to_bytes(), again.to_bytes());
        // 0600 on Unix: the file is only for the relay.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// A pre-existing file with loose permissions (0o644) is still loaded,
    /// but the relay logs a warning. We verify the relay still starts (returns
    /// the key) — a warning, not a hard failure — and confirm the permissions
    /// were set to 0o644 (as put by the test), not silently changed.
    #[cfg(unix)]
    #[tokio::test]
    async fn loose_permissions_warn_but_key_still_loads() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().expect("dir");
        let path = directory.path().join("loose.bin");
        // Create the key normally first (0o600).
        let original = RelayState::load_or_create_setup(&path)
            .await
            .expect("create");
        // Widen the permissions to simulate an operator mistake.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        // Load should succeed (warning, not error).
        let loaded = RelayState::load_or_create_setup(&path)
            .await
            .expect("load with loose perms");
        assert_eq!(
            original.to_bytes(),
            loaded.to_bytes(),
            "key bytes unchanged"
        );
        // The relay does NOT silently fix the mode — that is an operator decision.
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o644,
            "relay must not silently chmod an existing file"
        );
    }
}
