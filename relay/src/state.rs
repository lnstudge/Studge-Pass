//! Shared state for the relay's handlers.

use crate::config::RelayConfig;
use crate::error::ApiError;
use crate::store::RelayStore;
use std::path::Path;
use std::sync::Arc;
use studge_core::crypto::opaque::ServerSetupKey;
use studge_core::crypto::signing::Timestamp;

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

    /// Loads or creates the OPAQUE server-setup key at `path`. The file holds
    /// the relay's long-term OPAQUE secret and is never stored in the
    /// database; on Unix it is created with 0600 permissions.
    pub async fn load_or_create_setup(path: &Path) -> Result<ServerSetupKey, ApiError> {
        if path.exists() {
            let bytes = std::fs::read(path).map_err(|_| ApiError::Unavailable)?;
            ServerSetupKey::from_bytes(&bytes).map_err(|_| ApiError::Unavailable)
        } else {
            let key = ServerSetupKey::generate().map_err(|_| ApiError::Unavailable)?;
            let bytes = key.to_bytes();
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(path, &bytes).map_err(|_| ApiError::Unavailable)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
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
}
