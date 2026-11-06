//! Shared state for the relay's handlers.

use crate::config::RelayConfig;

/// Everything a handler needs. Grows with the storage pool and the OPAQUE
/// server setup in the next steps.
#[derive(Clone)]
pub struct RelayState {
    config: RelayConfig,
}

impl RelayState {
    /// Builds the state from the loaded configuration.
    pub fn new(config: RelayConfig) -> Self {
        Self { config }
    }

    /// The loaded configuration.
    pub fn config(&self) -> &RelayConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carries_the_config() {
        let state = RelayState::new(RelayConfig::default());
        assert_eq!(state.config().listen.to_string(), "127.0.0.1:8787");
    }
}
