use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub account_id: Option<String>,
    pub device_id: Option<String>,
    pub identity_public: Option<String>,
    pub vault_id: Option<String>,
    pub relay_url: Option<String>,
    pub folder_path: Option<String>,
    pub session_minutes: u64,
    pub device_key_seed: Option<String>, // hex, zeroized on drop? stored encrypted ideally
}

impl Config {
    pub fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                session_minutes: 15,
                ..Default::default()
            });
        }
        let data = fs::read_to_string(path).context("read config")?;
        let mut cfg: Config = serde_json::from_str(&data).context("parse config")?;
        if cfg.session_minutes == 0 {
            cfg.session_minutes = 15;
        }
        Ok(cfg)
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let data = serde_json::to_string_pretty(self).context("serialize config")?;
        fs::write(path, data).context("write config")?;
        Ok(())
    }
}
