use anyhow::{Context, Result};
use std::path::PathBuf;
use studge_core::storage::SqliteStore;

pub struct App {
    pub home: PathBuf,
    pub store_path: PathBuf,
    pub config_path: PathBuf,
}

impl App {
    pub fn new() -> Result<Self> {
        let home = if let Ok(v) = std::env::var("STUDGE_HOME") {
            PathBuf::from(v)
        } else {
            let base = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| ".".to_string());
            PathBuf::from(base).join(".studge")
        };
        std::fs::create_dir_all(&home).context("create home")?;
        let store_path = home.join("studge.db");
        let config_path = home.join("config.json");
        Ok(Self {
            home,
            store_path,
            config_path,
        })
    }

    pub fn open_store(&self) -> Result<SqliteStore> {
        SqliteStore::open(&self.store_path).context("open store")
    }
}
