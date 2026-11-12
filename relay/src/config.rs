//! Relay configuration: a TOML file plus `STUDGE_RELAY_*` overrides.
//!
//! Every limit the brief names is here, with the SPEC §7.7 values as defaults,
//! so an operator can see and change them in one place. Environment variables
//! win over the file, and the file is optional: with no file and no variables
//! the relay listens on loopback with a database beside its working directory.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

/// Default listen address (loopback only, per Phase 0).
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8787";
/// Default SQLite file.
pub const DEFAULT_DATABASE: &str = "studge-relay.db";
/// Default OPAQUE server-setup key file.
pub const DEFAULT_SERVER_SETUP: &str = "studge-relay-opaque.bin";
/// SPEC §7.1: request bodies are capped at 8 MiB.
pub const DEFAULT_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
/// SPEC §6.11 and §7.7: at most 100 ops per push.
pub const DEFAULT_MAX_OPS_PER_PUSH: usize = 100;
/// SPEC §7.7 / D-0110: 100 MiB of vault data per account.
pub const DEFAULT_STORAGE_QUOTA_BYTES: i64 = 100 * 1024 * 1024;
/// SPEC §7.7: 10 login attempts per hour per account.
pub const DEFAULT_LOGIN_PER_ACCOUNT_HOUR: u32 = 10;
/// SPEC §7.7: 60 login attempts per hour per IP.
pub const DEFAULT_LOGIN_PER_IP_HOUR: u32 = 60;
/// SPEC §7.7: 5 registrations per hour per IP.
pub const DEFAULT_REGISTER_PER_IP_HOUR: u32 = 5;
/// SPEC §7.7: 60 pushes per minute per account.
pub const DEFAULT_PUSH_PER_ACCOUNT_MINUTE: u32 = 60;
/// SPEC §7.7: 300 reads per minute per account.
pub const DEFAULT_READ_PER_ACCOUNT_MINUTE: u32 = 300;
/// SPEC §7.1: a stalled request is dropped rather than held open.
pub const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 30;

/// A trusted reverse-proxy: an exact IP address or a CIDR prefix.
///
/// Only requests from a trusted proxy are allowed to supply `X-Forwarded-For`.
/// This prevents an untrusted client from spoofing its IP to evade rate limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedProxy {
    /// The network address (host bits zeroed).
    pub addr: IpAddr,
    /// Prefix length (32 for IPv4 host, 128 for IPv6 host).
    pub prefix_len: u8,
}

impl TrustedProxy {
    /// Returns `true` when `ip` falls inside this prefix.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                let mask = if self.prefix_len == 0 {
                    0u32
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                (u32::from(net) & mask) == (u32::from(candidate) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                let mask = if self.prefix_len == 0 {
                    0u128
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                (u128::from(net) & mask) == (u128::from(candidate) & mask)
            }
            // IPv4 and IPv6 never mix.
            _ => false,
        }
    }
}

impl std::str::FromStr for TrustedProxy {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((addr_str, len_str)) = s.split_once('/') {
            let addr: IpAddr = addr_str.parse().map_err(|_| ConfigError::Invalid)?;
            let prefix_len: u8 = len_str.parse().map_err(|_| ConfigError::Invalid)?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            if prefix_len > max {
                return Err(ConfigError::Invalid);
            }
            Ok(Self { addr, prefix_len })
        } else {
            // Single IP: treat as /32 or /128.
            let addr: IpAddr = s.parse().map_err(|_| ConfigError::Invalid)?;
            let prefix_len = if addr.is_ipv4() { 32 } else { 128 };
            Ok(Self { addr, prefix_len })
        }
    }
}

/// The whole relay configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
    /// Where the HTTP server listens.
    pub listen: SocketAddr,
    /// SQLite database file.
    pub database_path: PathBuf,
    /// OPAQUE `ServerSetup` file (never in the database).
    pub server_setup_path: PathBuf,
    /// Largest accepted request body.
    pub max_body_bytes: usize,
    /// Largest number of ops in one push.
    pub max_ops_per_push: usize,
    /// Vault bytes allowed per account.
    pub storage_quota_bytes: i64,
    /// Login attempts per hour per account.
    pub login_per_account_hour: u32,
    /// Login attempts per hour per IP.
    pub login_per_ip_hour: u32,
    /// Registrations per hour per IP.
    pub register_per_ip_hour: u32,
    /// Pushes per minute per account.
    pub push_per_account_minute: u32,
    /// Reads per minute per account.
    pub read_per_account_minute: u32,
    /// `Access-Control-Allow-Origin` allowlist (desktop app and extension IDs).
    pub cors_origins: Vec<String>,
    /// Trusted reverse-proxy addresses/CIDRs. Only these peers may supply
    /// `X-Forwarded-For`; others are ignored. Default: empty (direct mode).
    pub trusted_proxies: Vec<TrustedProxy>,
    /// Whether client IP addresses may appear in logs.
    pub log_ip_addresses: bool,
    /// Whether logs are JSON.
    pub log_json: bool,
    /// Request timeout.
    pub request_timeout_seconds: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN.parse().unwrap_or_else(|_| {
                // The constant is a valid socket address; this arm is
                // unreachable and only exists to avoid an `unwrap` in prod.
                SocketAddr::from(([127, 0, 0, 1], 8787))
            }),
            database_path: PathBuf::from(DEFAULT_DATABASE),
            server_setup_path: PathBuf::from(DEFAULT_SERVER_SETUP),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_ops_per_push: DEFAULT_MAX_OPS_PER_PUSH,
            storage_quota_bytes: DEFAULT_STORAGE_QUOTA_BYTES,
            login_per_account_hour: DEFAULT_LOGIN_PER_ACCOUNT_HOUR,
            login_per_ip_hour: DEFAULT_LOGIN_PER_IP_HOUR,
            register_per_ip_hour: DEFAULT_REGISTER_PER_IP_HOUR,
            push_per_account_minute: DEFAULT_PUSH_PER_ACCOUNT_MINUTE,
            read_per_account_minute: DEFAULT_READ_PER_ACCOUNT_MINUTE,
            cors_origins: Vec::new(),
            trusted_proxies: Vec::new(),
            log_ip_addresses: true,
            log_json: false,
            request_timeout_seconds: DEFAULT_REQUEST_TIMEOUT_SECONDS,
        }
    }
}

impl RelayConfig {
    /// Reads a TOML file (if it exists), then applies `STUDGE_RELAY_*`.
    pub fn load(path: Option<&std::path::Path>) -> Result<Self, ConfigError> {
        let mut config = Self::default();
        if let Some(path) = path {
            if path.exists() {
                let text = std::fs::read_to_string(path).map_err(|_| ConfigError::Unreadable)?;
                config.apply_toml(&text)?;
            }
        }
        config.apply_env(std::env::vars())?;
        config.validate()?;
        Ok(config)
    }

    /// Applies a TOML document over the current values.
    pub fn apply_toml(&mut self, text: &str) -> Result<(), ConfigError> {
        let table: toml::Table = toml::from_str(text).map_err(|_| ConfigError::Invalid)?;
        let known: [&str; 7] = KNOWN_SECTIONS;
        for key in table.keys() {
            if !known.contains(&key.as_str()) {
                // A typo in a security-relevant limit must not be ignored.
                return Err(ConfigError::UnknownSection);
            }
        }
        if let Some(server) = section(&table, "server")? {
            if let Some(listen) = server.get("listen") {
                let text = listen.as_str().ok_or(ConfigError::Invalid)?;
                self.listen = text.parse().map_err(|_| ConfigError::Invalid)?;
            }
        }
        if let Some(database) = section(&table, "database")? {
            if let Some(path) = database.get("path") {
                self.database_path = PathBuf::from(path.as_str().ok_or(ConfigError::Invalid)?);
            }
        }
        if let Some(opaque) = section(&table, "opaque")? {
            if let Some(path) = opaque.get("server_setup_path") {
                self.server_setup_path = PathBuf::from(path.as_str().ok_or(ConfigError::Invalid)?);
            }
        }
        if let Some(limits) = section(&table, "limits")? {
            self.max_body_bytes = unsigned(limits, "max_body_bytes", self.max_body_bytes)?;
            self.max_ops_per_push = unsigned(limits, "max_ops_per_push", self.max_ops_per_push)?;
            self.storage_quota_bytes = unsigned(
                limits,
                "storage_quota_bytes",
                self.storage_quota_bytes as usize,
            )? as i64;
            self.request_timeout_seconds = unsigned(
                limits,
                "request_timeout_seconds",
                self.request_timeout_seconds as usize,
            )? as u64;
        }
        if let Some(rates) = section(&table, "rates")? {
            self.login_per_account_hour = unsigned(
                rates,
                "login_per_account_hour",
                self.login_per_account_hour as usize,
            )? as u32;
            self.login_per_ip_hour =
                unsigned(rates, "login_per_ip_hour", self.login_per_ip_hour as usize)? as u32;
            self.register_per_ip_hour = unsigned(
                rates,
                "register_per_ip_hour",
                self.register_per_ip_hour as usize,
            )? as u32;
            self.push_per_account_minute = unsigned(
                rates,
                "push_per_account_minute",
                self.push_per_account_minute as usize,
            )? as u32;
            self.read_per_account_minute = unsigned(
                rates,
                "read_per_account_minute",
                self.read_per_account_minute as usize,
            )? as u32;
        }
        if let Some(cors) = section(&table, "cors")? {
            if let Some(origins) = cors.get("allowed_origins") {
                let list = origins.as_array().ok_or(ConfigError::Invalid)?;
                let mut out = Vec::with_capacity(list.len());
                for origin in list {
                    out.push(origin.as_str().ok_or(ConfigError::Invalid)?.to_string());
                }
                self.cors_origins = out;
            }
            if let Some(proxies) = cors.get("trusted_proxies") {
                let list = proxies.as_array().ok_or(ConfigError::Invalid)?;
                let mut out = Vec::with_capacity(list.len());
                for proxy in list {
                    out.push(
                        proxy
                            .as_str()
                            .ok_or(ConfigError::Invalid)?
                            .parse::<TrustedProxy>()?,
                    );
                }
                self.trusted_proxies = out;
            }
        }
        if let Some(log) = section(&table, "log")? {
            if let Some(ip) = log.get("ip_addresses") {
                self.log_ip_addresses = ip.as_bool().ok_or(ConfigError::Invalid)?;
            }
            if let Some(json) = log.get("json") {
                self.log_json = json.as_bool().ok_or(ConfigError::Invalid)?;
            }
        }
        Ok(())
    }

    /// Applies `STUDGE_RELAY_*` environment variables.
    pub fn apply_env<I>(&mut self, vars: I) -> Result<(), ConfigError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        for (key, value) in vars {
            let Some(name) = key.strip_prefix("STUDGE_RELAY_") else {
                continue;
            };
            match name {
                "LISTEN" => self.listen = value.parse().map_err(|_| ConfigError::Invalid)?,
                "DATABASE_PATH" => self.database_path = PathBuf::from(value),
                "SERVER_SETUP_PATH" => self.server_setup_path = PathBuf::from(value),
                "MAX_BODY_BYTES" => {
                    self.max_body_bytes = value.parse().map_err(|_| ConfigError::Invalid)?
                }
                "MAX_OPS_PER_PUSH" => {
                    self.max_ops_per_push = value.parse().map_err(|_| ConfigError::Invalid)?
                }
                "STORAGE_QUOTA_BYTES" => {
                    self.storage_quota_bytes = value.parse().map_err(|_| ConfigError::Invalid)?
                }
                "LOGIN_PER_ACCOUNT_HOUR" => {
                    self.login_per_account_hour = value.parse().map_err(|_| ConfigError::Invalid)?
                }
                "LOGIN_PER_IP_HOUR" => {
                    self.login_per_ip_hour = value.parse().map_err(|_| ConfigError::Invalid)?
                }
                "REGISTER_PER_IP_HOUR" => {
                    self.register_per_ip_hour = value.parse().map_err(|_| ConfigError::Invalid)?
                }
                "PUSH_PER_ACCOUNT_MINUTE" => {
                    self.push_per_account_minute =
                        value.parse().map_err(|_| ConfigError::Invalid)?
                }
                "READ_PER_ACCOUNT_MINUTE" => {
                    self.read_per_account_minute =
                        value.parse().map_err(|_| ConfigError::Invalid)?
                }
                "LOG_IP_ADDRESSES" => {
                    self.log_ip_addresses = parse_bool(&value)?;
                }
                "LOG_JSON" => self.log_json = parse_bool(&value)?,
                "CORS_ORIGINS" => {
                    self.cors_origins = value
                        .split(',')
                        .map(|origin| origin.trim())
                        .filter(|origin| !origin.is_empty())
                        .map(|origin| origin.to_string())
                        .collect();
                }
                "TRUSTED_PROXIES" => {
                    let mut out = Vec::new();
                    for item in value.split(',') {
                        let item = item.trim();
                        if !item.is_empty() {
                            out.push(item.parse::<TrustedProxy>()?);
                        }
                    }
                    self.trusted_proxies = out;
                }
                "REQUEST_TIMEOUT_SECONDS" => {
                    self.request_timeout_seconds =
                        value.parse().map_err(|_| ConfigError::Invalid)?
                }
                _ => return Err(ConfigError::UnknownVariable),
            }
        }
        Ok(())
    }

    /// Refuses configurations that cannot be safe.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_body_bytes == 0
            || self.max_body_bytes > 64 * 1024 * 1024
            || self.max_ops_per_push == 0
            || self.max_ops_per_push > 1000
            || self.storage_quota_bytes < 1024
            || self.request_timeout_seconds == 0
            || self.request_timeout_seconds > 600
        {
            return Err(ConfigError::OutOfRange);
        }
        for origin in &self.cors_origins {
            if origin == "*"
                || !origin.starts_with("http")
                    && !origin.starts_with("tauri://")
                    && !origin.starts_with("chrome-extension://")
            {
                // No wildcard CORS: the bearer token is the only credential.
                return Err(ConfigError::InvalidCorsOrigin);
            }
        }
        Ok(())
    }
}

/// The sections a config file may contain.
const KNOWN_SECTIONS: [&str; 7] = [
    "server", "database", "opaque", "limits", "rates", "cors", "log",
];

/// Returns `true` when `ip` is covered by any entry in `proxies`.
pub fn is_trusted_proxy(proxies: &[TrustedProxy], ip: IpAddr) -> bool {
    proxies.iter().any(|p| p.contains(ip))
}

fn section<'a>(table: &'a toml::Table, name: &str) -> Result<Option<&'a toml::Table>, ConfigError> {
    match table.get(name) {
        None => Ok(None),
        Some(value) => value.as_table().map(Some).ok_or(ConfigError::Invalid),
    }
}

fn unsigned(table: &toml::Table, key: &str, current: usize) -> Result<usize, ConfigError> {
    match table.get(key) {
        None => Ok(current),
        Some(value) => {
            let raw = value.as_integer().ok_or(ConfigError::Invalid)?;
            usize::try_from(raw).map_err(|_| ConfigError::OutOfRange)
        }
    }
}

fn parse_bool(value: &str) -> Result<bool, ConfigError> {
    match value {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::Invalid),
    }
}

/// Why a configuration was rejected. Messages never echo values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// The file could not be read.
    Unreadable,
    /// The file is not valid TOML or a value has the wrong type.
    Invalid,
    /// A section the relay does not know.
    UnknownSection,
    /// An environment variable the relay does not know.
    UnknownVariable,
    /// A number outside the accepted range.
    OutOfRange,
    /// A CORS origin that would defeat the allowlist.
    InvalidCorsOrigin,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Unreadable => "configuration file could not be read",
            Self::Invalid => "configuration is not valid",
            Self::UnknownSection => "configuration has an unknown section",
            Self::UnknownVariable => "unknown STUDGE_RELAY_* variable",
            Self::OutOfRange => "configuration value is outside the accepted range",
            Self::InvalidCorsOrigin => {
                "CORS origin must be an explicit https, tauri or extension origin"
            }
        };
        f.write_str(text)
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_follow_the_spec() {
        let config = RelayConfig::default();
        assert_eq!(config.listen.to_string(), "127.0.0.1:8787");
        assert_eq!(config.max_body_bytes, 8 * 1024 * 1024);
        assert_eq!(config.max_ops_per_push, 100);
        assert_eq!(config.storage_quota_bytes, 100 * 1024 * 1024);
        assert!(config.cors_origins.is_empty());
        config.validate().expect("defaults are valid");
    }

    #[test]
    fn a_toml_file_overrides_the_defaults() {
        let mut config = RelayConfig::default();
        config
            .apply_toml(
                r#"
[server]
listen = "127.0.0.1:9999"

[limits]
max_ops_per_push = 42
storage_quota_bytes = 1048576

[rates]
register_per_ip_hour = 3

[cors]
allowed_origins = ["https://app.example", "tauri://localhost"]

[log]
json = true
ip_addresses = false
"#,
            )
            .expect("valid toml");
        assert_eq!(config.listen.to_string(), "127.0.0.1:9999");
        assert_eq!(config.max_ops_per_push, 42);
        assert_eq!(config.storage_quota_bytes, 1_048_576);
        assert_eq!(config.register_per_ip_hour, 3);
        assert_eq!(config.cors_origins.len(), 2);
        assert!(config.log_json);
        assert!(!config.log_ip_addresses);
    }

    #[test]
    fn an_unknown_section_is_rejected() {
        let mut config = RelayConfig::default();
        assert_eq!(
            config
                .apply_toml("[rate_limits]\nmax = 1\n")
                .expect_err("typo"),
            ConfigError::UnknownSection
        );
    }

    #[test]
    fn environment_variables_win() {
        let mut config = RelayConfig::default();
        config
            .apply_env([
                (
                    "STUDGE_RELAY_LISTEN".to_string(),
                    "127.0.0.1:7777".to_string(),
                ),
                ("STUDGE_RELAY_MAX_OPS_PER_PUSH".to_string(), "7".to_string()),
                ("STUDGE_RELAY_LOG_JSON".to_string(), "true".to_string()),
                (
                    "STUDGE_RELAY_CORS_ORIGINS".to_string(),
                    "https://a.example, https://b.example".to_string(),
                ),
                ("UNRELATED".to_string(), "x".to_string()),
            ])
            .expect("valid env");
        assert_eq!(config.listen.to_string(), "127.0.0.1:7777");
        assert_eq!(config.max_ops_per_push, 7);
        assert!(config.log_json);
        assert_eq!(
            config.cors_origins,
            vec!["https://a.example", "https://b.example"]
        );
    }

    #[test]
    fn an_unknown_variable_is_rejected() {
        let mut config = RelayConfig::default();
        assert_eq!(
            config
                .apply_env([("STUDGE_RELAY_MAXBODY".to_string(), "1".to_string())])
                .expect_err("typo"),
            ConfigError::UnknownVariable
        );
    }

    #[test]
    fn wildcard_cors_and_out_of_range_limits_are_refused() {
        let config = RelayConfig {
            cors_origins: vec!["*".to_string()],
            ..RelayConfig::default()
        };
        assert_eq!(
            config.validate().expect_err("wildcard"),
            ConfigError::InvalidCorsOrigin
        );

        let config = RelayConfig {
            max_body_bytes: 0,
            ..RelayConfig::default()
        };
        assert_eq!(
            config.validate().expect_err("zero"),
            ConfigError::OutOfRange
        );

        let config = RelayConfig {
            max_ops_per_push: 10_000,
            ..RelayConfig::default()
        };
        assert_eq!(
            config.validate().expect_err("huge"),
            ConfigError::OutOfRange
        );
    }
}
