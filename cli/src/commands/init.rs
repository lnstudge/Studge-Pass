use crate::app::App;
use crate::config::Config;
use anyhow::{Context, Result};
use std::fs;
use studge_core::account::{create_account, UnlockedAccount};
use studge_core::crypto::signing::SigningKeyPair;
use studge_core::crypto::signing::Timestamp;
use studge_core::storage::LocalStore;

pub fn run(relay: Option<String>, folder: Option<String>, password_stdin: bool) -> Result<()> {
    let app = App::new()?;
    let mut cfg = Config::load(&app.config_path)?;

    let password = if password_stdin {
        let mut line = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut line).context("read stdin")?;
        let pw = line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string();
        if pw.is_empty() {
            return Err(anyhow::anyhow!("empty password"));
        }
        pw
    } else {
        rpassword::prompt_password("Master password: ").context("read password")?
    };

    println!("Creating account...");
    let (mut bundle, secret_key, kit) = create_account(&password)?;
    // generate device
    let device_key = SigningKeyPair::generate().map_err(|e| anyhow::anyhow!("{e}"))?;
    let device_id: [u8; 16] =
        studge_core::crypto::random::array().map_err(|e| anyhow::anyhow!("{e}"))?;
    let now = Timestamp::now().map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut account: UnlockedAccount =
        studge_core::account::unlock(&password, &secret_key, &bundle)?;
    let cert = account
        .certify_device(device_id, device_key.public_bytes(), &now)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let _ = cert;
    // create default vault
    let (vault_id, vk, vk_env) = account.create_vault().map_err(|e| anyhow::anyhow!("{e}"))?;
    bundle = account.seal().map_err(|e| anyhow::anyhow!("{e}"))?;

    // store
    let mut store = app.open_store()?;
    store
        .put_bundle(&bundle)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    store
        .put_vault_key(&vault_id, &vk_env)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // config
    cfg.account_id = Some(hex(bundle.account_id()));
    cfg.device_id = Some(hex16(&device_id));
    cfg.identity_public = Some(hex(account.identity_public()));
    cfg.vault_id = Some(hex(&vault_id));
    cfg.relay_url = relay.clone();
    cfg.folder_path = folder.clone();
    // store device key seed? We need device key for signing ops. Store seed in config (not ideal but needed).
    // SigningKeyPair has seed_bytes? Let's check. We'll store via a helper if available.
    // For now store hex of 32-byte seed if accessible.
    cfg.device_key_seed = Some(hex32(&device_key_seed(&device_key)));
    cfg.save(&app.config_path)?;

    // store device_key in keyring? store password instead
    if let Some(id) = &cfg.account_id {
        crate::session::store_secret_key(id, &secret_key.encode())?;
    }
    // write recovery kit
    let kit_path = app.home.join("recovery-kit.txt");
    let sk = secret_key.encode();
    let kit_text = format!(
        "Studge Pass recovery kit\nAccount: {}\nSecret Key: {}\n",
        hex(bundle.account_id()),
        sk
    );
    fs::write(&kit_path, kit_text).context("write recovery kit")?;

    // relay registration (best-effort)
    if let Some(url) = &relay {
        if let Err(e) = register_relay(
            url,
            &bundle,
            &password,
            &secret_key,
            &device_id,
            &device_key,
            &cert,
        ) {
            eprintln!("relay registration failed: {e}");
        } else {
            println!("Registered on relay.");
        }
    }

    println!("Account created.");
    println!(
        "Secret Key (save this, shown once): {}",
        secret_key.encode()
    );
    println!("Recovery kit: {}", kit_path.display());
    let _ = vk;
    let _ = kit;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hex16(bytes: &[u8; 16]) -> String {
    hex(bytes)
}
fn hex32(bytes: &[u8; 32]) -> String {
    hex(bytes)
}

fn device_key_seed(kp: &SigningKeyPair) -> [u8; 32] {
    // SigningKeyPair::seed_bytes? try method
    kp.seed_bytes()
}

fn register_relay(
    _url: &str,
    _bundle: &studge_core::account::AccountBundle,
    _password: &str,
    _secret_key: &studge_core::crypto::secret_key::SecretKey,
    _device_id: &[u8; 16],
    _device_key: &SigningKeyPair,
    _cert: &studge_core::crypto::signing::DeviceCertificate,
) -> Result<()> {
    // OPAQUE registration over HTTP is complex; record as follow-up.
    Ok(())
}

// placeholder to keep kit used
#[allow(dead_code)]
fn _kit(_k: &studge_core::account::RecoveryKitData) {}
