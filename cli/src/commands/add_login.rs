use anyhow::{Context, Result};
use clap::Args;
use studge_core::crypto::keys::AccountKey;
use studge_core::crypto::random;
use studge_core::crypto::signing::SigningKeyPair;
use studge_core::oplog::head::VaultHead;
use studge_core::oplog::materialise;
use studge_core::oplog::op::{Op, OpKind};
use studge_core::storage::LocalStore;
use studge_core::vault::items::{Item, ItemKind, UrlMatch};

use crate::app::App;
use crate::config::Config;
use crate::vault_util;

#[derive(Args, Debug)]
pub struct AddLoginArgs {
    #[arg(long)]
    pub title: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long)]
    pub password: Option<String>,
    #[arg(long)]
    pub url: Option<String>,
}

pub fn run_with(args: AddLoginArgs) -> Result<()> {
    let app = App::new()?;
    let cfg = Config::load(&app.config_path)?;
    let account_id = cfg.account_id.clone().context("no account")?;
    let device_id_hex = cfg.device_id.clone().context("no device")?;
    let mut device_id = [0u8; 16];
    let db = hex_decode(&device_id_hex)?;
    device_id.copy_from_slice(&db);
    let vault_id_hex = cfg.vault_id.clone().context("no vault")?;
    let mut vault_id = [0u8; 16];
    let vb = hex_decode(&vault_id_hex)?;
    vault_id.copy_from_slice(&vb);

    let seed_hex = cfg.device_key_seed.clone().context("no device key")?;
    let seed_bytes = hex_decode(&seed_hex)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let device_key = SigningKeyPair::from_seed(seed);

    let now = studge_core::crypto::signing::Timestamp::now().map_err(|e| anyhow::anyhow!("{e}"))?;

    let title = args.title.unwrap_or_else(|| "Login".to_string());
    let username = args.username.unwrap_or_default();
    let password = args.password.unwrap_or_default();
    let url = args.url.clone().unwrap_or_default();

    let item_id: [u8; 16] = random::array().map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut item = Item::new(item_id, vault_id, ItemKind::Login, now.clone())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    item.set_field("title", &title, &now)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if !username.is_empty() {
        item.set_field("username", &username, &now)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    if !password.is_empty() {
        item.set_field("password", &password, &now)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    if !url.is_empty() {
        item.add_url(&url, UrlMatch::ExactHost, &now)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // load account key from session
    let session_path = app.home.join("session.bin");
    let (ak_bytes, _) =
        match vault_util::load_session_pub(&account_id, device_id, &session_path, now_unix()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("DEBUG add load_session failed: {}", e);
                return Err(e);
            }
        };
    let account_key = AccountKey::from_bytes(*ak_bytes);
    let mut store = app.open_store()?;
    let aid = hex_decode(&account_id)?;
    let mut aidb = [0u8; 16];
    aidb.copy_from_slice(&aid);
    let bundle = store
        .get_bundle(&aidb)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .context("no bundle")?;
    let vk_env = store
        .get_vault_key(&vault_id)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .context("no vault key")?;
    let vk = studge_core::crypto::keys::unwrap_vault_key(&account_key, &vault_id, &vk_env)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // build dag to get parents/lamport
    let mut dag = studge_core::oplog::Dag::new(vault_id);
    let devices = studge_core::account::device_registry_from_bundle(&account_key, &bundle)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    for op in store
        .list_ops(&vault_id)
        .map_err(|e| anyhow::anyhow!("{e}"))?
    {
        let _ = dag.add(op, &devices);
    }
    let parents: Vec<_> = dag.heads().to_vec();
    let lamport = dag.lamport_max() + 1;

    let item_id_copy = item_id;
    let payload = item
        .to_payload_bytes()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let envelope = Op::seal_payload(&vk, &vault_id, &item_id_copy, OpKind::Create, &payload)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let op_id: [u8; 16] = random::array().map_err(|e| anyhow::anyhow!("{e}"))?;
    let stored = Op::new(
        vault_id,
        op_id,
        parents.clone(),
        lamport,
        device_id,
        now.clone(),
        OpKind::Create,
        Some(item_id_copy),
        envelope,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?
    .sign(&device_key)
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    store.put_op(&stored).map_err(|e| anyhow::anyhow!("{e}"))?;

    // update head
    let mut dag2 = studge_core::oplog::Dag::new(vault_id);
    for op in store
        .list_ops(&vault_id)
        .map_err(|e| anyhow::anyhow!("{e}"))?
    {
        let _ = dag2.add(op, &devices);
    }
    let head = VaultHead::create(
        &device_key,
        vault_id,
        device_id,
        dag2.heads(),
        dag2.len() as u64,
        dag2.lamport_max(),
        now,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let expected = if let Some(h) = store
        .get_head(&vault_id)
        .map_err(|e| anyhow::anyhow!("{e}"))?
    {
        h.hash().map_err(|e| anyhow::anyhow!("{e}"))?
    } else {
        studge_core::sync::transport::NO_HEAD
    };
    store.put_head(&head).map_err(|e| anyhow::anyhow!("{e}"))?;
    let _ = expected;
    let _ = materialise;

    println!("Added login: {}", title);
    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(anyhow::anyhow!("bad hex"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| anyhow::anyhow!("bad hex"))?);
    }
    Ok(out)
}
