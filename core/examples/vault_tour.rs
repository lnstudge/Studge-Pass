//! A guided tour of the Phase 3 vault: items, the signed op log, a conflict
//! resolved by the SPEC rule, a vault head, and a Bitwarden import.
//!
//! Everything here is FAKE and labelled DEMO ONLY. No real secret is printed:
//! the demo prints hashes, ids and counts, and one made-up password so the
//! reader can see what a stored field looks like.
//!
//! Run it with:
//!
//! ```text
//! .\x.ps1 "cargo run -p studge-core --example vault_tour"
//! ```

use std::error::Error;
use studge_core::account::{create_account, UnlockedAccount};
use studge_core::crypto::keys::VaultKey;
use studge_core::crypto::signing::{SigningKeyPair, Timestamp};
use studge_core::import::bitwarden;
use studge_core::oplog::head::{check_head_update, VaultHead};
use studge_core::oplog::materialise;
use studge_core::oplog::op::{Op, OpHash, OpKind, StoredOp};
use studge_core::oplog::Dag;
use studge_core::totp::TotpConfig;
use studge_core::vault::items::{Item, ItemKind, UrlMatch};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const ITEM_AADHAAR: [u8; 16] = [0xA1; 16];
const ITEM_PAN: [u8; 16] = [0xB2; 16];
const ITEM_UPI: [u8; 16] = [0xC3; 16];
const ITEM_LOGIN: [u8; 16] = [0xD4; 16];
const DEVICE_A: [u8; 16] = [0xD1; 16];
const DEVICE_B: [u8; 16] = [0xD2; 16];

fn stamp(text: &str) -> Timestamp {
    Timestamp::parse(text).unwrap_or_else(|_| {
        // Fixed, valid constants: a panic here would only mean a typo in this
        // demo, never user input.
        panic!("demo timestamp {text}")
    })
}

fn main() -> Result<()> {
    println!("Studge Pass - vault tour (DEMO ONLY, fake data)\n");

    // ---------------------------------------------------------------- account
    println!("1. Create an account");
    let (bundle, secret_key, kit) = create_account("demo-only password")?;
    println!("   account id      {}", hex16(bundle.account_id()));
    println!(
        "   recovery kit    account {} + Secret Key {}****",
        short16(kit.account_id()),
        &secret_key.encode()[..7]
    );
    let mut account: UnlockedAccount =
        studge_core::account::unlock("demo-only password", &secret_key, &bundle)?;
    println!("   kdf             {:?}\n", bundle.kdf());

    // ----------------------------------------------------------------- device
    println!("2. Certify two devices (a phone and a laptop)");
    let device_a = SigningKeyPair::generate()?;
    let device_b = SigningKeyPair::generate()?;
    account.certify_device(
        DEVICE_A,
        device_a.public_bytes(),
        &stamp("2026-11-01T09:00:00Z"),
    )?;
    account.certify_device(
        DEVICE_B,
        device_b.public_bytes(),
        &stamp("2026-11-01T09:05:00Z"),
    )?;
    println!(
        "   device A        {} pubkey {}\n   device B        {} pubkey {}\n",
        short16(&DEVICE_A),
        short32(&device_a.public_bytes()),
        short16(&DEVICE_B),
        short32(&device_b.public_bytes())
    );

    // ------------------------------------------------------------------ vault
    println!("3. Create a vault and five items");
    let (vault_id, vk, _vk_envelope) = account.create_vault()?;
    println!("   vault id        {}\n", hex16(&vault_id));
    let mut dag = Dag::new(vault_id);
    let mut lamport = 0u64;
    let mut head_hash: Option<OpHash> = None;

    let aadhaar = build_aadhaar()?;
    let pan = build_pan()?;
    let upi = build_upi()?;
    let login = build_login()?;
    let note = build_note()?;

    for (index, item) in [&aadhaar, &pan, &upi, &login, &note].iter().enumerate() {
        lamport += 1;
        let parents = head_hash.iter().copied().collect::<Vec<_>>();
        let stored = make_op(
            &vk,
            vault_id,
            index as u8 + 1,
            parents,
            lamport,
            DEVICE_A,
            &device_a,
            OpKind::Create,
            item,
        )?;
        head_hash = Some(dag.add(stored, account.devices())?);
    }

    let state = materialise(&dag, &vk)?;
    println!("   items           {}", state.len());
    for item in state.items() {
        println!(
            "   - {:<12} title={:<28} fields={}",
            item.kind().as_str(),
            item.field("title").unwrap_or("(untitled)"),
            field_count(item)
        );
    }
    println!();

    // ----------------------------------------------------------------- labels
    println!("4. The TOTP secret from the login item, as a live code");
    let totp_secret = login.field("totp").unwrap_or_default();
    let config = TotpConfig::from_field(totp_secret)?;
    println!("   issuer          {}", config.issuer().unwrap_or("(none)"));
    println!("   digest          {:?}", config.algorithm());
    println!(
        "   code at 1700000010 {}\n",
        config.code_at(1_700_000_010)?.as_str()
    );

    // -------------------------------------------------------------- op log
    println!("5. The op log as stored (hashes and metadata only, no plaintext)");
    println!(
        "   {:<8} {:<8} {:<11} {:<11} parents",
        "lamport", "kind", "device", "hash"
    );
    let mut ops: Vec<(OpHash, StoredOp)> = Vec::new();
    for hash in dag.heads() {
        let mut cursor = Some(hash);
        while let Some(current) = cursor {
            if ops.iter().any(|(known, _)| *known == current) {
                break;
            }
            let stored = dag.get(&current).ok_or("missing op")?;
            ops.push((current, stored.clone()));
            cursor = stored.op().parents().first().copied();
        }
    }
    ops.sort_by_key(|(_, stored)| stored.op().lamport());
    for (hash, stored) in &ops {
        let op = stored.op();
        let parents = if op.parents().is_empty() {
            "(genesis)".to_string()
        } else {
            op.parents()
                .iter()
                .map(short32)
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!(
            "   {:<8} {:<8} {:<11} {:<11} {}",
            op.lamport(),
            op.kind().as_str(),
            short16(op.device_id()),
            short32(hash),
            parents
        );
    }
    println!();

    // -------------------------------------------------------------- conflict
    println!("6. Two devices edit the same item offline (a real conflict)");
    let base = *dag.heads().first().ok_or("no head")?;
    let from_a = make_op(
        &vk,
        vault_id,
        20,
        vec![base],
        lamport + 1,
        DEVICE_A,
        &device_a,
        OpKind::Update,
        &with_password(&login, "demo-password-from-phone")?,
    )?;
    let from_b = make_op(
        &vk,
        vault_id,
        21,
        vec![base],
        lamport + 1,
        DEVICE_B,
        &device_b,
        OpKind::Update,
        &with_password(&login, "demo-password-from-laptop")?,
    )?;
    let hash_a = dag.add(from_a, account.devices())?;
    let hash_b = dag.add(from_b, account.devices())?;
    println!(
        "   phone  op       {} (device {})",
        short32(&hash_a),
        short16(&DEVICE_A)
    );
    println!(
        "   laptop op       {} (device {})",
        short32(&hash_b),
        short16(&DEVICE_B)
    );
    println!("   rule            highest (lamport, device_id) wins");
    let conflicted = materialise(&dag, &vk)?;
    let winner = conflicted
        .item(&ITEM_LOGIN)
        .and_then(|item| item.field("password"))
        .unwrap_or("(none)");
    println!("   winner          {winner}");
    println!(
        "   history         {} earlier value(s) kept in the item\n",
        conflicted
            .item(&ITEM_LOGIN)
            .map(|item| item.history("password").len())
            .unwrap_or(0)
    );

    // ------------------------------------------------------------------ head
    println!("7. Sign a vault head and check it against the previous one");
    let heads_before = dag.heads();
    let head = VaultHead::create(
        &device_a,
        vault_id,
        DEVICE_A,
        dag.heads(),
        dag.len() as u64,
        dag.lamport_max(),
        stamp("2026-11-05T12:00:00Z"),
    )?;
    head.verify(account.devices())?;
    println!(
        "   head hash       {} ops={} lamport_max={}",
        short32(&head.hash()?),
        head.op_count(),
        head.lamport_max()
    );
    println!("   heads           {}", heads_before.len());
    match check_head_update(&head, &head, &dag) {
        Ok(update) => println!("   same head       {update:?}"),
        Err(error) => println!("   same head       rejected: {error}"),
    }
    // A relay serving an older head is a rollback: prove it is refused.
    let mut older_heads = heads_before.clone();
    older_heads.truncate(1);
    let older = VaultHead::create(
        &device_a,
        vault_id,
        DEVICE_A,
        older_heads,
        1,
        1,
        stamp("2026-11-05T11:00:00Z"),
    )?;
    match check_head_update(&head, &older, &dag) {
        Ok(_) => println!("   old head        ACCEPTED (bug)"),
        Err(error) => println!("   old head        rejected: {error}"),
    }
    println!();

    // ---------------------------------------------------------------- import
    println!("8. Import a fake Bitwarden export");
    let export = br#"{
      "items": [
        {"type": 1, "name": "Demo Imported", "login": {"username": "demo", "password": "demo-only", "uris": [{"uri": "https://demo.example"}]}},
        {"type": 1, "name": "", "login": {}},
        {"type": 8, "name": "Demo Unknown"}
      ]
    }"#;
    let outcome = bitwarden::import_json(export)?;
    println!("   report          {}", outcome.report.summary());
    for skipped in &outcome.report.skipped {
        println!("   skipped row {}   {:?}", skipped.index, skipped.reason);
    }
    for parsed in &outcome.items {
        let item =
            parsed
                .clone()
                .into_item(vault_id, [0x77; 16], &stamp("2026-11-05T12:30:00Z"))?;
        println!(
            "   imported        {:<16} {}",
            item.field("title").unwrap_or("(untitled)"),
            item.urls()
                .first()
                .map(|url| url.url())
                .unwrap_or("(no url)")
        );
    }
    println!("\nDone. Nothing in this tour is real; every id, key and password is fake.");
    Ok(())
}

fn field_count(item: &Item) -> usize {
    let mut count = 0;
    for spec in studge_core::vault::template(item.kind()).fields {
        if item.field(spec.name).is_some() {
            count += 1;
        }
    }
    count + item.custom().len()
}

#[allow(clippy::too_many_arguments)]
fn make_op(
    vk: &VaultKey,
    vault_id: [u8; 16],
    op_id: u8,
    parents: Vec<OpHash>,
    lamport: u64,
    device_id: [u8; 16],
    signer: &SigningKeyPair,
    kind: OpKind,
    item: &Item,
) -> Result<StoredOp> {
    let item_id = *item.id();
    let payload = item.to_payload_bytes()?;
    let envelope = Op::seal_payload(vk, &vault_id, &item_id, kind, &payload)?;
    Ok(Op::new(
        vault_id,
        [op_id; 16],
        parents,
        lamport,
        device_id,
        stamp("2026-11-05T10:00:00Z"),
        kind,
        Some(item_id),
        envelope,
    )?
    .sign(signer)?)
}

fn with_password(item: &Item, password: &str) -> Result<Item> {
    let mut copy = item.clone();
    copy.set_field("password", password, &stamp("2026-11-05T11:30:00Z"))?;
    Ok(copy)
}

fn build_aadhaar() -> Result<Item> {
    let mut item = Item::new(
        ITEM_AADHAAR,
        [0x11; 16],
        ItemKind::Aadhaar,
        stamp("2026-11-05T09:00:00Z"),
    )?;
    item.set_field("title", "Demo Aadhaar", &stamp("2026-11-05T09:00:00Z"))?;
    item.set_field(
        "aadhaar_number",
        "0000 0000 0000",
        &stamp("2026-11-05T09:00:00Z"),
    )?;
    item.set_field("full_name", "Demo Person", &stamp("2026-11-05T09:00:00Z"))?;
    item.set_field("dob", "1990-01-01", &stamp("2026-11-05T09:00:00Z"))?;
    Ok(item)
}

fn build_pan() -> Result<Item> {
    let mut item = Item::new(
        ITEM_PAN,
        [0x11; 16],
        ItemKind::Pan,
        stamp("2026-11-05T09:01:00Z"),
    )?;
    item.set_field("title", "Demo PAN", &stamp("2026-11-05T09:01:00Z"))?;
    item.set_field("pan_number", "AAAAA0000A", &stamp("2026-11-05T09:01:00Z"))?;
    item.set_field("full_name", "Demo Person", &stamp("2026-11-05T09:01:00Z"))?;
    Ok(item)
}

fn build_upi() -> Result<Item> {
    let mut item = Item::new(
        ITEM_UPI,
        [0x11; 16],
        ItemKind::Upi,
        stamp("2026-11-05T09:02:00Z"),
    )?;
    item.set_field("title", "Demo UPI", &stamp("2026-11-05T09:02:00Z"))?;
    item.set_field("upi_id", "demo@okbank", &stamp("2026-11-05T09:02:00Z"))?;
    item.set_field("pin", "0000", &stamp("2026-11-05T09:02:00Z"))?;
    item.set_field("linked_bank", "Demo Bank", &stamp("2026-11-05T09:02:00Z"))?;
    Ok(item)
}

fn build_login() -> Result<Item> {
    let mut item = Item::new(
        ITEM_LOGIN,
        [0x11; 16],
        ItemKind::Login,
        stamp("2026-11-05T09:03:00Z"),
    )?;
    item.set_field("title", "Demo Login", &stamp("2026-11-05T09:03:00Z"))?;
    item.set_field(
        "username",
        "demo@example.test",
        &stamp("2026-11-05T09:03:00Z"),
    )?;
    item.set_field(
        "password",
        "demo-password-original",
        &stamp("2026-11-05T09:03:00Z"),
    )?;
    item.set_field("totp", "JBSWY3DPEHPK3PXP", &stamp("2026-11-05T09:03:00Z"))?;
    item.add_url(
        "https://demo.example/login",
        UrlMatch::ExactHost,
        &stamp("2026-11-05T09:03:00Z"),
    )?;
    item.add_custom("Support PIN", "0000", true, &stamp("2026-11-05T09:03:00Z"))?;
    Ok(item)
}

fn build_note() -> Result<Item> {
    let mut item = Item::new(
        [0xE5; 16],
        [0x11; 16],
        ItemKind::SecureNote,
        stamp("2026-11-05T09:04:00Z"),
    )?;
    item.set_field("title", "Demo Note", &stamp("2026-11-05T09:04:00Z"))?;
    item.set_field("notes", "demo only", &stamp("2026-11-05T09:04:00Z"))?;
    Ok(item)
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn short16(bytes: &[u8; 16]) -> String {
    let full = hex16(bytes);
    format!("{}..", &full[..8])
}

fn short32(bytes: &[u8; 32]) -> String {
    let full: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{}..", &full[..8])
}
