use anyhow::Result;
use keyring::Entry;
use zeroize::Zeroizing;

const SERVICE: &str = "studge-pass-cli";

pub fn store_password(account_id: &str, password: &str) -> Result<()> {
    let entry = Entry::new(SERVICE, account_id).map_err(|e| anyhow::anyhow!("{e}"))?;
    entry
        .set_password(password)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

pub fn store_secret_key(account_id: &str, sk: &str) -> Result<()> {
    let entry =
        Entry::new(SERVICE, &format!("{account_id}:sk")).map_err(|e| anyhow::anyhow!("{e}"))?;
    entry.set_password(sk).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

pub fn load_password(account_id: &str) -> Result<Option<Zeroizing<String>>> {
    let entry = Entry::new(SERVICE, account_id).map_err(|e| anyhow::anyhow!("{e}"))?;
    match entry.get_password() {
        Ok(p) => Ok(Some(Zeroizing::new(p))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("{e}")),
    }
}

pub fn load_secret_key(account_id: &str) -> Result<Option<Zeroizing<String>>> {
    let entry =
        Entry::new(SERVICE, &format!("{account_id}:sk")).map_err(|e| anyhow::anyhow!("{e}"))?;
    match entry.get_password() {
        Ok(p) => Ok(Some(Zeroizing::new(p))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("{e}")),
    }
}

pub fn delete_password(account_id: &str) -> Result<()> {
    let entry = Entry::new(SERVICE, account_id).map_err(|e| anyhow::anyhow!("{e}"))?;
    let _ = entry.delete_credential();
    let entry2 =
        Entry::new(SERVICE, &format!("{account_id}:sk")).map_err(|e| anyhow::anyhow!("{e}"))?;
    let _ = entry2.delete_credential();
    Ok(())
}
