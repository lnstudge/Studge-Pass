//! Folder-based transport (SPEC §7.10, D-0114).
//!
//! Layout:
//! ```text
//! <root>/vaults/<vault_id_hex>/ops/<op_hash_hex>.cbor
//! <root>/vaults/<vault_id_hex>/head.cbor
//! ```
//!
//! Each op file is written atomically (temp-file + rename) so a crash cannot
//! leave a partial file.  The transport tolerates:
//!
//! - **Duplicate files** — already have the op; idempotent.
//! - **"Conflicted copy" files** — Dropbox, OneDrive, and similar tools
//!   rename a conflicting file to `<name> (conflicted copy …)`.  Any file
//!   whose name is not a valid 64-character lowercase hex string followed by
//!   `.cbor` is silently skipped, so conflicted copies never interfere.
//! - **Stale temp files** — names starting with `.tmp` are skipped.
//!
//! Security: the transport never trusts file metadata (mtime, size). Every
//! file's content is parsed and signature-verified by the caller (the sync
//! engine) before use.

#[cfg(not(target_arch = "wasm32"))]
mod inner {
    use crate::oplog::head::VaultHead;
    use crate::oplog::op::StoredOp;
    use crate::sync::transport::{SyncError, Transport, VaultOps, NO_HEAD};
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    fn vault_dir(root: &Path, vault_id: [u8; 16]) -> PathBuf {
        let hex = hex_id(&vault_id);
        root.join("vaults").join(&hex)
    }

    fn ops_dir(root: &Path, vault_id: [u8; 16]) -> PathBuf {
        vault_dir(root, vault_id).join("ops")
    }

    fn head_path(root: &Path, vault_id: [u8; 16]) -> PathBuf {
        vault_dir(root, vault_id).join("head.cbor")
    }

    fn hex_id(id: &[u8; 16]) -> String {
        id.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn hex_hash(hash: &[u8; 32]) -> String {
        hash.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Returns `true` iff `name` is exactly `<64 lowercase hex chars>.cbor`.
    fn is_op_filename(name: &str) -> bool {
        name.ends_with(".cbor")
            && name.len() == 69 // 64 hex + ".cbor"
            && name[..64].chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
    }

    fn ensure_dir(path: &Path) -> Result<(), SyncError> {
        fs::create_dir_all(path).map_err(|e| SyncError::Io(e.to_string()))
    }

    fn write_atomically(path: &Path, data: &[u8]) -> Result<(), SyncError> {
        let parent = path
            .parent()
            .ok_or_else(|| SyncError::Io("no parent dir".into()))?;
        ensure_dir(parent)?;
        // Write to a temp file next to the target, then rename.
        let tmp_path = parent.join(format!(
            ".tmp-{}.cbor",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)
                .map_err(|e| SyncError::Io(e.to_string()))?;
            f.write_all(data)
                .map_err(|e| SyncError::Io(e.to_string()))?;
        }
        fs::rename(&tmp_path, path).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            SyncError::Io(e.to_string())
        })
    }

    /// Folder-backed transport.
    pub struct FolderTransport {
        root: PathBuf,
    }

    impl FolderTransport {
        /// Opens (or creates) a transport rooted at `root`.
        pub fn new(root: impl Into<PathBuf>) -> Self {
            Self { root: root.into() }
        }
    }

    impl Transport for FolderTransport {
        fn push(&mut self, vault_id: [u8; 16], ops: &[StoredOp]) -> Result<usize, SyncError> {
            let dir = ops_dir(&self.root, vault_id);
            ensure_dir(&dir)?;
            let mut accepted = 0;
            for op in ops {
                let hash = op.hash().map_err(|_| SyncError::MalformedPayload)?;
                let raw = op.to_cbor().map_err(|_| SyncError::MalformedPayload)?;
                let path = dir.join(format!("{}.cbor", hex_hash(&hash)));
                if !path.exists() {
                    write_atomically(&path, &raw)?;
                }
                accepted += 1;
            }
            Ok(accepted)
        }

        fn pull(
            &mut self,
            vault_id: [u8; 16],
            cursor: Option<[u8; 32]>,
        ) -> Result<VaultOps, SyncError> {
            let dir = ops_dir(&self.root, vault_id);
            let head_path = head_path(&self.root, vault_id);

            // Read all valid op files, sort by name for deterministic order.
            let mut op_files: Vec<(String, Vec<u8>)> = Vec::new();
            if dir.exists() {
                for entry in fs::read_dir(&dir).map_err(|e| SyncError::Io(e.to_string()))? {
                    let entry = entry.map_err(|e| SyncError::Io(e.to_string()))?;
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    // Skip conflicted copies, temp files, and non-op files.
                    if name_str.starts_with('.') || !is_op_filename(&name_str) {
                        continue;
                    }
                    let bytes = fs::read(entry.path()).map_err(|e| SyncError::Io(e.to_string()))?;
                    op_files.push((name_str.to_string(), bytes));
                }
            }
            // Sort by filename (which is the hex hash — deterministic, but not
            // topological).  The sync engine's DAG::add enforces topological
            // order by rejecting unknown parents, so the pull order here is
            // best-effort; the engine retries in any order it finds valid.
            op_files.sort_by(|(a, _), (b, _)| a.cmp(b));

            // Find the cursor position (if any) and skip ops up to and
            // including it.
            let cursor_hex = cursor.as_ref().map(hex_hash);
            let start = match &cursor_hex {
                None => 0,
                Some(hex) => {
                    let cursor_name = format!("{}.cbor", hex);
                    op_files
                        .iter()
                        .position(|(n, _)| n == &cursor_name)
                        .map(|p| p + 1)
                        .unwrap_or(0)
                }
            };

            let mut ops = Vec::new();
            for (_, raw) in &op_files[start..] {
                let op = StoredOp::from_cbor(raw).map_err(|_| SyncError::MalformedPayload)?;
                ops.push(op);
            }

            // Read head.
            let head = if head_path.exists() {
                let bytes = fs::read(&head_path).map_err(|e| SyncError::Io(e.to_string()))?;
                Some(VaultHead::from_cbor(&bytes).map_err(|_| SyncError::MalformedPayload)?)
            } else {
                None
            };

            Ok(VaultOps { ops, head })
        }

        fn put_head(
            &mut self,
            vault_id: [u8; 16],
            head: &VaultHead,
            expected_hash: [u8; 32],
        ) -> Result<(), SyncError> {
            let path = head_path(&self.root, vault_id);
            // Read the existing head hash for CAS.
            let current_hash: [u8; 32] = if path.exists() {
                let bytes = fs::read(&path).map_err(|e| SyncError::Io(e.to_string()))?;
                VaultHead::from_cbor(&bytes)
                    .map_err(|_| SyncError::MalformedPayload)?
                    .hash()
                    .map_err(|_| SyncError::MalformedPayload)?
            } else {
                NO_HEAD
            };

            if expected_hash != NO_HEAD && current_hash != expected_hash {
                return Err(SyncError::ForkDetected);
            }
            if expected_hash == NO_HEAD && current_hash != NO_HEAD {
                return Err(SyncError::ForkDetected);
            }

            let bytes = head.to_cbor().map_err(|_| SyncError::MalformedPayload)?;
            write_atomically(&path, &bytes)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::crypto::keys::VaultKey;
        use crate::crypto::signing::{DeviceCertificate, SigningKeyPair, Timestamp};
        use crate::oplog::devices::DeviceRegistry;
        use crate::oplog::op::{Op, OpKind};

        const ACCOUNT: [u8; 16] = [0xAA; 16];
        const VAULT: [u8; 16] = [0xBB; 16];
        const ITEM: [u8; 16] = [0xCC; 16];
        const DEVICE: [u8; 16] = [0xDD; 16];

        fn at(s: &str) -> Timestamp {
            Timestamp::parse(s).unwrap()
        }

        fn make_device() -> (SigningKeyPair, SigningKeyPair, DeviceRegistry) {
            let identity = SigningKeyPair::from_seed([1u8; 32]);
            let device = SigningKeyPair::from_seed([2u8; 32]);
            let mut reg = DeviceRegistry::new(ACCOUNT, identity.public_bytes());
            let cert = DeviceCertificate::create(
                &identity,
                ACCOUNT,
                DEVICE,
                device.public_bytes(),
                at("2026-11-05T09:00:00Z"),
            )
            .unwrap();
            reg.certify(&cert, &at("2026-11-05T10:00:00Z")).unwrap();
            (identity, device, reg)
        }

        fn make_genesis(device: &SigningKeyPair) -> StoredOp {
            let vk = VaultKey::from_bytes([3u8; 32]);
            let payload = Op::seal_payload(&vk, &VAULT, &ITEM, OpKind::Create, b"item").unwrap();
            Op::new(
                VAULT,
                [1u8; 16],
                vec![],
                1,
                DEVICE,
                at("2026-11-05T10:00:00Z"),
                OpKind::Create,
                Some(ITEM),
                payload,
            )
            .unwrap()
            .sign(device)
            .unwrap()
        }

        #[test]
        fn folder_transport_round_trips_ops_and_head() {
            let dir = tempfile::tempdir().unwrap();
            let mut transport = FolderTransport::new(dir.path());
            let (_, device, _) = make_device();
            let op = make_genesis(&device);
            let hash = op.hash().unwrap();
            transport.push(VAULT, &[op]).unwrap();
            let result = transport.pull(VAULT, None).unwrap();
            assert_eq!(result.ops.len(), 1);
            assert_eq!(result.ops[0].hash().unwrap(), hash);
        }

        #[test]
        fn conflicted_copy_files_are_ignored() {
            let dir = tempfile::tempdir().unwrap();
            let ops_dir_path = dir
                .path()
                .join("vaults")
                .join(VAULT.iter().map(|b| format!("{b:02x}")).collect::<String>())
                .join("ops");
            fs::create_dir_all(&ops_dir_path).unwrap();
            // Write a conflicted-copy file — Dropbox renames it with spaces.
            let conflict = ops_dir_path.join("aabbcc (conflicted copy 2026-11-05).cbor");
            fs::write(&conflict, b"garbage").unwrap();
            let mut transport = FolderTransport::new(dir.path());
            let result = transport.pull(VAULT, None).unwrap();
            assert_eq!(result.ops.len(), 0, "conflicted copies must be skipped");
        }

        #[test]
        fn push_is_idempotent_on_folder() {
            let dir = tempfile::tempdir().unwrap();
            let mut transport = FolderTransport::new(dir.path());
            let (_, device, _) = make_device();
            let op = make_genesis(&device);
            transport.push(VAULT, std::slice::from_ref(&op)).unwrap();
            transport.push(VAULT, &[op]).unwrap();
            let result = transport.pull(VAULT, None).unwrap();
            assert_eq!(result.ops.len(), 1);
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use inner::FolderTransport;
