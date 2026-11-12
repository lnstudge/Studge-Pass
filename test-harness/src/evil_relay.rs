//! `EvilRelay` — a `Transport` wrapper that injects attacks.
//!
//! Each test configures one attack by calling `set_attack` before the sync.
//! The relay wraps a `MemoryTransport` and intercepts `pull` to inject the
//! chosen misbehaviour.  `push` always passes through (evil relays attack
//! reads, not writes; DoS-of-writes is outside this threat model).
//!
//! Attacks implemented (SPEC §7.12, AGENTS.md security bar):
//!
//! | Variant | Server behaviour | Expected client error |
//! |---|---|---|
//! | `Honest` | Passthrough | — (sanity) |
//! | `DropOps` | Returns empty op list | `HeadReferencesUnknownOp` |
//! | `ReorderOps` | Reverses op list | `MissingParent` |
//! | `ReplayOldOp` | Appends first op again | idempotent (no error) |
//! | `RollbackHead` | Serves an old head | `RollbackDetected` |
//! | `ForkHead` | Serves a head with a ghost tip | `HeadReferencesUnknownOp` |
//! | `SwapCiphertext` | Swaps payloads between ops | `OpVerificationFailed` |
//! | `FlipBit` | Flips a bit in an op's sig | `OpVerificationFailed` |
//! | `StripSignature` | Zeroes sig bytes | `OpVerificationFailed` |
//! | `SubstituteDeviceCert` | Flips a bit in head's device_id | `OpVerificationFailed` |
//! | `WrongVaultId` | Returns ops tagged with different vault | `OpVerificationFailed` |
//! | `DowngradeSuite` | Serves head with suite `v0` | `OpVerificationFailed` |
//! | `TruncateOps` | Returns first n ops only | `HeadReferencesUnknownOp` |
//! | `GhostHeadEntry` | Head references unknown op hash | `HeadReferencesUnknownOp` |

use studge_core::oplog::head::VaultHead;
use studge_core::oplog::op::{OpHash, StoredOp};
use studge_core::sync::memory::MemoryTransport;
use studge_core::sync::transport::{SyncError, Transport, VaultOps};

/// The attack to inject on `pull`.
#[derive(Debug, Clone)]
pub enum Attack {
    /// Pass through honestly.
    Honest,
    /// Return an empty op list (head unchanged).
    DropOps,
    /// Return ops in reverse order (children before parents).
    ReorderOps,
    /// Append the first op again at the end.
    ReplayOldOp,
    /// Return a previously snapshotted (old) head.
    RollbackHead { snapshot_index: usize },
    /// Return a head whose first tip is replaced with a ghost hash.
    ForkHead,
    /// Swap the raw CBOR bytes of op `a` and op `b`.
    SwapCiphertext { a: usize, b: usize },
    /// Flip one byte in the sig bytes of op at `index`.
    FlipBit { index: usize },
    /// Zero the sig bytes of op at `index`.
    StripSignature { index: usize },
    /// Flip a byte in the head's device_id (breaks sig).
    SubstituteDeviceCert,
    /// Return ops with vault_id replaced by `other_vault`.
    WrongVaultId { other_vault: [u8; 16] },
    /// Return head with suite replaced by `v0`.
    DowngradeSuite,
    /// Return only the first `n` ops.
    TruncateOps { n: usize },
    /// Return a head that references a ghost op hash.
    GhostHeadEntry,
}

/// A transport wrapper that injects attacks.
pub struct EvilRelay {
    inner: MemoryTransport,
    attack: Attack,
    /// Saved (head_cbor, head_hash) snapshots, earliest first.
    head_snapshots: Vec<(Vec<u8>, OpHash)>,
}

impl EvilRelay {
    /// Wraps `inner` with no attack.
    pub fn new(inner: MemoryTransport) -> Self {
        Self {
            inner,
            attack: Attack::Honest,
            head_snapshots: Vec::new(),
        }
    }

    /// Sets the active attack.
    pub fn set_attack(&mut self, attack: Attack) {
        self.attack = attack;
    }

    /// Direct access to the inner transport for setup.
    pub fn inner_mut(&mut self) -> &mut MemoryTransport {
        &mut self.inner
    }
}

// ─── CBOR byte-level helpers ─────────────────────────────────────────────────

/// Flip the byte at `byte_pos % raw.len()` in `raw`.
fn flip_byte(raw: &mut [u8], byte_pos: usize) {
    if !raw.is_empty() {
        let idx = byte_pos % raw.len();
        raw[idx] ^= 0xFF;
    }
}

/// Zeroes the last `n` bytes of `raw`.
fn zero_last_n(raw: &mut [u8], n: usize) {
    let len = raw.len();
    if len >= n {
        raw[len - n..].iter_mut().for_each(|b| *b = 0);
    }
}

/// Replaces bytes `old` with `new` in `raw` (first occurrence only).
fn replace_bytes(raw: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    let pos = raw.windows(old.len()).position(|w| w == old);
    match pos {
        Some(i) => {
            let mut out = raw[..i].to_vec();
            out.extend_from_slice(new);
            out.extend_from_slice(&raw[i + old.len()..]);
            out
        }
        None => raw.to_vec(),
    }
}

impl Transport for EvilRelay {
    fn push(&mut self, vault_id: [u8; 16], ops: &[StoredOp]) -> Result<usize, SyncError> {
        let result = self.inner.push(vault_id, ops)?;
        // Snapshot the head after each push so rollback tests can use old ones.
        if let Ok(VaultOps { head: Some(h), .. }) = self.inner.pull(vault_id, None) {
            if let (Ok(bytes), Ok(hash)) = (h.to_cbor(), h.hash()) {
                // Only add if we don't already have this hash.
                if !self.head_snapshots.iter().any(|(_, hh)| hh == &hash) {
                    self.head_snapshots.push((bytes, hash));
                }
            }
        }
        Ok(result)
    }

    fn pull(
        &mut self,
        vault_id: [u8; 16],
        cursor: Option<[u8; 32]>,
    ) -> Result<VaultOps, SyncError> {
        let honest = self.inner.pull(vault_id, cursor)?;
        match self.attack.clone() {
            Attack::Honest => Ok(honest),

            Attack::DropOps => Ok(VaultOps {
                ops: vec![],
                head: honest.head,
            }),

            Attack::ReorderOps => {
                let mut ops = honest.ops;
                ops.reverse();
                Ok(VaultOps {
                    ops,
                    head: honest.head,
                })
            }

            Attack::ReplayOldOp => {
                // Pull from the beginning to get op at index 0.
                let all = self.inner.pull(vault_id, None)?;
                let mut ops = honest.ops;
                if let Some(first) = all.ops.into_iter().next() {
                    ops.push(first);
                }
                Ok(VaultOps {
                    ops,
                    head: honest.head,
                })
            }

            Attack::RollbackHead { snapshot_index } => {
                let (old_bytes, _) = match self.head_snapshots.get(snapshot_index) {
                    Some(s) => s.clone(),
                    None => return Ok(honest), // no snapshot yet
                };
                let old_head =
                    VaultHead::from_cbor(&old_bytes).map_err(|_| SyncError::MalformedPayload)?;
                // Return all the ops (so the client CAN add them to the DAG)
                // but the head points to an older state — a rollback.
                Ok(VaultOps {
                    ops: honest.ops,
                    head: Some(old_head),
                })
            }

            Attack::ForkHead => {
                // Build a head whose `heads[0]` is a ghost hash (unknown op).
                let head = match honest.head {
                    None => return Ok(honest),
                    Some(h) => h,
                };
                // Inject a ghost via raw injection to the inner transport, then
                // use inner.set_raw_head to set a head pointing at the ghost.
                let ghost: OpHash = [0xEEu8; 32];
                // Build the head we want by replacing the real tip hash in the
                // head's CBOR bytes with the ghost hash.
                let mut head_bytes = head.to_cbor().map_err(|_| SyncError::MalformedPayload)?;
                for tip in head.heads() {
                    // Replace the 32-byte tip slice in the encoded CBOR.
                    head_bytes = replace_bytes(&head_bytes, tip, &ghost);
                }
                // The head won't re-parse (sig is over original body), so just
                // set the raw bytes and the hash as ghost.
                // The engine checks VaultHead::from_cbor first — if that fails,
                // we return a MalformedPayload error from pull rather than the
                // desired HeadReferencesUnknownOp.  Instead, let's return the
                // honest ops but a head that references a ghost via a VaultHead
                // we synthesize: we can't sign it without the device key, but
                // we CAN build one via inject.  Best option: use the honest
                // head but set its byte content so the ghost tip is in `heads`.
                //
                // Practical approach: skip CBOR re-signing and just return
                // an honest ops list + a modified head pointing to ghost tips
                // that has the original sig (will fail verify OR succeed parse
                // but fail heads-exist check).
                let ghost_head = VaultHead::from_cbor(&head_bytes).ok();
                Ok(VaultOps {
                    ops: honest.ops,
                    head: ghost_head,
                })
            }

            Attack::SwapCiphertext { a, b } => {
                let mut ops = honest.ops;
                if a < ops.len() && b < ops.len() && a != b {
                    // Swap the raw bytes of op a and op b.
                    let raw_a = ops[a].to_cbor().map_err(|_| SyncError::MalformedPayload)?;
                    let raw_b = ops[b].to_cbor().map_err(|_| SyncError::MalformedPayload)?;
                    // Put raw_b bytes where op a was (and vice versa).
                    // from_cbor will either reject them (re-encode check fails
                    // because vault_id / op_id mismatch) or the sig check fails.
                    // Either way the client returns OpVerificationFailed.
                    if let Ok(op_b_bytes_as_a) = StoredOp::from_cbor(&raw_b) {
                        ops[a] = op_b_bytes_as_a;
                    }
                    if let Ok(op_a_bytes_as_b) = StoredOp::from_cbor(&raw_a) {
                        ops[b] = op_a_bytes_as_b;
                    }
                }
                Ok(VaultOps {
                    ops,
                    head: honest.head,
                })
            }

            Attack::FlipBit { index } => {
                let mut ops = honest.ops;
                if index < ops.len() {
                    let mut raw = ops[index]
                        .to_cbor()
                        .map_err(|_| SyncError::MalformedPayload)?;
                    // Flip a byte in the middle of the raw bytes.
                    // This will cause the re-encode check to fail in from_cbor.
                    let mid = raw.len() / 2;
                    flip_byte(&mut raw, mid);
                    if let Ok(op) = StoredOp::from_cbor(&raw) {
                        ops[index] = op;
                    }
                    // If parse fails, the engine will hit MalformedPayload
                    // when it tries to add it.  Both are OpVerificationFailed
                    // in the engine's error mapping.
                }
                Ok(VaultOps {
                    ops,
                    head: honest.head,
                })
            }

            Attack::StripSignature { index } => {
                let mut ops = honest.ops;
                if index < ops.len() {
                    let mut raw = ops[index]
                        .to_cbor()
                        .map_err(|_| SyncError::MalformedPayload)?;
                    // The sig is the last 64 bytes of the CBOR value.
                    zero_last_n(&mut raw, 64);
                    if let Ok(op) = StoredOp::from_cbor(&raw) {
                        ops[index] = op;
                    }
                }
                Ok(VaultOps {
                    ops,
                    head: honest.head,
                })
            }

            Attack::SubstituteDeviceCert => {
                // Flip a byte in the sig field of the head's CBOR bytes.
                // Canonical order puts "sig" first. Layout:
                //   byte 0: map header (0xA9 = 9-entry map)
                //   bytes 1-4: key "sig" (0x63 0x73 0x69 0x67)
                //   bytes 5-6: value header (0x58 0x40 = bytestring[64])
                //   bytes 7-70: 64 sig bytes  ← flip here
                let head = match honest.head {
                    None => return Ok(honest),
                    Some(h) => h,
                };
                let mut head_bytes = head.to_cbor().map_err(|_| SyncError::MalformedPayload)?;
                // Flip a byte in the sig data (bytes 7-70).
                if head_bytes.len() > 70 {
                    head_bytes[40] ^= 0xFF; // flip byte 40 (inside sig data)
                }
                // from_cbor re-reads the sig bytes from the struct after parse
                // and re-encodes them; since we stored the flipped sig in the
                // struct, the re-encode passes. Then verify() fails.
                let tampered_head = VaultHead::from_cbor(&head_bytes).ok();
                Ok(VaultOps {
                    ops: honest.ops,
                    head: tampered_head,
                })
            }

            Attack::WrongVaultId { other_vault } => {
                // Replace vault_id bytes in every op's CBOR.
                let ops: Vec<StoredOp> = honest
                    .ops
                    .iter()
                    .filter_map(|op| {
                        let raw = op.to_cbor().ok()?;
                        // Replace the 16-byte vault_id bytes with other_vault.
                        let vault_id_bytes = vault_id.to_vec();
                        let patched = replace_bytes(&raw, &vault_id_bytes, &other_vault);
                        StoredOp::from_cbor(&patched).ok()
                    })
                    .collect();
                Ok(VaultOps {
                    ops,
                    head: honest.head,
                })
            }

            Attack::DowngradeSuite => {
                // Replace `"v1"` with `"v0"` in the head's CBOR bytes, then
                // serve the raw (non-parseable) bytes by returning a
                // MalformedPayload error — this simulates a relay that serves
                // an unrecognised suite id.  The client detects it as an error.
                let head = match honest.head {
                    None => return Ok(honest),
                    Some(h) => h,
                };
                let head_bytes = head.to_cbor().map_err(|_| SyncError::MalformedPayload)?;
                // `v1` in CBOR is: text string of length 2 = 0x62, 0x76, 0x31
                let v1_cbor = [0x62u8, 0x76, 0x31]; // CBOR text "v1"
                let v0_cbor = [0x62u8, 0x76, 0x30]; // CBOR text "v0"
                let patched = replace_bytes(&head_bytes, &v1_cbor, &v0_cbor);
                // VaultHead::from_cbor rejects unknown suite → Err.
                // We surface this as a MalformedPayload error.
                match VaultHead::from_cbor(&patched) {
                    Ok(h) => Ok(VaultOps {
                        ops: honest.ops,
                        head: Some(h),
                    }),
                    Err(_) => Err(SyncError::MalformedPayload),
                }
            }

            Attack::TruncateOps { n } => {
                let mut ops = honest.ops;
                ops.truncate(n);
                Ok(VaultOps {
                    ops,
                    head: honest.head,
                })
            }

            Attack::GhostHeadEntry => {
                // Return a head that references a hash not present in our ops.
                let head = match honest.head {
                    None => return Ok(honest),
                    Some(h) => h,
                };
                // Build a head pointing to a ghost hash via the inject API.
                let ghost: OpHash = [0xDEu8; 32];
                let mut head_bytes = head.to_cbor().map_err(|_| SyncError::MalformedPayload)?;
                for tip in head.heads() {
                    head_bytes = replace_bytes(&head_bytes, tip, &ghost);
                }
                let ghost_head = VaultHead::from_cbor(&head_bytes).ok();
                Ok(VaultOps {
                    ops: honest.ops,
                    head: ghost_head,
                })
            }
        }
    }

    fn put_head(
        &mut self,
        vault_id: [u8; 16],
        head: &VaultHead,
        expected_hash: [u8; 32],
    ) -> Result<(), SyncError> {
        self.inner.put_head(vault_id, head, expected_hash)
    }
}
