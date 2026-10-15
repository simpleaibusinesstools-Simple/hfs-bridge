//! Persistent deferred reclamation using ordinary HFS records. This directory
//! belongs to this protocol; it is never exposed through the Windows namespace.
//! Validate the entire store before staging any recovery deletion. A conflicting
//! or malformed store refuses the image rather than guessing what to remove.
use super::*;
use sha2::{Digest, Sha256};

pub(super) const DIRECTORY: &str = ".hfs-bridge-orphans-v1";
const PATH: &str = "/.hfs-bridge-orphans-v1";
const MARKER: &str = "/.hfs-bridge-orphans-v1/owner";
const MAGIC: &[u8; 8] = b"HFSBOR01";

struct Store {
    cnid: u32,
    nodes: Vec<u32>,
}

impl<D: BlockDevice> Adapter<D> {
    fn store_error(detail: impl fmt::Display) -> Error {
        error(
            Status::Unsupported,
            format!("deferred-delete store: {detail}"),
        )
    }

    fn volume_identity(&mut self) -> Result<[u8; 8]> {
        let mut uuid = [0; 8];
        self.device
            .read_at(1024 + 104, &mut uuid)
            .map_err(engine_error)?;
        Ok(uuid)
    }

    fn marker_bytes(&mut self, directory: u32, marker: u32) -> Result<[u8; 64]> {
        let mut bytes = [0; 64];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..16].copy_from_slice(&self.volume_identity()?);
        bytes[16..20].copy_from_slice(&directory.to_be_bytes());
        bytes[20..24].copy_from_slice(&marker.to_be_bytes());
        let digest = Sha256::digest(&bytes[..32]);
        bytes[32..].copy_from_slice(&digest);
        Ok(bytes)
    }

    fn validate_holding(&mut self) -> Result<Option<Store>> {
        let roots = self
            .fs
            .list_path(&mut self.device, "/")
            .map_err(engine_error)?;
        let mut directory = None;
        for entry in roots {
            if mac_private_root_name(2, &entry.name) {
                if volume::be16(&self.body(entry.inode)?, 0) != 1 {
                    return Err(Self::store_error(
                        "Mac private root entry is not a directory",
                    ));
                }
                continue;
            }
            if names::same_windows_name(&entry.name, DIRECTORY).map_err(Self::store_error)? {
                if directory.is_some() || entry.name != DIRECTORY {
                    return Err(Self::store_error("conflicting reserved name"));
                }
                directory = Some(entry.inode);
            }
        }
        let Some(cnid) = directory else {
            return Ok(None);
        };
        if self.path(cnid)? != PATH
            || self.info(cnid)?.kind != Kind::Directory
            || self.info(cnid)?.attributes & 1 != 0
        {
            return Err(Self::store_error("invalid directory identity/type/lock"));
        }
        let entries = self
            .fs
            .list_path(&mut self.device, PATH)
            .map_err(engine_error)?;
        let mut owner = None;
        let mut nodes = Vec::new();
        for entry in entries {
            let expected = format!("{PATH}/{}", entry.name);
            if self.path(entry.inode)? != expected {
                return Err(Self::store_error("thread/parent mismatch"));
            }
            let info = self.info(entry.inode)?;
            if info.attributes & 1 != 0 {
                return Err(Self::store_error("locked entry"));
            }
            if entry.name == "owner" {
                if owner.replace(entry.inode).is_some()
                    || info.kind != Kind::File
                    || info.size != 64
                    || self
                        .fs
                        .resource_fork_size(&mut self.device, MARKER)
                        .map_err(engine_error)?
                        .unwrap_or(0)
                        != 0
                {
                    return Err(Self::store_error("invalid owner record"));
                }
            } else {
                if entry.name != format!("{:08X}", entry.inode) {
                    return Err(Self::store_error("unknown child or CNID mismatch"));
                }
                if info.kind == Kind::Directory
                    && !self
                        .fs
                        .list_path(&mut self.device, &expected)
                        .map_err(engine_error)?
                        .is_empty()
                {
                    return Err(Self::store_error("nonempty deferred directory"));
                }
                nodes.push(entry.inode);
                self.fs
                    .validate_remove_attributes(&mut self.device, entry.inode)
                    .map_err(engine_error)?;
            }
        }
        let owner = owner.ok_or_else(|| Self::store_error("missing owner"))?;
        let expected = self.marker_bytes(cnid, owner)?;
        let mut actual = [0; 64];
        self.fs
            .open_file_reader(&mut self.device, MARKER)
            .map_err(engine_error)?
            .read_exact(&mut actual)
            .map_err(|e| error(Status::IoError, e))?;
        if actual != expected {
            return Err(Self::store_error(
                "owner version, identity or checksum mismatch",
            ));
        }
        Ok(Some(Store { cnid, nodes }))
    }

    /// Invoked only after the normal clean-image preflight. Pending HFS journals
    /// remain refused by production open; this is not automatic journal replay.
    pub(super) fn inspect_deferred(&mut self) -> Result<()> {
        self.holding = self.validate_holding()?.map(|store| store.cnid);
        Ok(())
    }
    pub(super) fn recover_deferred(&mut self) -> Result<()> {
        let Some(store) = self.validate_holding()? else {
            return Ok(());
        };
        // Validation above covers every child before the first model mutation.
        self.holding = Some(store.cnid);
        let time = now_filetime()?;
        for cnid in store.nodes {
            let path = self.path(cnid)?;
            let result = self.fs.remove(&mut self.device, &path);
            self.mutated(result)?;
        }
        self.remove_holding(time)?;
        self.publish_namespace()?;
        self.holding = None;
        Ok(())
    }

    fn stage_holding(&mut self, existing: Option<Store>, time: u64) -> Result<u32> {
        if let Some(store) = existing {
            return Ok(store.cnid);
        }
        if self.info(2)?.attributes & 1 != 0 {
            return Err(error(Status::AccessDenied, "volume root is locked"));
        }
        // Read fallible device identity before staging any metadata changes.
        let uuid = self.volume_identity()?;
        let result = self.fs.create_dir(
            &mut self.device,
            PATH,
            0o700,
            0,
            0,
            filetime_to_hfs(time)? - 2_082_844_800,
        );
        let cnid = self.mutated(result)?;
        // No intervening creation; the marker's identity is the next CNID.
        let marker = cnid
            .checked_add(1)
            .ok_or_else(|| Self::store_error("CNID overflow"))?;
        let mut bytes = [0; 64];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..16].copy_from_slice(&uuid);
        bytes[16..20].copy_from_slice(&cnid.to_be_bytes());
        bytes[20..24].copy_from_slice(&marker.to_be_bytes());
        let digest = Sha256::digest(&bytes[..32]);
        bytes[32..].copy_from_slice(&digest);
        let result = self.fs.create_file(
            &mut self.device,
            MARKER,
            &mut &bytes[..],
            64,
            0o600,
            0,
            0,
            filetime_to_hfs(time)? - 2_082_844_800,
        );
        let created = self.mutated(result)?;
        if created != marker {
            self.failure = Some("deferred marker identity mismatch".into());
            return Err(error(
                Status::FailedVolume,
                "deferred marker identity mismatch",
            ));
        }
        Ok(cnid)
    }

    pub(super) fn pending_name(&self, parent: u32, name: &str) -> Result<bool> {
        for entry in self
            .pending_delete
            .values()
            .filter(|entry| entry.parent == parent)
        {
            if names::same_windows_name(&entry.name, name)
                .map_err(|e| error(Status::InvalidName, e))?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn defer_delete(&mut self, cnid: u32) -> Result<()> {
        let (holding, pending) = self.stage_deferred_delete(cnid)?;
        self.publish_namespace()?;
        self.holding = Some(holding);
        self.pending_delete.insert(cnid, pending);
        Ok(())
    }

    /// Stage the holding entry without publishing. Rename replacement can then
    /// publish old-target retention and the new target name in one transaction.
    pub(super) fn stage_deferred_delete(&mut self, cnid: u32) -> Result<(u32, PendingDelete)> {
        let source = self.path(cnid)?;
        let parent_path = source.rsplit_once('/').unwrap().0;
        let parent = if parent_path.is_empty() {
            2
        } else {
            volume::be32(
                &self.fs.catalog_record(parent_path).map_err(engine_error)?,
                8,
            )
        };
        let name = self
            .names(parent)?
            .entries()
            .iter()
            .find(|entry| entry.cnid == cnid)
            .ok_or_else(|| error(Status::IoError, "deletion name missing"))?
            .windows_name
            .clone();
        let store = self.validate_holding()?;
        let time = now_filetime()?;
        let holding = self.stage_holding(store, time)?;
        let destination = format!("{PATH}/{cnid:08X}");
        let result = self.fs.rename(&mut self.device, &source, &destination);
        self.mutated(result)?;
        for id in [parent, holding, 2] {
            self.stage_namespace_times(id, [None, None, Some(time), Some(time)]);
        }
        // Store creation, original-name removal and parent counts share one
        // metadata publication. Marker data is synced before journal publish.
        Ok((holding, PendingDelete { parent, name }))
    }

    pub(super) fn remove_holding(&mut self, time: u64) -> Result<()> {
        for path in [MARKER, PATH] {
            let result = self.fs.remove(&mut self.device, path);
            self.mutated(result)?;
        }
        self.stage_namespace_times(2, [None, None, Some(time), Some(time)]);
        Ok(())
    }

    pub(super) fn validate_resource_deletion(&mut self, cnid: u32) -> Result<()> {
        let path = self.path(cnid)?;
        self.fs
            .validate_resource_edit(&mut self.device, std::path::Path::new(&path))
            .map_err(engine_error)?;
        if self.validate_holding()?.is_none() {
            if self.info(2)?.attributes & 1 != 0 {
                return Err(error(Status::AccessDenied, "volume root is locked"));
            }
            if self.volume_info()?.free_bytes < u64::from(self.fs.block_size()) {
                return Err(error(
                    Status::DiskFull,
                    "resource unlink needs a recovery marker block",
                ));
            }
        }
        Ok(())
    }

    /// Unlink only the resource stream. Transfer its committed allocation into
    /// a marked recovery file before acknowledging cleanup, retaining every
    /// old resource context until its final close, including mapped I/O.
    pub(super) fn defer_resource(&mut self, base: u32) -> Result<()> {
        let store = self.validate_holding()?;
        let time = now_filetime()?;
        let holding = self.stage_holding(store, time)?;
        let temporary = format!("{PATH}/resource-pending");
        let result = self.fs.create_file(
            &mut self.device,
            &temporary,
            &mut &[][..],
            0,
            0o600,
            0,
            0,
            filetime_to_hfs(time)? - 2_082_844_800,
        );
        let orphan = self.mutated(result)?;
        let result = self.fs.rename(
            &mut self.device,
            &temporary,
            &format!("{PATH}/{orphan:08X}"),
        );
        self.mutated(result)?;
        let result = self.fs.detach_resource_fork(&mut self.device, base, orphan);
        self.mutated(result)?;
        for cnid in [base, holding, 2] {
            self.stage_namespace_times(cnid, [None, None, Some(time), Some(time)]);
        }
        self.publish_namespace()?;
        self.holding = Some(holding);
        self.pending_delete.insert(
            orphan,
            PendingDelete {
                parent: 0,
                name: String::new(),
            },
        );
        for context in self
            .handles
            .values_mut()
            .filter(|c| c.cnid == base && c.resource)
        {
            context.cnid = orphan;
            context.resource = false;
            context.display_cnid = Some(base);
        }
        Ok(())
    }
}
