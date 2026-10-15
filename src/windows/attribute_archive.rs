use super::*;
use crate::attribute_archive as wire;

pub(super) struct Archive {
    pub cnid: u32,
    pub data: Vec<u8>,
    pub dirty: bool,
    pub detached: bool,
    covered: Vec<u64>,
    covered_count: usize,
}
impl Archive {
    fn new(cnid: u32, data: Vec<u8>, dirty: bool) -> Self {
        Self {
            cnid,
            data,
            dirty,
            detached: false,
            covered: Vec::new(),
            covered_count: 0,
        }
    }
    fn reset(&mut self, size: usize) {
        self.data.clear();
        self.data.resize(size, 0);
        self.covered.clear();
        self.covered.resize(size.div_ceil(64), 0);
        self.covered_count = 0;
        self.dirty = true;
    }
    fn mark(&mut self, start: usize, end: usize) {
        self.covered.resize(self.data.len().div_ceil(64), 0);
        for byte in start..end {
            let mask = 1u64 << (byte % 64);
            if self.covered[byte / 64] & mask == 0 {
                self.covered[byte / 64] |= mask;
                self.covered_count += 1;
            }
        }
    }
}
pub(super) fn archive_path(path: &str) -> Option<&str> {
    let (base, stream) = path.split_once(':')?;
    (stream.eq_ignore_ascii_case(wire::STREAM)
        || stream.eq_ignore_ascii_case(&format!("{}:$DATA", wire::STREAM)))
    .then_some(base)
}
impl<D: BlockDevice> Adapter<D> {
    fn archive_id(&self, cnid: u32) -> Option<u64> {
        self.archives
            .iter()
            .find_map(|(&id, stream)| (stream.cnid == cnid && !stream.detached).then_some(id))
    }
    fn all_archive_values(&mut self, cnid: u32) -> Result<Vec<(String, Vec<u8>)>> {
        let cnid = self.metadata_cnid(cnid)?;
        let mut values = Vec::new();
        let mut total = 0usize;
        let compressed = self.body(cnid)?[41] & 0x20 != 0;
        for name in self.read_attribute_names(cnid)? {
            if name == crate::security_descriptor::ATTRIBUTE
                || crate::timestamps::is_private_attribute(&name)
                || name == crate::named_streams::ATTRIBUTE
                || (compressed && name == "com.apple.decmpfs")
            {
                continue;
            }
            let value = self
                .read_attribute(cnid, &name)?
                .ok_or_else(|| error(Status::IoError, "listed archive attribute is absent"))?;
            total = total
                .checked_add(value.len())
                .filter(|&n| n <= wire::MAX_VALUE_BYTES)
                .ok_or_else(|| {
                    error(
                        Status::Unsupported,
                        "aggregate archive attributes exceed 16MiB",
                    )
                })?;
            if values.len() == wire::MAX_RECORDS {
                return Err(error(Status::Unsupported, "too many archive attributes"));
            }
            values.push((name, value));
        }
        Ok(values)
    }
    fn archive_values(&mut self, cnid: u32) -> Result<Vec<(String, Vec<u8>)>> {
        Ok(self
            .all_archive_values(cnid)?
            .into_iter()
            .filter(|(name, _)| name != "com.apple.FinderInfo")
            .collect())
    }
    fn archive_bytes(&mut self, cnid: u32) -> Result<Option<Vec<u8>>> {
        let (mut eas, supplemental) = crate::ea::partition_values(self.all_archive_values(cnid)?);
        if supplemental.is_empty() {
            return Ok(None);
        }
        eas.retain(|(name, _)| name != "com.apple.FinderInfo");
        Ok(Some(wire::encode_projected(&eas, &supplemental)?))
    }
    pub(super) fn archive_info(&mut self, cnid: u32, id: Option<u64>) -> Result<FileInfo> {
        let size = match id.or_else(|| self.archive_id(cnid)) {
            Some(id) => self.archives[&id].data.len(),
            None => self.archive_bytes(cnid)?.map_or(0, |bytes| bytes.len()),
        };
        let mut info = self.info(cnid)?;
        info.kind = Kind::File;
        info.attributes &= !0x10;
        info.size = size as u64;
        // The transport envelope has no independent on-disk allocation.
        info.allocation_size = 0;
        info.ea_size = 0;
        Ok(info)
    }
    fn check_archive_open(&mut self, cnid: u32, mut request: OpenRequest) -> Result<()> {
        if request.kind == Some(Kind::Directory) {
            return Err(error(Status::NotDirectory, "metadata stream is a file"));
        }
        request.kind = None;
        self.check_open(cnid, request, Stream::Archive)
    }
    pub(super) fn open_archive(
        &mut self,
        base: &str,
        request: OpenRequest,
        create: bool,
        allocation: u64,
    ) -> Result<Handle> {
        let cnid = self.resolve(base)?;
        if cnid < 16 {
            return Err(error(
                Status::AccessDenied,
                "reserved metadata stream target",
            ));
        }
        self.check_archive_open(cnid, request)?;
        if allocation > wire::MAX_BYTES as u64 {
            return Err(error(
                Status::Unsupported,
                "metadata stream allocation limit",
            ));
        }
        let existing = self.archive_id(cnid);
        let values = if existing.is_none() {
            self.archive_bytes(cnid)?
        } else {
            None
        };
        let present = existing.is_some() || values.is_some();
        if create && present {
            return Err(error(Status::Collision, "metadata stream exists"));
        }
        if !create && !present {
            return Err(error(Status::NotFound, "metadata stream is absent"));
        }
        let initial_data = if existing.is_none() {
            Some(if create { Vec::new() } else { values.unwrap() })
        } else {
            None
        };
        let mut base_request = request;
        base_request.kind = None;
        let handle = self.add_handle(cnid, base_request)?;
        let id = existing.unwrap_or(handle.0);
        if let Some(data) = initial_data {
            self.archives.insert(id, Archive::new(cnid, data, create));
        }
        self.handles.get_mut(&handle).unwrap().archive = Some(id);
        Ok(handle)
    }
    pub(super) fn archive_read(&self, id: u64, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let stream = &self.archives[&id];
        let start = offset.min(stream.data.len() as u64) as usize;
        let count = buffer.len().min(stream.data.len() - start);
        buffer[..count].copy_from_slice(&stream.data[start..start + count]);
        Ok(count)
    }
    pub(super) fn reset_archive(&mut self, id: u64, size: u64) -> Result<()> {
        if size > wire::MAX_BYTES as u64 {
            return Err(error(Status::Unsupported, "metadata stream size limit"));
        }
        let stream = self.archives.get_mut(&id).unwrap();
        if stream.detached {
            return Err(error(Status::DeletePending, "metadata stream was unlinked"));
        }
        if !stream.dirty && size == stream.data.len() as u64 {
            return Ok(());
        }
        stream.reset(size as usize);
        Ok(())
    }
    pub(super) fn archive_write(&mut self, id: u64, offset: u64, bytes: &[u8]) -> Result<usize> {
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|&n| n <= wire::MAX_BYTES as u64)
            .ok_or_else(|| error(Status::Unsupported, "metadata stream write bounds"))?
            as usize;
        let start = offset as usize;
        let stream = self.archives.get_mut(&id).unwrap();
        if stream.detached {
            return Err(error(Status::DeletePending, "metadata stream was unlinked"));
        }
        if !stream.dirty {
            if start != 0 {
                return Err(error(
                    Status::Unsupported,
                    "metadata stream requires complete replacement",
                ));
            }
            stream.reset(0);
        }
        stream.data.resize(stream.data.len().max(end), 0);
        stream.data[start..end].copy_from_slice(bytes);
        stream.mark(start, end);
        self.publish_archive(id, false)?;
        Ok(bytes.len())
    }
    pub(super) fn publish_archive(&mut self, id: u64, required: bool) -> Result<()> {
        let stream = &self.archives[&id];
        if !stream.dirty || stream.detached {
            return Ok(());
        }
        let full_header = stream.data.len() >= 24
            && (0..24).all(|byte| {
                stream
                    .covered
                    .get(byte / 64)
                    .is_some_and(|&bits| bits & (1u64 << (byte % 64)) != 0)
            });
        let size = if full_header {
            wire::declared_size(&stream.data)?
        } else {
            None
        };
        let complete =
            size.is_some_and(|size| size == stream.data.len() && size == stream.covered_count);
        if !complete {
            if required {
                return Err(error(
                    Status::InvalidParameter,
                    "metadata stream transfer is incomplete",
                ));
            }
            return Ok(());
        }
        let snapshot = wire::decode_snapshot(&stream.data)?;
        if snapshot.records.iter().any(|(name, _)| {
            name == crate::security_descriptor::ATTRIBUTE
                || crate::timestamps::is_private_attribute(name)
                || name == crate::named_streams::ATTRIBUTE
        }) {
            return Err(error(
                Status::AccessDenied,
                "private metadata cannot be imported through attribute archives",
            ));
        }
        let cnid = stream.cnid;
        let mut values = std::collections::BTreeMap::new();
        if snapshot.projected {
            let eas = self.ea_import.get(&cnid).ok_or_else(|| {
                error(
                    Status::InvalidParameter,
                    "projected stream requires a current base-file EA import",
                )
            })?;
            for change in eas {
                if change.name != "com.apple.FinderInfo"
                    && let Some(value) = &change.value
                {
                    values.insert(change.name.clone(), value.clone());
                }
            }
        }
        for (name, value) in snapshot.records {
            if let Some(value) = value {
                values.entry(name).or_insert(value);
            }
        }
        let names = self
            .archive_values(cnid)?
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        let mut changes = values
            .into_iter()
            .map(|(name, value)| crate::ea::Change {
                name,
                value: Some(value),
            })
            .collect::<Vec<_>>();
        for name in names {
            if !changes.iter().any(|c| c.name == name) {
                changes.push(crate::ea::Change { name, value: None });
            }
        }
        if changes.len() > wire::MAX_RECORDS {
            return Err(error(
                Status::Unsupported,
                "metadata replacement exceeds batch limit",
            ));
        }
        let kind = self.info(cnid)?.kind;
        Self::reject_private_changes(&changes)?;
        self.validate_windows_attribute_changes(kind, &changes)?;
        let references = changes
            .iter()
            .map(|c| (c.name.as_str(), c.value.as_deref()))
            .collect::<Vec<_>>();
        if !references.is_empty() {
            let time = now_filetime()?;
            self.publish_entry_attributes(cnid, &references, time)?;
        }
        let stream = self.archives.get_mut(&id).unwrap();
        stream.dirty = false;
        stream.covered.clear();
        stream.covered_count = 0;
        Ok(())
    }
    pub(super) fn delete_archive(&mut self, id: u64) -> Result<()> {
        if self.archives[&id].detached {
            return Ok(());
        }
        let cnid = self.archives[&id].cnid;
        let names = self
            .archive_values(cnid)?
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        let references = names
            .iter()
            .map(|name| (name.as_str(), None))
            .collect::<Vec<_>>();
        if !references.is_empty() {
            let time = now_filetime()?;
            self.publish_entry_attributes(cnid, &references, time)?;
        }
        let stream = self.archives.get_mut(&id).unwrap();
        stream.detached = true;
        stream.dirty = false;
        Ok(())
    }
    pub(super) fn check_archive_ea_edit(&self, cnid: u32) -> Result<()> {
        if self
            .archives
            .values()
            .any(|stream| stream.cnid == cnid && !stream.detached)
        {
            return Err(error(Status::SharingViolation, "metadata stream is open"));
        }
        Ok(())
    }
    /// Fit native EAs within WinFsp's bounded transport. Omitted ordinary values
    /// travel in the supplementary stream; FinderInfo also uses its AFP stream.
    #[cfg(all(windows, feature = "native-mount"))]
    pub(crate) fn native_ea_records(&mut self, handle: Handle) -> Result<Vec<crate::ea::Record>> {
        let values = crate::ea::partition_values(self.ea_values(handle)?).0;
        crate::ea::records(&values)
    }
    #[cfg(all(windows, feature = "native-mount"))]
    pub(crate) fn extended_attributes_native(
        &mut self,
        handle: Handle,
    ) -> Result<Vec<crate::ea::Record>> {
        if !self.context(handle)?.access.read_ea {
            return Err(error(Status::AccessDenied, "FILE_READ_EA required"));
        }
        self.native_ea_records(handle)
    }
}
