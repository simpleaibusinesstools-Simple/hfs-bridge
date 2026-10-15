//! Ordinary Windows named data streams. Store replacement and file-wide dates
//! share one HFS publication. Removed streams retain their own in-memory object
//! until the final handle closes; their IDs are never assigned to a new stream.
use super::*;
use crate::named_streams::{self as wire, Store};

pub(super) fn named_path(path: &str) -> Result<Option<(&str, &str)>> {
    let Some((base, suffix)) = path.split_once(':') else {
        return Ok(None);
    };
    components(base)?;
    if base == "\\" {
        return Err(error(Status::InvalidName, "root cannot carry a stream"));
    }
    if suffix.eq_ignore_ascii_case(":$DATA") {
        return Ok(None);
    }
    let name = if let Some((name, kind)) = suffix.split_once(':') {
        if !kind.eq_ignore_ascii_case("$DATA") {
            return Err(error(Status::InvalidName, "unsupported stream type"));
        }
        name
    } else {
        suffix
    };
    if ["AFP_Resource", "AFP_AfpInfo", "HFSB_Attributes"]
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n))
    {
        return Ok(None);
    }
    wire::validate_name(name).map_err(|e| error(Status::InvalidName, e))?;
    Ok(Some((base, name)))
}

impl<D: BlockDevice> Adapter<D> {
    fn check_overwritten_name(&mut self, cnid: u32, name: &str) -> Result<()> {
        let identity = self.metadata_cnid(cnid)?;
        for key in self
            .overwritten_named
            .iter()
            .filter(|(id, _)| *id == identity)
        {
            if let Some(record) = self.detached_named.get(key)
                && wire::same_name(&record.name, name)?
                && self
                    .handles
                    .values()
                    .any(|c| c.identity_cnid == identity && c.named == Some(key.1) && !c.cleaned)
            {
                return Err(error(
                    Status::DeletePending,
                    "overwritten stream still has open handles",
                ));
            }
        }
        Ok(())
    }
    pub(super) fn named_store(&mut self, cnid: u32) -> Result<Arc<Store>> {
        self.healthy()?;
        let cnid = self.metadata_cnid(cnid)?;
        if let Some((cached_cnid, store)) = &self.named_cache
            && *cached_cnid == cnid
        {
            return Ok(store.clone());
        }
        let store = self.read_attribute(cnid, wire::ATTRIBUTE)?.map_or_else(
            || Ok(Store::default()),
            |bytes| wire::decode(&bytes).map_err(|e| error(Status::IoError, e)),
        )?;
        let store = Arc::new(store);
        self.named_cache = Some((cnid, store.clone()));
        Ok(store)
    }
    // Borrow only the requested record. Reads and metadata queries must not
    // copy every payload in the committed container. A mutation still plans a
    // separate owned Store and installs it only after the durable publication.
    pub(super) fn with_named_record<R>(
        &mut self,
        context: Context,
        f: impl FnOnce(&wire::Stream) -> R,
    ) -> Result<R> {
        let id = context
            .named
            .ok_or_else(|| error(Status::InvalidHandle, "not a named stream"))?;
        if let Some(record) = self.detached_named.get(&(context.identity_cnid, id)) {
            return Ok(f(record));
        }
        let store = self.named_store(context.cnid)?;
        let record = store
            .streams
            .iter()
            .find(|s| s.id == id)
            .ok_or_else(|| error(Status::IoError, "live named stream disappeared"))?;
        Ok(f(record))
    }
    pub(super) fn named_info_record(
        &mut self,
        cnid: u32,
        record: &wire::Stream,
    ) -> Result<FileInfo> {
        let mut info = self.info(cnid)?;
        info.kind = Kind::File;
        info.attributes &= !0x10;
        info.size = record.data.len() as u64;
        info.allocation_size = record.allocation;
        info.ea_size = 0;
        Ok(info)
    }
    pub(super) fn named_info_path(&mut self, base: &str, name: &str) -> Result<FileInfo> {
        let cnid = self.resolve(base)?;
        self.check_overwritten_name(cnid, name)?;
        let store = self.named_store(cnid)?;
        let record = store
            .find(name)?
            .ok_or_else(|| error(Status::NotFound, "named stream absent"))?;
        self.named_info_record(cnid, record)
    }
    pub(super) fn check_named_mutation(&mut self, cnid: u32) -> Result<()> {
        let info = self.info(cnid)?;
        if cnid < 16 || info.node != crate::links::Node::Ordinary || self.namespace_locked(cnid)? {
            return Err(error(
                Status::AccessDenied,
                "named-stream target is reserved, locked or linked",
            ));
        }
        if self.body(cnid)?[41] & 0x20 != 0
            && !self
                .fs
                .compressed_conversion_supported(&mut self.device, cnid)
                .map_err(engine_error)?
        {
            return Err(error(
                Status::AccessDenied,
                "unsupported compressed stream target",
            ));
        }
        Ok(())
    }
    pub(super) fn open_named(
        &mut self,
        base: &str,
        name: &str,
        mut request: OpenRequest,
        create: bool,
        allocation: u64,
    ) -> Result<Handle> {
        if request.kind == Some(Kind::Directory) {
            return Err(error(Status::NotDirectory, "named stream is a file"));
        }
        let cnid = self.resolve(base)?;
        self.check_overwritten_name(cnid, name)?;
        let store = self.named_store(cnid)?;
        let present = store.find(name)?;
        if create && present.is_some() {
            return Err(error(Status::Collision, "named stream exists"));
        }
        let id = if create {
            store.next_id
        } else {
            present
                .ok_or_else(|| error(Status::NotFound, "named stream absent"))?
                .id
        };
        request.kind = None;
        self.check_open(cnid, request, Stream::Named(id))?;
        if create
            || request.access.write
            || request.access.append
            || request.access.delete
            || request.access.metadata
            || request.access.write_ea
        {
            self.check_named_mutation(cnid)?;
        }
        self.handle_slot()?;
        if create {
            let (planned, _) = store.with_created(name, allocation, self.fs.block_size())?;
            self.publish_named(cnid, planned, Some(now_filetime()?), true, 0)?;
        }
        let handle = self.add_handle(cnid, request)?;
        self.handles.get_mut(&handle).unwrap().named = Some(id);
        Ok(handle)
    }
    /// A cleanup allocation trim preserves dates; other changes update the
    /// change date, and content edits update the modification date as well.
    pub(super) fn publish_named(
        &mut self,
        cnid: u32,
        store: Store,
        exact: Option<u64>,
        content: bool,
        explicit_times: u8,
    ) -> Result<()> {
        self.check_named_mutation(cnid)?;
        let bytes = wire::encode(&store)?;
        let info = self.info(cnid)?;
        let dates = [
            None,
            None,
            exact.filter(|_| content && explicit_times & 4 == 0),
            exact.filter(|_| explicit_times & 8 == 0),
        ];
        let times = dates.map(|date| date.map(filetime_to_hfs).transpose());
        let [a, b, c, d] = times;
        let catalog = if exact.is_some() {
            vec![fstool::fs::hfs_plus::CatalogUpdate {
                cnid,
                times: [a?, b?, c?, d?],
                attributes: self
                    .native_windows_attributes(cnid, Some(info.attributes | 0x20))
                    .map_err(engine_error)?,
            }]
        } else {
            Vec::new()
        };
        let precision = self.prepare_precision(&catalog, &[(cnid, dates)], None)?;
        let related = precision.references();
        let attributes = [(wire::ATTRIBUTE, Some(bytes.as_slice()))];
        let metadata = fstool::fs::hfs_plus::PublicationMetadata {
            attributes: &attributes,
            catalog: &catalog,
            related: &related,
        };
        let result = if self.body(cnid)?[41] & 0x20 != 0 {
            // Convert only as part of an actual stream mutation. Existing
            // conversion preflights codec/ownership and counts decoded data,
            // attributes and private records together before its first write.
            // Round upward so allocation never truncates the original content.
            let unit = u64::from(self.fs.block_size());
            let allocation = info
                .size
                .div_ceil(unit)
                .checked_mul(unit)
                .ok_or_else(|| error(Status::DiskFull, "conversion allocation overflow"))?;
            let path = self.path(cnid)?;
            self.fs.allocate_compressed_with_publication(
                &mut self.device,
                Path::new(&path),
                allocation,
                metadata,
            )
        } else {
            self.fs
                .set_entry_attributes_with_publication(&mut self.device, cnid, metadata)
        };
        self.publication_result(result)?;
        self.durable()?;
        // Install only the fully committed container. Failed publication/sync
        // leaves no cached candidate, and subsequent reads obey sticky failure.
        self.named_cache = Some((cnid, Arc::new(store)));
        Ok(())
    }
    // A detached stream can still receive paging writes through existing
    // handles. It must never republish its name or overwrite a replacement ID.
    pub(super) fn edit_named(
        &mut self,
        context: Context,
        edit: impl FnOnce(Store, u64, u32) -> Result<Store>,
        exact: Option<u64>,
        content: bool,
    ) -> Result<()> {
        self.check_named_mutation(context.cnid)?;
        let id = context.named.unwrap();
        let key = (context.identity_cnid, id);
        if let Some(record) = self.detached_named.get(&key) {
            let single = Store {
                next_id: id
                    .checked_add(1)
                    .ok_or_else(|| error(Status::IoError, "invalid detached identity"))?,
                streams: vec![record.clone()],
            };
            let planned = edit(single, id, self.fs.block_size())?;
            self.detached_named.insert(
                key,
                planned
                    .streams
                    .into_iter()
                    .next()
                    .ok_or_else(|| error(Status::IoError, "detached edit removed its record"))?,
            );
            return Ok(());
        }
        let store = self.named_store(context.cnid)?;
        // The cache holds only committed bytes. Move them into a disposable
        // candidate instead of cloning a large payload for every small write.
        // On any refusal, a later read reloads the still-committed disk state;
        // publish_named reinstalls a cache only after successful durability.
        self.named_cache = None;
        let planned = edit(Arc::unwrap_or_clone(store), id, self.fs.block_size())?;
        self.publish_named(
            context.cnid,
            planned,
            exact,
            content,
            context.explicit_times,
        )
    }
    pub(super) fn delete_named(&mut self, context: Context) -> Result<()> {
        let id = context.named.unwrap();
        let key = (context.identity_cnid, id);
        if self.detached_named.contains_key(&key) {
            return Ok(());
        }
        let (planned, record) = self.named_store(context.cnid)?.without(id)?;
        self.publish_named(
            context.cnid,
            planned,
            Some(now_filetime()?),
            true,
            context.explicit_times,
        )?;
        self.detached_named.insert(key, record);
        Ok(())
    }
    pub(super) fn can_delete_named(&mut self, handle: Handle, context: Context) -> Result<()> {
        if !context.access.delete {
            return Err(error(Status::AccessDenied, "DELETE access required"));
        }
        self.check_named_mutation(context.cnid)?;
        if self.handles.iter().any(|(h, c)| {
            *h != handle
                && c.identity_cnid == context.identity_cnid
                && c.named == context.named
                && !c.cleaned
                && c.access.participates_in_sharing()
                && !c.share.delete
        }) {
            return Err(error(
                Status::SharingViolation,
                "named stream denies deletion",
            ));
        }
        Ok(())
    }
    #[cfg(feature = "native-mount")]
    pub(super) fn trim_named(&mut self, handle: Handle, context: Context) -> Result<()> {
        if self.handles.iter().any(|(h, c)| {
            *h != handle
                && !c.cleaned
                && c.identity_cnid == context.identity_cnid
                && c.named == context.named
        }) {
            return Ok(());
        }
        if self.info(context.cnid)?.node != crate::links::Node::Ordinary
            || self.namespace_locked(context.cnid)?
            || self.body(context.cnid)?[41] & 0x20 != 0
        {
            return Ok(());
        }
        let (size, allocation) =
            self.with_named_record(context, |r| (r.data.len(), r.allocation))?;
        let block = u64::from(self.fs.block_size());
        if allocation > (size as u64).div_ceil(block) * block {
            self.edit_named(
                context,
                |store, id, unit| store.with_trimmed_allocation(id, unit),
                None,
                false,
            )?;
        }
        Ok(())
    }
}
