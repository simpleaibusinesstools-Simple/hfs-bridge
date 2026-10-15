//! Confined translation for relative symbolic links. Planning never writes
//! or grants permission to mutate a node; publication authorizes separately.
use super::*;

impl<D: BlockDevice> Adapter<D> {
    /// Remove only a conventional symbolic redirect from an exclusive explicit
    /// reparse handle. The former target is never opened for mutation.
    pub fn remove_symbolic_link(&mut self, handle: Handle, packet: &[u8]) -> Result<()> {
        self.healthy()?;
        if packet.len() != 8 || packet[..4] != 0xa000000cu32.to_le_bytes() || packet[4..] != [0; 4]
        {
            return Err(error(
                Status::InvalidParameter,
                "invalid symbolic-link removal header",
            ));
        }
        let context = self.context(handle)?;
        if context.cleaned || !context.reparse || context.stream() != Stream::Data {
            return Err(error(
                Status::InvalidHandle,
                "live explicit reparse handle required",
            ));
        }
        if !(context.access.write || context.access.metadata)
            || self.namespace_locked(context.cnid)?
        {
            return Err(error(
                Status::AccessDenied,
                "link removal needs attribute write access",
            ));
        }
        if self.pending_delete.contains_key(&context.cnid) {
            return Err(error(Status::DeletePending, "link awaits deletion"));
        }
        if self
            .handles
            .iter()
            .any(|(id, other)| *id != handle && other.cnid == context.cnid)
        {
            return Err(error(
                Status::SharingViolation,
                "link removal requires the only file handle",
            ));
        }
        let before = self.info(context.cnid)?;
        if before.node != crate::links::Node::SymbolicLink
            || !self.named_store(context.cnid)?.streams.is_empty()
        {
            return Err(error(
                Status::Unsupported,
                "conventional symbolic node without streams required",
            ));
        }
        let directory = self.symbolic_windows_target(context.cnid)?.1;
        let time = now_filetime()?;
        let exact = [
            Some(before.creation_time),
            Some(before.access_time),
            Some(time),
            Some(time),
        ];
        let mut times = [None; 4];
        for (slot, date) in times.iter_mut().zip(exact) {
            *slot = date.map(filetime_to_hfs).transpose()?;
        }
        let catalog = [fstool::fs::hfs_plus::CatalogUpdate {
            cnid: context.cnid,
            times,
            attributes: None,
        }];
        let precision = self.prepare_precision(
            &catalog,
            &[(context.cnid, exact)],
            directory.then_some((context.cnid, Kind::Directory)),
        )?;
        let mut related = precision.references();
        related.push((context.cnid, crate::links::KIND_ATTRIBUTE, None));
        let path = self.path(context.cnid)?;
        let result = self.fs.remove_symlink_with_publication(
            &mut self.device,
            Path::new(&path),
            directory,
            fstool::fs::hfs_plus::PublicationMetadata {
                catalog: &catalog,
                related: &related,
                ..Default::default()
            },
        );
        self.publication_result(result)?;
        self.handles.get_mut(&handle).unwrap().reparse = false;
        Ok(())
    }

    /// Open the reparse node itself for inspection or namespace operations.
    /// Ordinary opens never acquire permission to mutate a symbolic link.
    pub fn open_reparse(&mut self, path: &str, mut request: OpenRequest) -> Result<Handle> {
        self.healthy()?;
        if path.contains(':') {
            // Windows also sets FILE_OPEN_REPARSE_POINT for ordinary stream
            // deletion. Preserve the existing stream lifetime/access checks;
            // this flag alone does not make a stream a symbolic-link node.
            return self.open(path, request);
        }
        let cnid = self.resolve(path)?;
        if self.info(cnid)?.node != crate::links::Node::SymbolicLink {
            return self.open(path, request);
        }
        request.kind = None;
        self.check_open_inner(cnid, request, Stream::Data, true)?;
        let handle = self.add_handle(cnid, request)?;
        self.handles.get_mut(&handle).unwrap().reparse = true;
        Ok(handle)
    }
    /// Convert an empty placeholder or replace an explicit reparse node's target. The native kernel
    /// authorizes the control request; this additionally checks handle access,
    /// namespace confinement, exclusive lifetime and storage eligibility.
    pub fn set_symbolic_link(&mut self, handle: Handle, packet: &[u8]) -> Result<()> {
        let target = self.plan_symbolic_target(handle, packet)?;
        let context = self.context(handle)?;
        // FSCTL_SET_REPARSE_POINT permits FILE_WRITE_DATA or
        // FILE_WRITE_ATTRIBUTES. CreateSymbolicLinkW uses the latter; requiring
        // ordinary data-write access rejects that legitimate native request.
        // This does not grant data writes through the resulting reparse node.
        if !(context.access.write || context.access.metadata)
            || self.namespace_locked(context.cnid)?
        {
            return Err(error(
                Status::AccessDenied,
                "link control needs an unlocked file with data or attribute write access",
            ));
        }
        if self.pending_delete.contains_key(&context.cnid) {
            return Err(error(Status::DeletePending, "placeholder awaits deletion"));
        }
        if self
            .handles
            .iter()
            .any(|(id, other)| *id != handle && other.cnid == context.cnid)
        {
            return Err(error(
                Status::SharingViolation,
                "link conversion requires the only file handle",
            ));
        }
        if !self.named_store(context.cnid)?.streams.is_empty() {
            return Err(error(Status::Unsupported, "placeholder has named streams"));
        }
        let before = self.info(context.cnid)?;
        let replacing = before.node == crate::links::Node::SymbolicLink;
        let directory = before.kind == Kind::Directory;
        let link_directory = if replacing {
            self.symbolic_windows_target(context.cnid)?.1
        } else {
            directory
        };
        // A Windows directory readonly hint has no ordinary-file equivalent.
        // Refuse rather than leave metadata that the converted entry rejects.
        if directory && self.windows_flags(context.cnid)? & 1 != 0 {
            return Err(error(
                Status::AccessDenied,
                "directory placeholder is readonly",
            ));
        }
        let time = now_filetime()?;
        let exact = [
            directory.then_some(before.creation_time),
            directory.then_some(before.access_time),
            Some(time),
            Some(time),
        ];
        let mut times = [None; 4];
        for (slot, date) in times.iter_mut().zip(exact) {
            *slot = date.map(filetime_to_hfs).transpose()?;
        }
        let catalog = [fstool::fs::hfs_plus::CatalogUpdate {
            cnid: context.cnid,
            times,
            attributes: None,
        }];
        let precision = self.prepare_precision(
            &catalog,
            &[(context.cnid, exact)],
            directory.then_some((context.cnid, Kind::File)),
        )?;
        let kind = crate::links::kind_record(context.cnid, &target, link_directory);
        let mut related = precision.references();
        if directory || replacing {
            related.push((
                context.cnid,
                crate::links::KIND_ATTRIBUTE,
                Some(kind.as_slice()),
            ));
        }
        let path = self.path(context.cnid)?;
        let metadata = fstool::fs::hfs_plus::PublicationMetadata {
            catalog: &catalog,
            related: &related,
            ..Default::default()
        };
        let result = if replacing {
            self.fs.replace_symlink_target_with_publication(
                &mut self.device,
                Path::new(&path),
                &target,
                metadata,
            )
        } else if directory {
            self.fs.convert_empty_directory_to_symlink_with_publication(
                &mut self.device,
                Path::new(&path),
                &target,
                metadata,
            )
        } else {
            self.fs.convert_empty_file_to_symlink_with_publication(
                &mut self.device,
                Path::new(&path),
                &target,
                metadata,
            )
        };
        self.publication_result(result)?;
        self.handles.get_mut(&handle).unwrap().reparse = true;
        Ok(())
    }

    /// Translate a relative Windows target into a relative HFS/POSIX target.
    /// Existing components resolve only through the current public alias map.
    /// Missing components may form dangling targets. Intermediate links and dot
    /// traversal through missing directories are refused. Other dot segments
    /// are preserved, rather than changing relative path traversal semantics.
    pub fn plan_symbolic_target(&mut self, handle: Handle, packet: &[u8]) -> Result<String> {
        self.healthy()?;
        let context = self.context(handle)?;
        if context.cleaned || context.stream() != Stream::Data {
            return Err(error(
                Status::InvalidHandle,
                "live base-file handle required",
            ));
        }
        let info = self.info(context.cnid)?;
        if !(info.node == crate::links::Node::Ordinary
            || (context.reparse && info.node == crate::links::Node::SymbolicLink))
            || (info.kind == Kind::Directory
                && (context.cnid < 16 || volume::be32(&self.body(context.cnid)?, 4) != 0))
        {
            return Err(error(
                Status::Unsupported,
                "ordinary file or empty directory placeholder required",
            ));
        }
        let target = crate::links::relative_symbolic_target(packet)?;
        let parts = target.split('\\').collect::<Vec<_>>();
        if parts.len() > 1024 || parts.iter().any(|part| part.is_empty()) {
            return Err(error(
                Status::InvalidName,
                "empty or excessive target components",
            ));
        }
        let path = self.path(context.cnid)?;
        let parent = path.rsplit_once('/').unwrap().0;
        let mut raw = Vec::<String>::new();
        // One entry for each ancestor, including the volume root. None denotes
        // a missing directory, never permission to look outside this image.
        let mut directories = vec![Some(2)];
        for part in parent.split('/').filter(|part| !part.is_empty()) {
            raw.push(part.to_owned());
            let body = self
                .fs
                .catalog_record(&format!("/{}", raw.join("/")))
                .map_err(engine_error)?;
            let id = volume::be32(&body, 8);
            let visible = self
                .names(directories.last().copied().flatten().unwrap())?
                .entries()
                .iter()
                .any(|entry| entry.cnid == id);
            if !visible || volume::be16(&body, 0) != 1 || self.pending_delete.contains_key(&id) {
                return Err(error(
                    Status::AccessDenied,
                    "placeholder parent is not public",
                ));
            }
            directories.push(Some(id));
        }
        let mut translated = Vec::new();
        for (index, part) in parts.iter().enumerate() {
            match *part {
                "." => {
                    if directories.last().copied().flatten().is_none() {
                        return Err(error(
                            Status::Unsupported,
                            "dot traversal through a missing directory",
                        ));
                    }
                    translated.push(".".to_owned());
                }
                ".." => {
                    if directories.last().copied().flatten().is_none() {
                        return Err(error(
                            Status::Unsupported,
                            "dot traversal through a missing directory",
                        ));
                    }
                    if raw.pop().is_none() {
                        return Err(error(
                            Status::AccessDenied,
                            "link target escapes the volume",
                        ));
                    }
                    directories.pop();
                    translated.push("..".to_owned());
                }
                _ => {
                    let parent_id = directories.last().copied().flatten();
                    let mut resolved = None;
                    if let Some(id) = parent_id {
                        if self.pending_name(id, part)? {
                            return Err(error(Status::DeletePending, "target name awaits close"));
                        }
                        let view = self.names(id)?;
                        if let Ok(entry) = view.resolve(part) {
                            resolved = Some((entry.cnid, entry.hfs_component.clone()));
                        }
                    }
                    let (id, name) = if let Some((id, name)) = resolved {
                        if self.pending_delete.contains_key(&id) {
                            return Err(error(Status::DeletePending, "target awaits close"));
                        }
                        if index + 1 < parts.len() && volume::be16(&self.body(id)?, 0) != 1 {
                            return Err(error(
                                Status::NotDirectory,
                                "target traverses a file or symbolic link",
                            ));
                        }
                        (Some(id), name)
                    } else {
                        let name = names::new_windows_component(part)
                            .map_err(|e| error(Status::InvalidName, e))?;
                        if raw.is_empty()
                            && (mac_private_root_name(2, &name)
                                || names::same_windows_name(&name, deferred::DIRECTORY)
                                    .map_err(|e| error(Status::InvalidName, e))?)
                        {
                            return Err(error(Status::AccessDenied, "reserved link target"));
                        }
                        if parent_id.is_some() {
                            let candidate = format!(
                                "{}/{}",
                                format!("/{}", raw.join("/")).trim_end_matches('/'),
                                name
                            );
                            // An invisible entry or broader HFS name equivalence
                            // must not be mistaken for a new dangling component.
                            match self.fs.catalog_record(&candidate) {
                                Err(fstool::Error::InvalidArgument(message))
                                    if message == "hfs+: catalog entry does not exist" => {}
                                Ok(_) => {
                                    return Err(error(
                                        Status::AccessDenied,
                                        "target is absent from the public Windows view",
                                    ));
                                }
                                Err(e) => return Err(engine_error(e)),
                            }
                        }
                        (None, name)
                    };
                    raw.push(name.clone());
                    directories.push(id);
                    translated.push(name);
                }
            }
        }
        let result = translated.join("/");
        if result.len() > 1024 {
            return Err(error(
                Status::Unsupported,
                "Mac link target exceeds 1024 bytes",
            ));
        }
        Ok(result)
    }
}
