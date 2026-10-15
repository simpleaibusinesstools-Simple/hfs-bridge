//! Optional WinFsp host. One mutex owns all image state; the kernel supplies
//! granted access and enforces ordinary sharing; the adapter also checks sharing
//! across existing hard-link names using the synchronous native request. The initial descriptor grants
//! full access only to the mounting process user and SYSTEM. Custom Windows
//! descriptors are stored separately from Mac ownership and ordinary EAs.
use crate::windows as core;
use ::windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW,
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            GetTokenInformation, PSECURITY_DESCRIPTOR, TOKEN_ELEVATION, TOKEN_OWNER, TOKEN_QUERY,
            TOKEN_USER, TokenElevation, TokenOwner, TokenUser,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    },
    core::{PCWSTR, PWSTR},
};
use fstool::block::BlockDevice;
use std::{
    ffi::c_void,
    path::Path,
    sync::{Arc, Mutex},
};
use winfsp::{
    FspError, Result, U16CStr,
    filesystem::{
        DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext,
        ModificationDescriptor, OpenFileInfo, StreamInfo, WideNameInfo,
    },
    host::{FileSystemHost, FileSystemParams, VolumeParams},
};

mod profile;

fn status(value: core::Status) -> FspError {
    FspError::NTSTATUS(value.ntstatus() as i32)
}
fn map_error(value: core::Error) -> FspError {
    if std::env::var_os("HFS_NATIVE_TRACE").is_some() {
        eprintln!("Adapter refusal: {value}");
    }
    status(value.status)
}
fn copy_reparse_packet(packet: Option<Vec<u8>>, buffer: &mut [u8]) -> Result<u64> {
    let packet = packet.ok_or(FspError::NTSTATUS(0xc0000275u32 as i32))?;
    if buffer.len() < packet.len() {
        return Err(FspError::NTSTATUS(0xc0000023u32 as i32));
    }
    buffer[..packet.len()].copy_from_slice(&packet);
    Ok(packet.len() as u64)
}
fn path(value: &U16CStr) -> Result<String> {
    String::from_utf16(value.as_slice()).map_err(|_| status(core::Status::InvalidName))
}
fn request(options: u32, access: u32) -> Result<core::OpenRequest> {
    let directory = options & 1 != 0;
    let file = options & 0x40 != 0;
    if directory && file {
        return Err(status(core::Status::InvalidParameter));
    }
    Ok(core::OpenRequest {
        access: core::Access {
            read: access & 1 != 0,
            write: access & 2 != 0,
            append: access & 4 != 0,
            delete: access & 0x10000 != 0,
            metadata: access & 0x100 != 0,
            read_ea: access & 8 != 0,
            write_ea: access & 0x10 != 0,
        },
        share: core::Share::ALL, // native Open does not receive sharing; WinFsp enforces it
        kind: if directory {
            Some(core::Kind::Directory)
        } else if file {
            Some(core::Kind::File)
        } else {
            None
        },
    })
}
fn hard_link_share(request: &winfsp_sys::FSP_FSCTL_TRANSACT_REQ) -> Result<core::Share> {
    if request.Kind != winfsp_sys::FspFsctlTransactCreateKind as u32 {
        return Err(status(core::Status::IoError));
    }
    // SAFETY: the transaction discriminator selects the Create union member;
    // the dispatcher owns this request for the synchronous callback duration.
    let mask = unsafe { request.Req.Create.ShareAccess };
    if mask & !7 != 0 {
        return Err(status(core::Status::InvalidParameter));
    }
    Ok(core::Share {
        read: mask & 1 != 0,
        write: mask & 2 != 0,
        delete: mask & 4 != 0,
    })
}
fn fill(source: core::FileInfo, target: &mut FileInfo) {
    *target = FileInfo {
        file_attributes: if source.attributes == 0 {
            0x80
        } else {
            source.attributes
        },
        allocation_size: source.allocation_size,
        file_size: source.size,
        creation_time: source.creation_time,
        last_access_time: source.access_time,
        last_write_time: source.write_time,
        change_time: source.change_time,
        index_number: u64::from(source.identity_cnid),
        reparse_tag: source.node.reparse_tag(),
        ea_size: source.ea_size,
        ..Default::default()
    };
}

fn normalized_name(info: &mut OpenFileInfo, requested: &str, stored: &str) {
    let requested = requested.encode_utf16().collect::<Vec<_>>();
    let stored = stored.encode_utf16().collect::<Vec<_>>();
    // WinFsp permits case changes only and supplies the buffer capacity in bytes.
    // Keep its default for alternate Unicode normalization or absent test buffers.
    if stored.len() * 2 <= usize::from(info.normalized_name_size())
        && stored.len() * 2 < winfsp::constants::FSP_FSCTL_TRANSACT_RSP_BUFFER_SIZEMAX
        && crate::names::ordinal(&requested, &stored).is_ok_and(|o| o.is_eq())
    {
        info.set_normalized_name(&stored, None);
    }
}

/// Owned self-relative descriptor. Win32 allocations never escape the constructor.
pub struct OwnerSecurity {
    descriptor: Vec<u8>,
    creation_owner: String,
}
struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0)));
        }
    }
}
struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
impl OwnerSecurity {
    pub fn current_user() -> crate::Result<Self> {
        // Token information is read into an aligned allocation before dereferencing TOKEN_USER.
        unsafe {
            let mut raw = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw)?;
            let token = Token(raw);
            let mut size = 0;
            let _ = GetTokenInformation(token.0, TokenUser, None, 0, &mut size);
            if size < std::mem::size_of::<TOKEN_USER>() as u32 || size > 65536 {
                return Err("invalid user token size".into());
            }
            let mut storage = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(storage.as_mut_ptr().cast()),
                size,
                &mut size,
            )?;
            let user = &*storage.as_ptr().cast::<TOKEN_USER>();
            // ConvertSidToStringSidW is kept local to avoid retaining pointers into the token.
            let mut sid = PWSTR::null();
            ::windows::Win32::Security::Authorization::ConvertSidToStringSidW(
                user.User.Sid,
                &mut sid,
            )?;
            let sid_allocation = LocalAllocation(sid.0.cast());
            let sid_text = sid.to_string()?;
            let sddl =
                format!("O:{sid_text}G:{sid_text}D:P(A;OICI;FA;;;{sid_text})(A;OICI;FA;;;SY)");
            drop(sid_allocation);
            // Elevated callers default new-object ownership to the token's
            // TOKEN_OWNER (often Administrators), rather than TOKEN_USER.
            // This is a creation alias only; reported ownership and grants
            // remain the uniform mounting-user descriptor below.
            let mut owner_size = 0;
            let _ = GetTokenInformation(token.0, TokenOwner, None, 0, &mut owner_size);
            if owner_size < std::mem::size_of::<TOKEN_OWNER>() as u32 || owner_size > 65536 {
                return Err("invalid default owner token size".into());
            }
            let mut owner_storage =
                vec![0usize; (owner_size as usize).div_ceil(std::mem::size_of::<usize>())];
            GetTokenInformation(
                token.0,
                TokenOwner,
                Some(owner_storage.as_mut_ptr().cast()),
                owner_size,
                &mut owner_size,
            )?;
            let owner = &*owner_storage.as_ptr().cast::<TOKEN_OWNER>();
            let mut owner_sid = PWSTR::null();
            ::windows::Win32::Security::Authorization::ConvertSidToStringSidW(
                owner.Owner,
                &mut owner_sid,
            )?;
            let owner_allocation = LocalAllocation(owner_sid.0.cast());
            let creation_owner = owner_sid.to_string()?;
            drop(owner_allocation);
            let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            let mut descriptor_size = 0;
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                Some(&mut descriptor_size),
            )?;
            let allocation = LocalAllocation(descriptor.0);
            let bytes =
                std::slice::from_raw_parts(descriptor.0.cast::<u8>(), descriptor_size as usize)
                    .to_vec();
            drop(allocation);
            Ok(Self {
                descriptor: bytes,
                creation_owner,
            })
        }
    }
    fn copy_to(&self, output: Option<&mut [c_void]>) -> Result<u64> {
        Self::copy_bytes(&self.descriptor, output)
    }
    fn copy_bytes(descriptor: &[u8], output: Option<&mut [c_void]>) -> Result<u64> {
        validate_native_security(descriptor)?;
        if let Some(output) = output {
            if output.len() < descriptor.len() {
                return Err(FspError::NTSTATUS(0xc0000023u32 as i32));
            }
            // c_void has size one; the binding's buffer represents bytes, not pointers.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    descriptor.as_ptr(),
                    output.as_mut_ptr().cast(),
                    descriptor.len(),
                );
            }
        }
        Ok(descriptor.len() as u64)
    }
    pub fn sddl(&self) -> crate::Result<String> {
        // Win32 accepts a pointer to a self-relative descriptor without modifying it.
        unsafe {
            let mut result = PWSTR::null();
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                PSECURITY_DESCRIPTOR(self.descriptor.as_ptr().cast_mut().cast()),
                SDDL_REVISION_1,
                ::windows::Win32::Security::OBJECT_SECURITY_INFORMATION(7),
                &mut result,
                None,
            )?;
            let allocation = LocalAllocation(result.0.cast());
            let text = result.to_string()?;
            drop(allocation);
            Ok(text)
        }
    }
    fn accepts_creation(&self, descriptor: Option<&[c_void]>) -> Result<()> {
        let Some(descriptor) = descriptor else {
            return Ok(());
        };
        // WinFsp computes this descriptor even for a normal CreateFile call.
        // Accept the mounting user or its token's default creation owner and
        // exactly the same two full-access ACEs. Never add an administrator ACE.
        // Inheritance/control flags and primary group do not add access grants.
        unsafe {
            let mut text = PWSTR::null();
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                PSECURITY_DESCRIPTOR(descriptor.as_ptr().cast_mut().cast()),
                SDDL_REVISION_1,
                ::windows::Win32::Security::OBJECT_SECURITY_INFORMATION(5),
                &mut text,
                None,
            )
            .map_err(|_| status(core::Status::Unsupported))?;
            let allocation = LocalAllocation(text.0.cast());
            let requested = text
                .to_string()
                .map_err(|_| status(core::Status::Unsupported))?;
            drop(allocation);
            let expected = self.sddl().map_err(|_| status(core::Status::Unsupported))?;
            if !creation_matches(&requested, &expected, &self.creation_owner) {
                if std::env::var_os("HFS_NATIVE_TRACE").is_some() {
                    eprintln!("Creation ACL refused: requested={requested} expected={expected}");
                }
                return Err(status(core::Status::Unsupported));
            }
        }
        Ok(())
    }
}

fn validate_native_security(bytes: &[u8]) -> Result<()> {
    crate::security_descriptor::validate(bytes).map_err(|_| status(core::Status::Unsupported))?;
    // Bounds are established in Rust before passing stored offsets to Win32.
    unsafe {
        let descriptor = PSECURITY_DESCRIPTOR(bytes.as_ptr().cast_mut().cast());
        if !::windows::Win32::Security::IsValidSecurityDescriptor(descriptor).as_bool()
            || ::windows::Win32::Security::GetSecurityDescriptorLength(descriptor) as usize
                > bytes.len()
        {
            return Err(status(core::Status::Unsupported));
        }
    }
    Ok(())
}

fn creation_matches(requested: &str, expected: &str, default_owner: &str) -> bool {
    let (Some((owner, grants)), Some((mount_owner, expected_grants))) =
        (creation_acl(requested), creation_acl(expected))
    else {
        return false;
    };
    // ConvertSecurityDescriptorToStringSecurityDescriptor uses BA for this SID;
    // ConvertSidToStringSid returns its numeric spelling.
    let owner = if owner == "BA" {
        "S-1-5-32-544"
    } else {
        &owner
    };
    grants == expected_grants && (owner == mount_owner || owner == default_owner)
}

fn creation_acl(sddl: &str) -> Option<(String, Vec<String>)> {
    let remainder = sddl.strip_prefix("O:")?;
    let end = [remainder.find("G:"), remainder.find("D:")]
        .into_iter()
        .flatten()
        .min()?;
    let owner = &remainder[..end];
    let (_, dacl) = sddl.split_once("D:")?;
    let (control, aces) = dacl.split_once('(')?;
    if !["", "P", "AI", "PAI", "AR", "PAR", "ARAI", "PARAI"].contains(&control) {
        return None;
    }
    let mut canonical = Vec::new();
    for ace in aces.split('(') {
        let ace = ace.strip_suffix(')')?;
        let fields = ace.split(';').collect::<Vec<_>>();
        if fields.len() != 6
            || fields[0] != "A"
            || fields[2] != "FA"
            || !fields[3].is_empty()
            || !fields[4].is_empty()
        {
            return None;
        }
        let mut flags = fields[1];
        while !flags.is_empty() {
            let rest = flags
                .strip_prefix("OI")
                .or_else(|| flags.strip_prefix("CI"))
                .or_else(|| flags.strip_prefix("ID"))?;
            flags = rest;
        }
        canonical.push(fields[5].to_owned());
    }
    if canonical.len() != 2 {
        return None;
    }
    canonical.sort();
    Some((owner.to_owned(), canonical))
}

struct State<D: BlockDevice> {
    adapter: core::Adapter<D>,
    failure: Option<String>,
    stopping: bool,
}
pub struct Native<D: BlockDevice> {
    read_only: bool,
    state: Arc<Mutex<State<D>>>,
    security: OwnerSecurity,
    profile: profile::Profile,
}
pub struct Context {
    handle: core::Handle,
    granted_access: u32,
    directory: DirBuffer,
}
impl<D: BlockDevice> Native<D> {
    pub fn new(mut adapter: core::Adapter<D>) -> crate::Result<Self> {
        adapter.use_windows_directory_hints();
        Ok(Self {
            read_only: adapter.is_read_only(),
            state: Arc::new(Mutex::new(State {
                adapter,
                failure: None,
                stopping: false,
            })),
            security: OwnerSecurity::current_user()?,
            profile: profile::Profile::new(),
        })
    }
    fn require_writable(&self) -> Result<()> {
        if self.read_only {
            Err(FspError::NTSTATUS(0xc00000a2u32 as i32))
        } else {
            Ok(())
        }
    }
    #[track_caller]
    fn with<T>(&self, f: impl FnOnce(&mut core::Adapter<D>) -> core::Result<T>) -> Result<T> {
        self.with_native(|adapter| f(adapter).map_err(map_error))
    }
    #[track_caller]
    fn with_native<T>(&self, f: impl FnOnce(&mut core::Adapter<D>) -> Result<T>) -> Result<T> {
        let mut sample = self.profile.begin();
        let mut state = self
            .state
            .lock()
            .map_err(|_| status(core::Status::FailedVolume))?;
        if let Some(sample) = &mut sample {
            sample.locked();
        }
        if state.failure.is_some() {
            return Err(status(core::Status::FailedVolume));
        }
        if state.stopping {
            return Err(status(core::Status::Busy));
        }
        f(&mut state.adapter)
    }
    #[track_caller]
    fn void(&self, f: impl FnOnce(&mut core::Adapter<D>) -> core::Result<()>) {
        let mut sample = self.profile.begin();
        if let Ok(mut state) = self.state.lock() {
            if let Some(sample) = &mut sample {
                sample.locked();
            }
            if let Err(error) = f(&mut state.adapter) {
                eprintln!("Native lifecycle failure: {error}");
                state.failure.get_or_insert(error.to_string());
            }
        }
    }
    pub fn flush_for_shutdown(&self) -> Result<()> {
        self.with(|a| a.flush_for_shutdown())
    }
    pub fn failure(&self) -> Option<String> {
        match self.state.lock() {
            Ok(s) => s
                .failure
                .clone()
                .or_else(|| s.adapter.failure().map(str::to_owned)),
            Err(_) => Some("native owner mutex poisoned".into()),
        }
    }
    pub fn volume_params(&self) -> Result<VolumeParams> {
        self.with(|a| {
            let root = a.path_info("\\")?;
            let mut params = VolumeParams::new();
            let units = u16::try_from(a.block_size() / 512).map_err(|_| core::Error {
                status: core::Status::Unsupported,
                detail: "unsupported allocation unit".into(),
            })?;
            params
                .sector_size(512)
                .sectors_per_allocation_unit(units)
                .max_component_length(255)
                .filesystem_name("HFS Bridge")
                .read_only_volume(a.is_read_only())
                .volume_creation_time(root.creation_time)
                .volume_serial_number(0x48465342)
                .case_sensitive_search(false)
                .case_preserved_names(true)
                .unicode_on_disk(true)
                .named_streams(true)
                .extended_attributes(true)
                .case_preseve_extended_attributes(true)
                .persistent_acls(true)
                .reparse_points(true)
                .reparse_points_access_check(true)
                .no_reparse_points_dir_check(true)
                .post_cleanup_when_modified_only(false)
                .flush_and_purge_on_cleanup(true)
                .pass_query_directory_filename(true)
                .file_info_timeout(0)
                .dir_info_timeout(0)
                .volume_info_timeout(0);
            Ok(params)
        })
    }
}
impl<D: BlockDevice> FileSystemContext for Native<D> {
    type FileContext = Context;
    fn get_reparse_point_by_name(
        &self,
        name: &U16CStr,
        _directory: bool,
        buffer: &mut [u8],
    ) -> Result<u64> {
        let packet = self.with(|a| {
            a.reparse_by_path(&path(name).map_err(|_| core::Error {
                status: core::Status::InvalidName,
                detail: "invalid UTF-16".into(),
            })?)
        })?;
        copy_reparse_packet(packet, buffer)
    }
    fn get_reparse_point(
        &self,
        context: &Context,
        _name: &U16CStr,
        buffer: &mut [u8],
    ) -> Result<u64> {
        copy_reparse_packet(self.with(|a| a.reparse_by_handle(context.handle))?, buffer)
    }
    fn set_reparse_point(&self, context: &Context, _name: &U16CStr, buffer: &[u8]) -> Result<()> {
        self.require_writable()?;
        if std::env::var_os("HFS_NATIVE_TRACE").is_some() {
            eprintln!(
                "Set reparse: access={:08X} bytes={}",
                context.granted_access,
                buffer.len()
            );
        }
        self.with(|a| a.set_symbolic_link(context.handle, buffer))
    }
    fn delete_reparse_point(
        &self,
        context: &Context,
        _name: &U16CStr,
        buffer: &[u8],
    ) -> Result<()> {
        self.require_writable()?;
        self.with(|a| a.remove_symbolic_link(context.handle, buffer))
    }
    fn get_extended_attributes(&self, context: &Context, buffer: &mut [u8]) -> Result<u32> {
        let records = self.with(|a| a.extended_attributes_native(context.handle))?;
        let packet = crate::ea::encode(&records).map_err(map_error)?;
        let mut aligned = packet
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| u32::from_ne_bytes(*chunk))
            .collect::<Vec<_>>();
        let mut used = 0u32;
        let mut offset = 0usize;
        while offset < packet.len() {
            // encode emits aligned, validated FILE_FULL_EA_INFORMATION records;
            // u32 storage guarantees the alignment required by the native ABI.
            let entry = unsafe {
                aligned
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<winfsp_sys::_FILE_FULL_EA_INFORMATION>()
            };
            let added = unsafe {
                winfsp_sys::FspFileSystemAddEa(
                    entry,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    &mut used,
                )
            };
            if added == 0 {
                if used == 0 {
                    return Err(FspError::NTSTATUS(0xc0000023u32 as i32));
                }
                return Ok(used);
            }
            let next = u32::from_le_bytes(packet[offset..offset + 4].try_into().unwrap()) as usize;
            if next == 0 {
                break;
            }
            offset += next;
        }
        unsafe {
            winfsp_sys::FspFileSystemAddEa(
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut used,
            )
        };
        Ok(used)
    }
    fn set_extended_attributes(
        &self,
        context: &Context,
        buffer: &[u8],
        info: &mut FileInfo,
    ) -> Result<()> {
        self.require_writable()?;
        self.with(|a| a.set_extended_attributes(context.handle, buffer))?;
        fill(self.with(|a| a.file_info_native(context.handle))?, info);
        Ok(())
    }
    fn get_stream_info(&self, context: &Context, buffer: &mut [u8]) -> Result<u32> {
        let streams = self.with(|a| a.streams(context.handle))?;
        let mut cursor = 0;
        for (name, info) in streams {
            let mut entry = StreamInfo::<256>::new();
            entry.stream_size = info.size;
            entry.stream_alloc_size = info.allocation_size;
            // StreamInfo names exclude both NT path syntax and a NUL terminator.
            entry.set_name_raw(name.encode_utf16().collect::<Vec<_>>().as_slice())?;
            if !entry.append_to_buffer(buffer, &mut cursor) {
                break;
            }
        }
        StreamInfo::<256>::finalize_buffer(buffer, &mut cursor);
        Ok(cursor)
    }
    fn get_security_by_name(
        &self,
        name: &U16CStr,
        output: Option<&mut [c_void]>,
        resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> Result<FileSecurity> {
        if let Some(security) = resolver(name) {
            return Ok(security);
        }
        let name = path(name)?;
        let (info, descriptor) =
            self.with(|a| Ok((a.path_info(&name)?, a.native_security_by_path(&name)?)))?;
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: match descriptor {
                Some(bytes) => OwnerSecurity::copy_bytes(&bytes, output)?,
                None => self.security.copy_to(output)?,
            },
            attributes: if info.attributes == 0 {
                0x80
            } else {
                info.attributes
            },
        })
    }
    fn open(
        &self,
        name: &U16CStr,
        options: u32,
        access: u32,
        info: &mut OpenFileInfo,
    ) -> Result<Context> {
        if self.read_only && (access & 0x500d0156 != 0 || options & 0x1000 != 0) {
            self.require_writable()?;
        }
        let path = path(name)?;
        let mut request = request(options, access)?;
        let node = self.with(|a| a.path_info(&path))?.node;
        if node == crate::links::Node::HardLink {
            // SAFETY: this is a synchronous FileSystemContext::open callback.
            // Only a copied share mask leaves the closure; no request reference
            // is retained, and operation-context access is not recursive.
            request.share = unsafe { self.with_operation_request(hard_link_share) }
                .ok_or_else(|| status(core::Status::IoError))??;
        }
        if node.reparse_tag() != 0 && options & 0x200000 == 0 {
            // Resolution must happen before a normal open. In particular a
            // zero-size FIFO must never masquerade as an empty regular file.
            return Err(FspError::NTSTATUS(0xc0000279u32 as i32));
        }
        if options & 0x200000 != 0 && node == crate::links::Node::SymbolicLink {
            request.kind = None;
        }
        let handle = self.with(|a| {
            if options & 0x200000 != 0 {
                a.open_reparse(&path, request)
            } else {
                a.open(&path, request)
            }
        })?;
        if path == "\\" && std::env::var_os("HFS_NATIVE_TRACE").is_some() {
            // SAFETY: this call is inside the synchronous open callback; the
            // returned process identifier is copied and is diagnostic only.
            let process = unsafe { winfsp_sys::FspFileSystemOperationProcessIdF() };
            eprintln!(
                "Root open {handle:?}: pid={process} access={access:08X} options={options:08X}"
            );
        }
        match self.with(|a| {
            Ok((
                a.file_info_native(handle)?,
                a.normalized_windows_path(&path)?,
            ))
        }) {
            Ok((value, stored)) => {
                fill(value, info.as_mut());
                normalized_name(info, &path, &stored);
            }
            Err(e) => {
                self.void(|a| a.close(handle));
                return Err(e);
            }
        }
        Ok(Context {
            handle,
            granted_access: access,
            directory: DirBuffer::new(),
        })
    }
    fn create(
        &self,
        name: &U16CStr,
        options: u32,
        access: u32,
        attributes: u32,
        descriptor: Option<&[c_void]>,
        allocation_size: u64,
        extra: Option<&[u8]>,
        reparse: bool,
        info: &mut OpenFileInfo,
    ) -> Result<Context> {
        self.require_writable()?;
        // The kernel computes the inherited descriptor and grants creation
        // access. Persist supported custom descriptors atomically with creation.
        if std::env::var_os("HFS_NATIVE_TRACE").is_some() {
            eprintln!(
                "Create: options={options:08X} access={access:08X} attributes={attributes:08X} security={} allocation={allocation_size} extra={}",
                descriptor.is_some(),
                extra.map_or(0, |e| e.len())
            );
        }
        let stored_descriptor = if let Some(value) = descriptor {
            // The WinFsp binding supplies a bounded byte slice from its request.
            let bytes =
                unsafe { std::slice::from_raw_parts(value.as_ptr().cast::<u8>(), value.len()) };
            validate_native_security(bytes)?;
            if self.security.accepts_creation(descriptor).is_ok() {
                None
            } else {
                Some(bytes)
            }
        } else {
            None
        };
        if reparse || attributes & !0x1b7 != 0 {
            return Err(status(core::Status::Unsupported));
        }
        let initial = crate::ea::changes(extra.unwrap_or_default(), &[]).map_err(map_error)?;
        let path = path(name)?;
        let request = request(options, access)?;
        let kind = if options & 1 != 0 {
            core::Kind::Directory
        } else {
            core::Kind::File
        };
        let attributes = attributes | if kind == core::Kind::File { 0x20 } else { 0x10 };
        let handle = self.with(|a| {
            a.create_with_security(
                &path,
                kind,
                request,
                Some(attributes),
                allocation_size,
                &initial,
                stored_descriptor,
            )
        })?;
        match self.with(|a| {
            Ok((
                a.file_info_native(handle)?,
                a.normalized_windows_path(&path)?,
            ))
        }) {
            Ok((value, stored)) => {
                fill(value, info.as_mut());
                normalized_name(info, &path, &stored);
            }
            Err(e) => {
                self.void(|a| a.close(handle));
                return Err(e);
            }
        }
        Ok(Context {
            handle,
            granted_access: access,
            directory: DirBuffer::new(),
        })
    }
    fn cleanup(&self, context: &Context, _name: Option<&U16CStr>, flags: u32) {
        self.void(|a| a.cleanup_native(context.handle, flags));
    }
    fn close(&self, context: Context) {
        self.void(|a| a.close(context.handle));
    }
    fn get_security(&self, context: &Context, output: Option<&mut [c_void]>) -> Result<u64> {
        let descriptor = self.with(|a| a.native_security(context.handle))?;
        match descriptor {
            Some(bytes) => OwnerSecurity::copy_bytes(&bytes, output),
            None => self.security.copy_to(output),
        }
    }
    fn set_security(
        &self,
        context: &Context,
        information: u32,
        modification: ModificationDescriptor,
    ) -> Result<()> {
        self.require_writable()?;
        if information == 0 || information & !0xa0000007 != 0 {
            return Err(status(core::Status::Unsupported));
        }
        if (information & 3 != 0 && context.granted_access & 0x80000 == 0)
            || (information & 0xa0000004 != 0 && context.granted_access & 0x40000 == 0)
        {
            return Err(status(core::Status::AccessDenied));
        }
        // Read, merge and publish under the same owner mutex so concurrent
        // owner/group/DACL edits cannot overwrite one another's changes.
        self.with_native(|adapter| {
            let descriptor = adapter.native_security(context.handle).map_err(map_error)?;
            let input = descriptor.as_deref().unwrap_or(&self.security.descriptor);
            validate_native_security(input)?;
            unsafe {
                let mut result = std::ptr::null_mut();
                let code = winfsp_sys::FspSetSecurityDescriptor(
                    input.as_ptr().cast_mut().cast(),
                    information,
                    modification.as_mut_ptr(),
                    &mut result,
                );
                if code < 0 {
                    return Err(FspError::NTSTATUS(code));
                }
                struct Allocation(*mut c_void);
                impl Drop for Allocation {
                    fn drop(&mut self) {
                        unsafe {
                            winfsp_sys::FspDeleteSecurityDescriptor(
                                self.0,
                                // WinFsp's C API takes the creating function's
                                // identity as an unprototyped function pointer.
                                // It is not invoked through this erased signature.
                                Some(std::mem::transmute::<
                                    unsafe extern "C" fn(
                                        *mut c_void,
                                        u32,
                                        *mut c_void,
                                        *mut *mut c_void,
                                    )
                                        -> i32,
                                    unsafe extern "C" fn() -> i32,
                                >(
                                    winfsp_sys::FspSetSecurityDescriptor
                                )),
                            );
                        }
                    }
                }
                let allocation = Allocation(result);
                let length = ::windows::Win32::Security::GetSecurityDescriptorLength(
                    PSECURITY_DESCRIPTOR(result),
                ) as usize;
                if !(20..=crate::security_descriptor::MAX_BYTES).contains(&length) {
                    return Err(status(core::Status::Unsupported));
                }
                let bytes = std::slice::from_raw_parts(allocation.0.cast::<u8>(), length);
                validate_native_security(bytes)?;
                adapter
                    .set_native_security(context.handle, bytes)
                    .map_err(map_error)
            }
        })
    }
    fn get_file_info(&self, context: &Context, info: &mut FileInfo) -> Result<()> {
        fill(
            self.with(|a| a.file_info_native_shared(context.handle))?,
            info,
        );
        Ok(())
    }
    fn get_volume_info(&self, output: &mut winfsp::filesystem::VolumeInfo) -> Result<()> {
        let info = self.with(|a| a.volume_info())?;
        output.total_size = info.total_bytes;
        output.free_size = info.free_bytes;
        output.set_volume_label(info.label);
        Ok(())
    }
    fn set_volume_label(
        &self,
        label: &U16CStr,
        output: &mut winfsp::filesystem::VolumeInfo,
    ) -> Result<()> {
        self.require_writable()?;
        let label = path(label)?;
        self.with(|a| a.set_volume_label(&label))?;
        self.get_volume_info(output)
    }
    fn flush(&self, context: Option<&Context>, info: &mut FileInfo) -> Result<()> {
        self.with(|a| a.flush(context.map(|x| x.handle)))?;
        if let Some(context) = context {
            self.get_file_info(context, info)?;
        }
        Ok(())
    }
    fn read(&self, context: &Context, output: &mut [u8], offset: u64) -> Result<u32> {
        let count = self.with(|a| a.read_native(context.handle, offset, output))?;
        if count == 0 && !output.is_empty() {
            return Err(FspError::NTSTATUS(0xc0000011u32 as i32));
        }
        Ok(count as u32)
    }
    fn write(
        &self,
        context: &Context,
        input: &[u8],
        offset: u64,
        append: bool,
        constrained: bool,
        info: &mut FileInfo,
    ) -> Result<u32> {
        self.require_writable()?;
        let count = self.with(|a| a.write(context.handle, offset, input, append, constrained))?;
        self.get_file_info(context, info)?;
        Ok(count as u32)
    }
    fn set_file_size(
        &self,
        context: &Context,
        size: u64,
        allocation: bool,
        info: &mut FileInfo,
    ) -> Result<()> {
        self.require_writable()?;
        self.with(|a| {
            if allocation {
                a.set_allocation_size(context.handle, size)
            } else {
                a.set_size(context.handle, size)
            }
        })?;
        self.get_file_info(context, info)
    }
    fn set_basic_info(
        &self,
        context: &Context,
        attributes: u32,
        creation: u64,
        access: u64,
        write: u64,
        change: u64,
        info: &mut FileInfo,
    ) -> Result<()> {
        self.require_writable()?;
        self.with(|a| {
            a.set_basic_info(
                context.handle,
                core::BasicTimes {
                    creation: (creation != 0).then_some(creation),
                    access: (access != 0).then_some(access),
                    write: (write != 0).then_some(write),
                    change: (change != 0).then_some(change),
                },
                (attributes != u32::MAX).then_some(attributes),
            )
        })?;
        self.get_file_info(context, info)
    }
    fn overwrite(
        &self,
        context: &Context,
        attributes: u32,
        replace_attributes: bool,
        allocation: u64,
        extra: Option<&[u8]>,
        info: &mut FileInfo,
    ) -> Result<()> {
        self.require_writable()?;
        self.with(|a| {
            let changes = if extra.is_some_and(|x| !x.is_empty()) {
                a.creation_ea_changes(context.handle, extra.unwrap())?
            } else {
                Vec::new()
            };
            a.overwrite_with_ea(
                context.handle,
                attributes,
                replace_attributes,
                allocation,
                &changes,
            )
        })?;
        self.get_file_info(context, info)
    }
    fn set_delete(&self, context: &Context, _name: &U16CStr, delete: bool) -> Result<()> {
        if delete {
            self.require_writable()?;
            self.with(|a| a.can_delete(context.handle))
        } else {
            self.with(|a| a.file_info_native(context.handle))
                .map(|_| ())
        }
    }
    fn rename(
        &self,
        context: &Context,
        _old: &U16CStr,
        new: &U16CStr,
        replace: bool,
    ) -> Result<()> {
        self.require_writable()?;
        let destination = path(new)?;
        self.with(|a| a.rename_native(context.handle, &destination, replace))
    }
    fn get_dir_info_by_name(
        &self,
        context: &Context,
        file_name: &U16CStr,
        out_dir_info: &mut DirInfo,
    ) -> Result<()> {
        let name = path(file_name)?;
        let entry = self.with(|a| a.directory_entry(context.handle, &name))?;
        out_dir_info.reset();
        out_dir_info.set_name_raw(entry.name.encode_utf16().collect::<Vec<_>>().as_slice())?;
        fill(entry.info, out_dir_info.file_info_mut());
        Ok(())
    }
    fn read_directory(
        &self,
        context: &Context,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> Result<u32> {
        // Native helper snapshots and pages one enumeration. Filtering stays in
        // the kernel (PassQueryDirectoryPattern is false), never drops pages.
        let mut sample = self.profile.begin();
        let mut owner = self
            .state
            .lock()
            .map_err(|_| status(core::Status::FailedVolume))?;
        if let Some(sample) = &mut sample {
            sample.locked();
        }
        if owner.failure.is_some() {
            return Err(status(core::Status::FailedVolume));
        }
        if owner.stopping {
            return Err(status(core::Status::Busy));
        }
        let a = &mut owner.adapter;
        let current = a.file_info_native(context.handle).map_err(map_error)?;
        match context.directory.acquire(marker.is_none(), None) {
            Ok(lock) => {
                let entries = a.read_directory(context.handle).map_err(map_error)?;
                let mut values = Vec::new();
                if current.cnid != 2 {
                    values.push((".".to_string(), current));
                    values.push((
                        "..".to_string(),
                        a.parent_info(context.handle).map_err(map_error)?,
                    ));
                }
                values.extend(entries.into_iter().map(|e| (e.name, e.info)));
                for (name, info) in values {
                    let mut entry = DirInfo::<255>::new();
                    entry.set_name_raw(name.encode_utf16().collect::<Vec<_>>().as_slice())?;
                    fill(info, entry.file_info_mut());
                    lock.write(&mut entry)?;
                }
            }
            Err(e) if e.to_ntstatus() == 0 => {} // already captured until restart
            Err(e) => return Err(e),
        }
        Ok(context.directory.read(marker, buffer))
    }
}

/// Interactive host lifetime: EOF/Enter requests unmount; a busy mount stays
/// alive and requests another Enter. Never releases the image on a busy check.
pub fn mount_image(
    source: &Path,
    output: &Path,
    base: u64,
    length: Option<u64>,
    letter: &str,
) -> crate::Result<()> {
    mount_with_factory(
        || core::Adapter::copy_image(source, output, base, length),
        letter,
        "disposable image",
    )
}

/// Mount exactly the previously inspected partition of an already-offline USB
/// disk. The disk factory checks identity, geometry and exclusive ownership.
pub fn mount_read_only_disk(
    number: u32,
    partition: u32,
    token: &str,
    letter: &str,
) -> crate::Result<()> {
    mount_with_factory(
        || {
            Ok(core::Adapter::from_read_only_device(
                crate::disk::open_read_partition(number, partition, token)?,
            )?)
        },
        letter,
        "read-only external drive",
    )
}

pub fn mount_read_only_image(
    source: &Path,
    base: u64,
    length: Option<u64>,
    letter: &str,
) -> crate::Result<()> {
    mount_with_factory(
        || {
            Ok(core::Adapter::from_read_only_device(
                crate::image::Image::read_only(source, base, length)?,
            )?)
        },
        letter,
        "read-only image",
    )
}

pub fn mount_disk(number: u32, partition: u32, token: &str, letter: &str) -> crate::Result<()> {
    mount_with_factory(
        || {
            Ok(core::Adapter::from_device(crate::disk::open_partition(
                number, partition, token,
            )?)?)
        },
        letter,
        "selected offline disk partition",
    )
}

/// Hold a removable USB partition's volume lock and buffered write-through
/// handle until all filesystem callbacks stop and the final flush succeeds.
pub fn mount_locked_volume(
    number: u32,
    partition: u32,
    token: &str,
    letter: &str,
) -> crate::Result<()> {
    mount_with_factory(
        || {
            Ok(core::Adapter::from_device(
                crate::disk::locked_volume::open(number, partition, token)?,
            )?)
        },
        letter,
        "locked removable USB partition",
    )
}

/// Host an adapter whose caller already owns its backing device. This accepts
/// no device path and does not acquire or alter any Windows disk. The caller
/// retains the outer capability (for example, a newly created test VHD) until
/// this returns; all filesystem contexts must close before explicit unmount.
pub fn mount_owned_adapter<D: BlockDevice>(
    adapter: core::Adapter<D>,
    letter: &str,
) -> crate::Result<()> {
    mount_with_factory(|| Ok(adapter), letter, "owned disposable device")
}

fn process_is_elevated() -> crate::Result<bool> {
    unsafe {
        let mut raw = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw)?;
        let token = Token(raw);
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0;
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )?;
        if returned != std::mem::size_of::<TOKEN_ELEVATION>() as u32 {
            return Err("invalid token elevation result".into());
        }
        Ok(elevation.TokenIsElevated != 0)
    }
}

fn mount_with_factory<D: BlockDevice>(
    factory: impl FnOnce() -> crate::Result<core::Adapter<D>>,
    letter: &str,
    description: &str,
) -> crate::Result<()> {
    let bytes = letter.as_bytes();
    if bytes.len() != 2
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || matches!(bytes[0].to_ascii_uppercase(), b'A'..=b'C')
    {
        return Err("mount point must be an unused drive letter D: through Z:".into());
    }
    // Load the pinned runtime from the package or an exact development path.
    load_runtime()?;
    let drives = unsafe { ::windows::Win32::Storage::FileSystem::GetLogicalDrives() };
    let bit = u32::from(bytes[0].to_ascii_uppercase() - b'A');
    if drives == 0 || drives & (1 << bit) != 0 {
        return Err("mount drive letter is already in use or drive inventory failed".into());
    }
    let native = Native::new(factory()?)?;
    let read_only = native.read_only;
    let state = native.state.clone();
    let mut params = FileSystemParams::default_params(native.volume_params()?);
    params.use_dir_info_by_name = true;
    let mut host = FileSystemHost::<_, winfsp::host::FineGuard>::new_with_options(params, native)?;
    // A plain X: link belongs to the caller's logon namespace. After UAC that
    // namespace differs from ordinary Explorer's. WinFsp's \\.\X: syntax uses
    // Mount Manager to publish a transient, globally visible drive instead.
    // File access still uses the existing mounting-user/SYSTEM descriptor.
    // Ordinary image mounts retain their non-admin, session-local behavior.
    let mount_point = if process_is_elevated()? {
        format!(r"\\.\{letter}")
    } else {
        letter.to_owned()
    };
    host.mount(&mount_point)?;
    host.start()?;
    println!(
        "Mounted {description} at {letter}\\. Press Enter to unmount; keep this process running."
    );
    loop {
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            return Err("stdin closed before an explicit unmount request".into());
        }
        let outcome = {
            let mut owner = state.lock().map_err(|_| "native owner mutex poisoned")?;
            if let Some(error) = &owner.failure {
                return Err(error.clone().into());
            }
            let result = owner.adapter.flush_for_shutdown();
            if result.is_ok() {
                owner.stopping = true;
            }
            result
        };
        match outcome {
            Ok(()) => break,
            Err(e) if e.status == core::Status::Busy => {
                eprintln!("Open files remain; close them and press Enter again.");
            }
            Err(e) => return Err(e.into()),
        }
    }
    host.unmount();
    host.stop();
    {
        let mut owner = state.lock().map_err(|_| "native owner mutex poisoned")?;
        if let Some(error) = &owner.failure {
            return Err(error.clone().into());
        }
        owner.adapter.flush_for_shutdown()?;
    }
    if read_only {
        println!("Unmounted; {description} closed without changes.");
    } else {
        println!("Unmounted; {description} flushed successfully.");
    }
    Ok(())
}

fn runtime_path(
    executable: &Path,
    project: &Path,
    packaged: bool,
) -> crate::Result<std::path::PathBuf> {
    let parent = executable.parent().ok_or("executable has no directory")?;
    let sibling = parent.join("runtime/winfsp-x64.dll");
    if packaged {
        return Ok(sibling);
    }
    let development = [
        "target/native/release/hfs-bridge.exe",
        "target/native/debug/hfs-bridge.exe",
        "target/debug/hfs-bridge.exe",
    ]
    .iter()
    .any(|relative| executable == project.join(relative));
    let unit_test = cfg!(test) && parent == project.join("target/native/debug/deps");
    if development || unit_test {
        return Ok(project.join(".cache/native/runtime/winfsp-x64.dll"));
    }
    // Relocated executables must use their own package runtime. They cannot
    // silently depend on a developer checkout, current directory or PATH.
    Ok(sibling)
}

pub fn load_runtime() -> crate::Result<()> {
    use sha2::{Digest, Sha256};
    use std::{fs::OpenOptions, io::Read, os::windows::fs::OpenOptionsExt};
    if !cfg!(target_arch = "x86_64") {
        return Err("initial native runtime supports Windows x64 only".into());
    }
    let executable = std::env::current_exe()?;
    let sibling = executable
        .parent()
        .ok_or("executable has no directory")?
        .join("runtime/winfsp-x64.dll");
    let dll = runtime_path(
        &executable,
        Path::new(env!("CARGO_MANIFEST_DIR")),
        sibling.try_exists()?,
    )?;
    crate::image::validate_path(&dll)?;
    let mut file = OpenOptions::new().read(true).share_mode(1).open(&dll)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 {
        return Err("invalid runtime DLL".into());
    }
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    let digest = format!("{:X}", Sha256::digest(&contents));
    if digest != "08D7389B8D030770A4DE108A60A86047D5CDD00B9ECAFC6DD66E957BC51C2437" {
        return Err("runtime DLL does not match the reviewed WinFsp 2.1 release".into());
    }
    // Keep the read handle denying replacement/writes throughout loading.
    unsafe {
        use ::windows::Win32::System::LibraryLoader::{
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
        };
        LoadLibraryExW(
            &::windows::core::HSTRING::from(dll.as_os_str()),
            None,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )?;
    }
    drop(file);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn hard_link_share_validates_the_native_transaction_and_all_masks() {
        let mut request = winfsp_sys::FSP_FSCTL_TRANSACT_REQ::default();
        assert!(super::hard_link_share(&request).is_err());
        request.Kind = winfsp_sys::FspFsctlTransactCreateKind as u32;
        for mask in 0..8 {
            request.Req.Create.ShareAccess = mask;
            let share = super::hard_link_share(&request).unwrap();
            assert_eq!(share.read, mask & 1 != 0);
            assert_eq!(share.write, mask & 2 != 0);
            assert_eq!(share.delete, mask & 4 != 0);
        }
        for mask in [8, 0x100, u32::MAX] {
            request.Req.Create.ShareAccess = mask;
            assert!(super::hard_link_share(&request).is_err());
        }
    }
    use super::*;
    use fstool::{
        block::MemoryBackend,
        fs::hfs_plus::{FormatOpts, HfsPlus},
    };
    use winfsp::U16CString;
    #[test]
    fn relocated_runtime_never_falls_back_to_the_developer_checkout() {
        let project = Path::new(r"C:\development\HFS Bridge");
        let development = project.join("target/native/release/hfs-bridge.exe");
        assert_eq!(
            runtime_path(&development, project, false).unwrap(),
            project.join(".cache/native/runtime/winfsp-x64.dll")
        );
        assert_eq!(
            runtime_path(&development, project, true).unwrap(),
            development.parent().unwrap().join("runtime/winfsp-x64.dll")
        );
        let relocated = Path::new(r"D:\private test\bin\hfs-bridge.exe");
        for present in [false, true] {
            assert_eq!(
                runtime_path(relocated, project, present).unwrap(),
                relocated.parent().unwrap().join("runtime/winfsp-x64.dll")
            );
        }
        let misleading = project.join("artifacts/unreviewed/hfs-bridge.exe");
        assert_eq!(
            runtime_path(&misleading, project, false).unwrap(),
            misleading.parent().unwrap().join("runtime/winfsp-x64.dll")
        );
    }
    fn name(value: &str) -> U16CString {
        U16CString::from_str(value).unwrap()
    }
    fn native() -> Native<MemoryBackend> {
        load_runtime().unwrap();
        let mut disk = MemoryBackend::new(32 * 1024 * 1024);
        let mut fs = HfsPlus::format(
            &mut disk,
            &FormatOpts {
                journaled: true,
                ..Default::default()
            },
        )
        .unwrap();
        fs.flush(&mut disk).unwrap();
        Native::new(core::Adapter::from_device(disk).unwrap()).unwrap()
    }
    #[test]
    fn invalid_mount_letters_never_acquire_a_backing_device() {
        for letter in ["C:", "A:", "Z", "Z:\\", "\\\\.\\PhysicalDrive0", "1:"] {
            let result = mount_with_factory::<MemoryBackend>(
                || panic!("invalid mount letter acquired a device"),
                letter,
                "test device",
            );
            assert!(result.is_err());
        }
    }
    fn open_info() -> OpenFileInfo {
        // Only the FileInfo prefix is written by these tests; normalized_name is
        // never dereferenced. All fields admit zero bit patterns in the binding.
        unsafe { std::mem::zeroed() }
    }
    #[test]
    fn read_only_mount_callbacks_browse_but_refuse_mutations_and_cleanup_writes() {
        use std::io::{self, Read, Seek, SeekFrom, Write};
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Audited {
            disk: MemoryBackend,
            writes: Arc<AtomicUsize>,
            syncs: Arc<AtomicUsize>,
        }
        impl Read for Audited {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.disk.read(b)
            }
        }
        impl Seek for Audited {
            fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
                self.disk.seek(p)
            }
        }
        impl Write for Audited {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.writes.fetch_add(1, Ordering::SeqCst);
                self.disk.write(b)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.syncs.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
        impl BlockDevice for Audited {
            fn block_size(&self) -> u32 {
                self.disk.block_size()
            }
            fn total_size(&self) -> u64 {
                self.disk.total_size()
            }
            fn sync(&mut self) -> fstool::Result<()> {
                self.syncs.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
        load_runtime().unwrap();
        for journaled in [false, true] {
            let mut disk = MemoryBackend::new(8 * 1024 * 1024);
            let mut fs = HfsPlus::format(
                &mut disk,
                &FormatOpts {
                    journaled,
                    ..Default::default()
                },
            )
            .unwrap();
            fs.flush(&mut disk).unwrap();
            drop(fs);
            let mut writer = core::Adapter::from_device(disk).unwrap();
            let h = writer
                .create(
                    "\\sample.txt",
                    core::Kind::File,
                    core::OpenRequest {
                        access: core::Access::ALL,
                        ..Default::default()
                    },
                )
                .unwrap();
            writer
                .write(h, 0, b"original payload", false, false)
                .unwrap();
            writer.set_allocation_size(h, 65536).unwrap();
            writer.close(h).unwrap();
            let disk = writer.shutdown().unwrap();
            let writes = Arc::new(AtomicUsize::new(0));
            let syncs = Arc::new(AtomicUsize::new(0));
            let n = Native::new(
                core::Adapter::from_read_only_device(Audited {
                    disk,
                    writes: writes.clone(),
                    syncs: syncs.clone(),
                })
                .unwrap(),
            )
            .unwrap();
            assert!(n.read_only);
            n.volume_params().unwrap();
            let before = n.with(|a| a.path_info("\\sample.txt")).unwrap();
            let h = n
                .open(&name("\\sample.txt"), 0, 0x120089, &mut open_info())
                .unwrap();
            let mut bytes = [0; 16];
            assert_eq!(n.read(&h, &mut bytes, 0).unwrap(), 16);
            assert_eq!(&bytes, b"original payload");
            let protected = |result: Result<()>| {
                assert!(
                    matches!(result, Err(FspError::NTSTATUS(code)) if code as u32 == 0xc00000a2)
                )
            };
            for access in [2, 4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000] {
                protected(
                    n.open(&name("\\sample.txt"), 0, access, &mut open_info())
                        .map(|_| ()),
                );
            }
            protected(
                n.open(&name("\\sample.txt"), 0x1000, 1, &mut open_info())
                    .map(|_| ()),
            );
            protected(
                n.create(
                    &name("\\new.txt"),
                    0,
                    2,
                    0,
                    None,
                    0,
                    None,
                    false,
                    &mut open_info(),
                )
                .map(|_| ()),
            );
            protected(
                n.write(&h, b"changed", 0, false, false, &mut FileInfo::default())
                    .map(|_| ()),
            );
            protected(n.set_file_size(&h, 0, false, &mut FileInfo::default()));
            protected(n.set_basic_info(&h, 0, 0, 0, 0, 0, &mut FileInfo::default()));
            protected(n.set_extended_attributes(&h, &[], &mut FileInfo::default()));
            protected(n.set_reparse_point(&h, &name("\\sample.txt"), &[]));
            protected(n.delete_reparse_point(&h, &name("\\sample.txt"), &[]));
            protected(n.rename(&h, &name("\\sample.txt"), &name("\\renamed.txt"), false));
            protected(n.set_delete(&h, &name("\\sample.txt"), true));
            protected(n.overwrite(&h, 0, false, 0, None, &mut FileInfo::default()));
            // SAFETY: VolumeInfo contains only integers and an inline u16 array.
            let mut volume_info: winfsp::filesystem::VolumeInfo = unsafe { std::mem::zeroed() };
            protected(n.set_volume_label(&name("Changed"), &mut volume_info));
            n.flush(Some(&h), &mut FileInfo::default()).unwrap();
            assert!(n.flush_for_shutdown().is_err());
            // Windows may request cleanup allocation trimming even for read opens.
            n.cleanup(&h, None, 0x3f);
            n.close(h);
            n.flush_for_shutdown().unwrap();
            let after = n.with(|a| a.path_info("\\sample.txt")).unwrap();
            assert_eq!(before.allocation_size, after.allocation_size);
            assert_eq!(before.size, after.size);
            assert!(n.failure().is_none());
            drop(n);
            assert_eq!(writes.load(Ordering::SeqCst), 0);
            assert_eq!(syncs.load(Ordering::SeqCst), 0);
        }
    }
    fn create(n: &Native<MemoryBackend>, path: &str, dir: bool) -> Context {
        n.create(
            &name(path),
            if dir { 1 } else { 0x40 },
            0x1011f,
            if dir { 0x10 } else { 0x80 },
            None,
            0,
            None,
            false,
            &mut open_info(),
        )
        .unwrap()
    }
    #[test]
    fn symbolic_callback_honors_data_or_attribute_access_without_granting_data_write() {
        for access in [0x110100, 2, 0, 1, 4, 8, 0x10, 0x10000] {
            let n = native();
            let file = n
                .create(
                    &name("\\link"),
                    0x200040,
                    access,
                    0x80,
                    None,
                    0,
                    None,
                    false,
                    &mut open_info(),
                )
                .unwrap();
            let result = n.set_reparse_point(
                &file,
                &name("\\link"),
                &crate::links::symbolic_packet("target").unwrap(),
            );
            if access & 0x102 != 0 {
                result.unwrap_or_else(|e| panic!("allowed access {access:08X}: {e:?}"));
                // Reparse conversion does not turn the link into a writable
                // ordinary file, even when the creating handle had data access.
                assert!(
                    n.write(&file, b"bad", 0, false, false, &mut FileInfo::default())
                        .is_err()
                );
            } else {
                assert!(
                    matches!(result, Err(FspError::NTSTATUS(code)) if code == core::Status::AccessDenied.ntstatus() as i32)
                );
                let mut info = FileInfo::default();
                n.get_file_info(&file, &mut info).unwrap();
                assert_eq!(info.reparse_tag, 0);
                assert_eq!(info.file_size, 0);
            }
            n.cleanup(&file, None, 0);
            n.close(file);
        }
    }
    #[test]
    fn directory_symbolic_callback_preserves_dangling_kind_and_metadata() {
        let n = native();
        let file = n
            .create(
                &name("\\dirlink"),
                0x200001,
                0x110100,
                0x10,
                None,
                0,
                None,
                false,
                &mut open_info(),
            )
            .unwrap();
        let mut before = FileInfo::default();
        n.get_file_info(&file, &mut before).unwrap();
        n.set_reparse_point(
            &file,
            &name("\\dirlink"),
            &crate::links::symbolic_packet("missing-directory").unwrap(),
        )
        .unwrap();
        let mut after = FileInfo::default();
        n.get_file_info(&file, &mut after).unwrap();
        assert_eq!(after.file_attributes & 0x410, 0x410);
        assert_eq!(
            after.reparse_tag,
            crate::links::Node::SymbolicLink.reparse_tag()
        );
        assert_eq!(after.creation_time, before.creation_time);
        assert!(
            n.write(&file, b"bad", 0, false, false, &mut FileInfo::default())
                .is_err()
        );
        n.cleanup(&file, None, 0);
        n.close(file);
    }
    #[test]
    fn symbolic_callback_requires_explicit_reparse_lifetime_and_preserves_target() {
        let n = native();
        let target = create(&n, "\\target", false);
        n.write(
            &target,
            b"target bytes",
            0,
            false,
            false,
            &mut FileInfo::default(),
        )
        .unwrap();
        let file = create(&n, "\\link", false);
        n.set_reparse_point(
            &file,
            &name("\\link"),
            &crate::links::symbolic_packet("target").unwrap(),
        )
        .unwrap();
        let mut packet = [0; 256];
        let length = n
            .get_reparse_point(&file, &name("\\link"), &mut packet)
            .unwrap();
        assert_eq!(
            crate::links::relative_symbolic_target(&packet[..length as usize]).unwrap(),
            "target"
        );
        assert!(n.read(&file, &mut [0; 16], 0).is_err());
        assert!(
            n.write(&file, b"bad", 0, false, false, &mut FileInfo::default())
                .is_err()
        );
        n.cleanup(&file, None, 0);
        n.close(file);
        assert!(n.open(&name("\\link"), 0x40, 1, &mut open_info()).is_err());
        let file = n
            .open(&name("\\link"), 0x200040, 0x10001, &mut open_info())
            .unwrap();
        n.rename(&file, &name("\\link"), &name("\\renamed"), false)
            .unwrap();
        n.set_delete(&file, &name("\\renamed"), true).unwrap();
        n.cleanup(&file, None, 1);
        n.close(file);
        let mut data = [0; 12];
        assert_eq!(n.read(&target, &mut data, 0).unwrap(), 12);
        assert_eq!(&data, b"target bytes");
        n.cleanup(&target, None, 0);
        n.close(target);
    }

    #[test]
    fn existing_link_control_updates_target_without_granting_ordinary_writes() {
        let n = native();
        let file = create(&n, "\\replace-link", false);
        n.set_reparse_point(
            &file,
            &name("\\replace-link"),
            &crate::links::symbolic_packet("old").unwrap(),
        )
        .unwrap();
        n.cleanup(&file, None, 0);
        n.close(file);
        assert!(
            n.open(&name("\\replace-link"), 0x40, 0x100, &mut open_info())
                .is_err()
        );
        let link = n
            .open(&name("\\replace-link"), 0x200040, 0x100, &mut open_info())
            .unwrap();
        n.set_reparse_point(
            &link,
            &name("\\replace-link"),
            &crate::links::symbolic_packet("new").unwrap(),
        )
        .unwrap();
        let mut packet = [0; 256];
        let length = n
            .get_reparse_point(&link, &name("\\replace-link"), &mut packet)
            .unwrap();
        assert_eq!(
            crate::links::relative_symbolic_target(&packet[..length as usize]).unwrap(),
            "new"
        );
        assert!(
            n.write(&link, b"bad", 0, false, false, &mut FileInfo::default())
                .is_err()
        );
        n.cleanup(&link, None, 0);
        n.close(link);
    }
    #[test]
    fn removal_callback_restores_ordinary_type_and_identity() {
        for directory in [false, true] {
            let n = native();
            let file = create(&n, "\\remove-link", directory);
            n.set_reparse_point(
                &file,
                &name("\\remove-link"),
                &crate::links::symbolic_packet("missing").unwrap(),
            )
            .unwrap();
            n.cleanup(&file, None, 0);
            n.close(file);
            let link = n
                .open(&name("\\remove-link"), 0x200000, 0x100, &mut open_info())
                .unwrap();
            let mut before = FileInfo::default();
            n.get_file_info(&link, &mut before).unwrap();
            n.delete_reparse_point(&link, &name("\\remove-link"), &[12, 0, 0, 160, 0, 0, 0, 0])
                .unwrap();
            let mut after = FileInfo::default();
            n.get_file_info(&link, &mut after).unwrap();
            assert_eq!(after.index_number, before.index_number);
            assert_eq!(
                after.file_attributes & 0x410,
                if directory { 0x10 } else { 0 }
            );
            assert_eq!(after.reparse_tag, 0);
            assert_eq!(after.file_size, 0);
            n.cleanup(&link, None, 0);
            n.close(link);
        }
    }
    #[test]
    fn reparse_open_flag_preserves_ordinary_named_stream_deletion() {
        let n = native();
        let base = create(&n, "\\ordinary", false);
        let stream = create(&n, "\\ordinary:note", false);
        n.write(
            &stream,
            b"stream",
            0,
            false,
            false,
            &mut FileInfo::default(),
        )
        .unwrap();
        n.cleanup(&stream, None, 0);
        n.close(stream);
        let stream = n
            .open(
                &name("\\ordinary:note"),
                0x200040,
                0x10001,
                &mut open_info(),
            )
            .unwrap();
        n.set_delete(&stream, &name("\\ordinary:note"), true)
            .unwrap();
        n.cleanup(&stream, None, 1);
        n.close(stream);
        assert!(
            n.open(&name("\\ordinary:note"), 0x40, 1, &mut open_info())
                .is_err()
        );
        assert!(n.get_file_info(&base, &mut FileInfo::default()).is_ok());
        n.cleanup(&base, None, 0);
        n.close(base);
    }
    #[test]
    fn normalized_open_name_preserves_nested_case_and_bounds() {
        let n = native();
        let dir = create(&n, "\\MixedFolder", true);
        let file = create(&n, "\\MixedFolder\\FileName", false);
        n.cleanup(&file, None, 0);
        n.close(file);
        let mut buffer = [0x5555u16; 128];
        let wire = winfsp_sys::FSP_FSCTL_OPEN_FILE_INFO {
            NormalizedName: buffer.as_mut_ptr(),
            NormalizedNameSize: 254,
            ..Default::default()
        };
        // The binding guarantees the same repr(C) layout as this WinFsp struct;
        // the writable backing array stays alive throughout the callback.
        let mut info: OpenFileInfo = unsafe { std::mem::transmute(wire) };
        let opened = n
            .open(&name("\\mixedfolder\\filename"), 0x40, 1, &mut info)
            .unwrap();
        let size = usize::from(info.normalized_name_size()) / 2;
        assert_eq!(
            String::from_utf16(&buffer[..size]).unwrap(),
            "\\MixedFolder\\FileName"
        );
        assert_eq!(buffer[size], 0x5555);
        n.cleanup(&opened, None, 0);
        n.close(opened);
        normalized_name(&mut info, "\\different", "\\MixedFolder\\FileName");
        assert_eq!(buffer[size], 0x5555);
        let wire = winfsp_sys::FSP_FSCTL_OPEN_FILE_INFO {
            NormalizedName: buffer.as_mut_ptr(),
            NormalizedNameSize: 2,
            ..Default::default()
        };
        let mut tiny: OpenFileInfo = unsafe { std::mem::transmute(wire) };
        let before = buffer;
        normalized_name(&mut tiny, "\\filename", "\\FileName");
        assert_eq!(buffer, before);
        assert_eq!(tiny.normalized_name_size(), 2);
        n.cleanup(&dir, None, 0);
        n.close(dir);
        n.flush_for_shutdown().unwrap();
    }
    #[test]
    fn last_cleanup_releases_only_unused_fork_allocation() {
        let n = native();
        let file = create(&n, "\\Reserved", false);
        let mut info = FileInfo::default();
        n.set_file_size(&file, 65536, true, &mut info).unwrap();
        let bytes = vec![0x79; 5001];
        n.write(&file, &bytes, 0, false, false, &mut info).unwrap();
        let readonly = n
            .open(&name("\\Reserved"), 0x40, 1, &mut open_info())
            .unwrap();
        n.cleanup(&file, None, 2);
        n.get_file_info(&readonly, &mut info).unwrap();
        assert_eq!(info.allocation_size, 65536);
        n.close(file);
        let before = info.clone();
        n.cleanup(&readonly, None, 2);
        n.get_file_info(&readonly, &mut info).unwrap();
        assert_eq!(info.file_size, 5001);
        assert_eq!(info.allocation_size, 8192);
        assert_eq!(info.last_write_time, before.last_write_time);
        assert_eq!(info.change_time, before.change_time);
        let mut actual = vec![0; bytes.len()];
        n.read(&readonly, &mut actual, 0).unwrap();
        assert_eq!(actual, bytes);
        n.close(readonly);
        let resource = create(&n, "\\Reserved:AFP_Resource", false);
        n.set_file_size(&resource, 32768, true, &mut info).unwrap();
        n.write(&resource, b"resource", 0, false, false, &mut info)
            .unwrap();
        n.cleanup(&resource, None, 2);
        n.get_file_info(&resource, &mut info).unwrap();
        assert_eq!(info.allocation_size, 4096);
        assert_eq!(info.file_size, 8);
        n.close(resource);
        n.flush_for_shutdown().unwrap();
        let state = Arc::try_unwrap(n.state).ok().unwrap().into_inner().unwrap();
        let mut reopened = core::Adapter::from_device(state.adapter.shutdown().unwrap()).unwrap();
        assert_eq!(
            reopened.path_info("\\Reserved").unwrap().allocation_size,
            8192
        );
        assert_eq!(
            reopened.path_info("\\Reserved:AFP_Resource").unwrap().size,
            8
        );
    }
    #[test]
    fn native_ea_callbacks_pack_wire_records_sizes_and_specific_access() {
        let n = native();
        let file = create(&n, "\\attributes.bin", false);
        let packet = crate::ea::encode(
            &crate::ea::records(&[
                ("com.example.CASE".into(), b"UPPER\0\xff".to_vec()),
                ("com.example.case".into(), vec![]),
                ("com.example.large".into(), vec![0x39; 8003]),
            ])
            .unwrap(),
        )
        .unwrap();
        let mut info = FileInfo::default();
        n.set_extended_attributes(&file, &packet, &mut info)
            .unwrap();
        assert_eq!(info.ea_size, packet.len() as u32);
        let mut buffer = vec![0u8; 65536];
        let used = n.get_extended_attributes(&file, &mut buffer).unwrap() as usize;
        assert_eq!(crate::ea::changes(&buffer[..used], &[]).unwrap().len(), 3);
        let mut tiny = [0; 8];
        assert_eq!(
            n.get_extended_attributes(&file, &mut tiny)
                .unwrap_err()
                .to_ntstatus(),
            0xc0000023u32 as i32
        );
        let read = n
            .open(&name("\\attributes.bin"), 0x40, 9, &mut open_info())
            .unwrap();
        assert_eq!(
            n.set_extended_attributes(&read, &packet, &mut info)
                .unwrap_err()
                .to_ntstatus(),
            0xc0000022u32 as i32
        );
        n.cleanup(&read, None, 0);
        n.close(read);
        n.cleanup(&file, None, 0);
        n.close(file);
        assert!(n.failure().is_none());
    }
    #[test]
    fn native_constructor_eas_validate_before_creation_and_overwrite() {
        let n = native();
        let values = [("com.example.created".into(), b"first".to_vec())];
        let packet = crate::ea::encode(&crate::ea::records(&values).unwrap()).unwrap();
        let file = n
            .create(
                &name("\\initial.bin"),
                0x40,
                9,
                0x80,
                None,
                0,
                Some(&packet),
                false,
                &mut open_info(),
            )
            .unwrap();
        let mut buffer = vec![0; 65536];
        let used = n.get_extended_attributes(&file, &mut buffer).unwrap() as usize;
        assert_eq!(
            crate::ea::changes(&buffer[..used], &[]).unwrap()[0]
                .value
                .as_deref(),
            Some(b"first".as_slice())
        );
        assert_eq!(
            n.set_extended_attributes(&file, &packet, &mut FileInfo::default())
                .unwrap_err()
                .to_ntstatus(),
            0xc0000022u32 as i32
        );
        n.cleanup(&file, None, 0);
        n.close(file);
        let mut invalid = packet.clone();
        invalid[4] = 0x80;
        assert!(
            n.create(
                &name("\\invalid.bin"),
                0x40,
                9,
                0x80,
                None,
                0,
                Some(&invalid),
                false,
                &mut open_info()
            )
            .is_err()
        );
        assert!(
            n.open(&name("\\invalid.bin"), 0x40, 9, &mut open_info())
                .is_err()
        );
        let writable = n
            .open(&name("\\initial.bin"), 0x40, 0x1010b, &mut open_info())
            .unwrap();
        n.write(
            &writable,
            b"old content",
            0,
            false,
            false,
            &mut FileInfo::default(),
        )
        .unwrap();
        assert!(
            n.overwrite(
                &writable,
                0x80,
                true,
                0,
                Some(&invalid),
                &mut FileInfo::default()
            )
            .is_err()
        );
        let mut old = [0; 11];
        n.read(&writable, &mut old, 0).unwrap();
        assert_eq!(&old, b"old content");
        let replacement = crate::ea::encode(
            &crate::ea::records(&[("com.example.created".into(), b"second".to_vec())]).unwrap(),
        )
        .unwrap();
        let mut info = FileInfo::default();
        n.overwrite(&writable, 0x80, true, 4096, Some(&replacement), &mut info)
            .unwrap();
        assert_eq!(info.file_size, 0);
        assert_eq!(info.allocation_size, 4096);
        let used = n.get_extended_attributes(&writable, &mut buffer).unwrap() as usize;
        assert_eq!(
            crate::ea::changes(&buffer[..used], &[]).unwrap()[0]
                .value
                .as_deref(),
            Some(b"second".as_slice())
        );
        n.cleanup(&writable, None, 0);
        n.close(writable);
        assert!(n.failure().is_none());
    }
    #[test]
    fn finder_stream_open_responses_and_paging_reads_follow_kernel_protocol() {
        let n = native();
        let main = create(&n, "\\finder.bin", false);
        let finder = create(&n, "\\finder.bin:AFP_AfpInfo", false);
        let mut bytes = crate::afp::encode(&[0; 32], 0).unwrap();
        bytes[16..24].copy_from_slice(b"TEXTttxt");
        bytes[24] = 0x40;
        n.write(&finder, &bytes, 0, false, false, &mut FileInfo::default())
            .unwrap();
        n.cleanup(&finder, None, 0);
        n.close(finder);
        let mut info = open_info();
        let writeonly = n
            .open(&name("\\finder.bin:AFP_AfpInfo"), 0x40, 2, &mut info)
            .unwrap();
        assert_eq!(info.as_mut().file_attributes, 0x80);
        let mut readback = [0; 60];
        assert_eq!(n.read(&writeonly, &mut readback, 0).unwrap(), 60);
        assert_eq!(readback, bytes);
        assert_eq!(
            n.with(|a| a.read(writeonly.handle, 0, &mut readback))
                .unwrap_err()
                .to_ntstatus(),
            0xc0000022u32 as i32
        );
        n.cleanup(&writeonly, None, 0);
        n.close(writeonly);
        n.cleanup(&main, None, 0);
        n.close(main);
        assert!(n.failure().is_none());
    }
    #[test]
    fn owner_security_is_bounded_and_has_no_public_grants() {
        let security = OwnerSecurity::current_user().unwrap();
        let text = security.sddl().unwrap();
        assert!(text.contains("(A;OICI;FA;;;SY)"));
        assert_eq!(text.matches("(A;").count(), 2);
        assert!(!text.contains(";;;WD)"));
        assert!(!text.contains(";;;BA)"));
        let length = security.copy_to(None).unwrap() as usize;
        let mut bytes = vec![0u8; length];
        let output = unsafe {
            std::slice::from_raw_parts_mut(bytes.as_mut_ptr().cast::<c_void>(), bytes.len())
        };
        assert_eq!(security.copy_to(Some(output)).unwrap(), length as u64);
        assert_eq!(bytes, security.descriptor);
        let mut short = [0u8; 1];
        let output =
            unsafe { std::slice::from_raw_parts_mut(short.as_mut_ptr().cast::<c_void>(), 1) };
        assert_eq!(
            security.copy_to(Some(output)).unwrap_err().to_ntstatus(),
            0xc0000023u32 as i32
        );
    }
    #[test]
    fn custom_security_is_persistent_and_cannot_be_replaced_through_eas() {
        let n = native();
        let mut custom = n.security.descriptor.clone();
        let dacl = u32::from_le_bytes(custom[16..20].try_into().unwrap()) as usize;
        // Restrict the first grant to read access; creation's already granted
        // rights still let the creator finish the new file.
        custom[dacl + 12..dacl + 16].copy_from_slice(&0x120089u32.to_le_bytes());
        crate::security_descriptor::validate(&custom).unwrap();
        let security =
            unsafe { std::slice::from_raw_parts(custom.as_ptr().cast::<c_void>(), custom.len()) };
        let file = n
            .create(
                &name("\\Secured"),
                0x40,
                0x1011f,
                0x80,
                Some(security),
                0,
                None,
                false,
                &mut open_info(),
            )
            .unwrap();
        n.write(
            &file,
            b"protected payload",
            0,
            false,
            false,
            &mut FileInfo::default(),
        )
        .unwrap();
        let mut result = vec![0u8; n.get_security(&file, None).unwrap() as usize];
        let out = unsafe {
            std::slice::from_raw_parts_mut(result.as_mut_ptr().cast::<c_void>(), result.len())
        };
        n.get_security(&file, Some(out)).unwrap();
        assert_eq!(result, custom);
        assert!(
            n.with(|a| a.extended_attributes(file.handle))
                .unwrap()
                .is_empty()
        );
        let forged = crate::ea::encode(
            &crate::ea::records(&[(
                crate::security_descriptor::ATTRIBUTE.into(),
                crate::security_descriptor::encode(&n.security.descriptor).unwrap(),
            )])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            n.set_extended_attributes(&file, &forged, &mut FileInfo::default())
                .unwrap_err()
                .to_ntstatus(),
            core::Status::AccessDenied.ntstatus() as i32
        );
        assert!(
            n.overwrite(
                &file,
                0x80,
                true,
                0,
                Some(&forged),
                &mut FileInfo::default()
            )
            .is_err()
        );
        let mut payload = [0; 17];
        n.read(&file, &mut payload, 0).unwrap();
        assert_eq!(&payload, b"protected payload");
        assert_eq!(
            n.with(|a| a.native_security(file.handle)).unwrap().unwrap(),
            custom
        );
        n.cleanup(&file, None, 0);
        n.close(file);
        n.flush_for_shutdown().unwrap();
        let state = Arc::try_unwrap(n.state).ok().unwrap().into_inner().unwrap();
        let disk = state.adapter.shutdown().unwrap();
        let n = Native::new(core::Adapter::from_device(disk).unwrap()).unwrap();
        assert_eq!(
            n.with(|a| a.native_security_by_path("\\Secured"))
                .unwrap()
                .unwrap(),
            custom
        );
        n.flush_for_shutdown().unwrap();
    }
    #[test]
    fn resource_callbacks_enumerate_and_edit_only_the_selected_fork() {
        let n = native();
        let data = create(&n, "\\forks.bin", false);
        let mut info = FileInfo::default();
        n.write(&data, b"main data", 0, false, false, &mut info)
            .unwrap();
        let resource = create(&n, "\\forks.bin:AFP_Resource:$DATA", false);
        n.write(&resource, b"resource\0\xff", 4094, false, false, &mut info)
            .unwrap();
        assert_eq!(info.file_size, 4104);
        let mut buffer = vec![0; 512];
        let used = n.get_stream_info(&data, &mut buffer).unwrap() as usize;
        assert_eq!(u16::from_le_bytes(buffer[..2].try_into().unwrap()), 24);
        assert_eq!(u16::from_le_bytes(buffer[24..26].try_into().unwrap()), 48);
        let raw_name = "AFP_Resource"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert!(
            buffer[..used]
                .windows(raw_name.len())
                .any(|v| v == raw_name)
        );
        let mut main = [0; 9];
        assert_eq!(n.read(&data, &mut main, 0).unwrap(), 9);
        assert_eq!(&main, b"main data");
        let mut tail = [0; 10];
        assert_eq!(n.read(&resource, &mut tail, 4094).unwrap(), 10);
        assert_eq!(&tail, b"resource\0\xff");
        n.set_delete(&resource, &name("\\forks.bin:AFP_Resource"), true)
            .unwrap();
        n.set_file_size(&resource, 0, false, &mut info).unwrap();
        n.write(&resource, b"again", 0, false, false, &mut info)
            .unwrap();
        let old = n
            .open(&name("\\forks.bin:AFP_Resource"), 0x40, 3, &mut open_info())
            .unwrap();
        n.cleanup(&resource, None, 0);
        n.close(resource);
        // The last cleanup may use a descriptor without DELETE access after
        // another descriptor's disposition was accepted by the kernel.
        n.cleanup(&old, None, 1);
        let fresh = create(&n, "\\forks.bin:AFP_Resource", false);
        n.write(&fresh, b"fresh", 0, false, false, &mut info)
            .unwrap();
        n.write(&old, b"OLDER", 0, false, false, &mut info).unwrap();
        let mut current = [0; 5];
        n.read(&fresh, &mut current, 0).unwrap();
        assert_eq!(&current, b"fresh");
        n.close(old);
        n.cleanup(&fresh, None, 0);
        n.close(fresh);
        n.cleanup(&data, None, 0);
        n.close(data);
        n.flush_for_shutdown().unwrap();
    }
    #[test]
    fn grants_kinds_and_lossless_utf16_are_checked() {
        let a = request(0x40, 4).unwrap();
        assert!(a.access.append);
        assert!(!a.access.write);
        assert!(!a.access.read);
        assert_eq!(a.kind, Some(core::Kind::File));
        assert!(request(0x41, 1).is_err());
        let invalid = [0xd800u16, 0];
        assert!(path(U16CStr::from_slice(&invalid).unwrap()).is_err());
    }
    #[test]
    fn inherited_acl_matching_refuses_other_grants_and_inherit_only_aces() {
        let expected = creation_acl(
            "O:S-1-5-21-100G:S-1-5-21-100D:P(A;OICI;FA;;;S-1-5-21-100)(A;OICI;FA;;;SY)",
        )
        .unwrap();
        assert_eq!(
            Some(expected.clone()),
            creation_acl("O:S-1-5-21-100D:AI(A;ID;FA;;;SY)(A;ID;FA;;;S-1-5-21-100)")
        );
        for other in [
            "O:S-1-5-21-101D:(A;;FA;;;S-1-5-21-100)(A;;FA;;;SY)",
            "O:S-1-5-21-100D:(A;;FA;;;WD)(A;;FA;;;SY)",
            "O:S-1-5-21-100D:(A;;FA;;;S-1-5-21-100)(A;;FA;;;SY)(A;;FA;;;WD)",
            "O:S-1-5-21-100D:(A;IO;FA;;;S-1-5-21-100)(A;;FA;;;SY)",
            "O:S-1-5-21-100D:(A;;FR;;;S-1-5-21-100)(A;;FA;;;SY)",
            "O:S-1-5-21-100D:(D;;FA;;;S-1-5-21-100)(A;;FA;;;SY)",
        ] {
            assert_ne!(Some(expected.clone()), creation_acl(other));
        }
    }
    #[test]
    fn creation_accepts_only_the_tokens_default_owner_with_identical_grants() {
        let expected = "O:S-1-5-21-100D:P(A;OICI;FA;;;S-1-5-21-100)(A;OICI;FA;;;SY)";
        let elevated = "O:BAD:(A;OICI;FA;;;S-1-5-21-100)(A;OICI;FA;;;SY)";
        assert!(creation_matches(expected, expected, "S-1-5-32-544"));
        assert!(creation_matches(elevated, expected, "S-1-5-32-544"));
        assert!(!creation_matches(elevated, expected, "S-1-5-21-100"));
        for refused in [
            "O:S-1-5-21-101D:(A;;FA;;;S-1-5-21-100)(A;;FA;;;SY)",
            "O:BAD:(A;;FA;;;BA)(A;;FA;;;SY)",
            "O:BAD:(A;;FA;;;S-1-5-21-100)(A;;FA;;;SY)(A;;FA;;;BA)",
            "O:BAD:(A;IO;FA;;;S-1-5-21-100)(A;;FA;;;SY)",
            "O:BAD:(A;;FR;;;S-1-5-21-100)(A;;FA;;;SY)",
            "O:BAD:(D;;FA;;;S-1-5-21-100)(A;;FA;;;SY)",
            "O:BAD:",
        ] {
            assert!(!creation_matches(refused, expected, "S-1-5-32-544"));
        }
    }
    #[test]
    fn single_directory_lookup_tracks_names_dates_and_deletion() {
        let n = native();
        let dir = create(&n, "\\Folder", true);
        let file = create(&n, "\\Folder\\Stored.txt", false);
        let mut info = FileInfo::default();
        n.write(&file, b"current", 0, false, false, &mut info)
            .unwrap();
        let mut entry = DirInfo::new();
        n.get_dir_info_by_name(&dir, &name("stored.TXT"), &mut entry)
            .unwrap();
        assert_eq!(entry.file_info_mut().index_number, info.index_number);
        assert_eq!(entry.file_info_mut().file_size, 7);
        n.get_dir_info_by_name(&dir, &name("."), &mut entry)
            .unwrap();
        assert_eq!(entry.file_info_mut().file_attributes & 0x10, 0x10);
        n.get_dir_info_by_name(&dir, &name(".."), &mut entry)
            .unwrap();
        assert_eq!(entry.file_info_mut().index_number, 2);
        for refused in ["missing", "Stored.txt:stream", "..\\Stored.txt", "*"] {
            assert!(
                n.get_dir_info_by_name(&dir, &name(refused), &mut entry)
                    .is_err()
            );
        }
        assert!(
            n.get_dir_info_by_name(&file, &name("child"), &mut entry)
                .is_err()
        );
        let no_list = n
            .open(&name("\\Folder"), 1, 0x80, &mut open_info())
            .unwrap();
        assert_eq!(
            n.get_dir_info_by_name(&no_list, &name("Stored.txt"), &mut entry)
                .unwrap_err()
                .to_ntstatus(),
            core::Status::AccessDenied.ntstatus() as i32
        );
        n.close(no_list);
        n.rename(
            &file,
            &name("\\Folder\\Stored.txt"),
            &name("\\Folder\\New.txt"),
            false,
        )
        .unwrap();
        assert!(
            n.get_dir_info_by_name(&dir, &name("Stored.txt"), &mut entry)
                .is_err()
        );
        n.get_dir_info_by_name(&dir, &name("NEW.TXT"), &mut entry)
            .unwrap();
        n.cleanup(&file, None, 1);
        assert!(
            n.get_dir_info_by_name(&dir, &name("New.txt"), &mut entry)
                .is_err()
        );
        n.close(file);
        n.cleanup(&dir, None, 0);
        n.close(dir);
        assert!(n.failure().is_none());
        n.flush_for_shutdown().unwrap();
    }
    #[test]
    fn callbacks_preserve_live_identity_and_durable_deletion() {
        let n = native();
        let root = n
            .with(|a| a.open("\\", core::OpenRequest::default()))
            .unwrap();
        let baseline = n
            .with(|a| a.read_directory(root))
            .unwrap()
            .into_iter()
            .map(|e| (e.name, e.info.cnid))
            .collect::<Vec<_>>();
        n.with(|a| a.close(root)).unwrap();
        let directory = create(&n, "\\Folder", true);
        let file = create(&n, "\\Folder\\file.txt", false);
        let mut info = FileInfo::default();
        assert_eq!(
            n.write(&file, b"original", 0, false, false, &mut info)
                .unwrap(),
            8
        );
        let cnid = info.index_number;
        n.rename(
            &file,
            &name("\\Folder\\file.txt"),
            &name("\\Folder\\renamed.txt"),
            false,
        )
        .unwrap();
        n.set_file_size(&file, 12, false, &mut info).unwrap();
        let mut bytes = [0xff; 12];
        assert_eq!(n.read(&file, &mut bytes, 0).unwrap(), 12);
        assert_eq!(&bytes, b"original\0\0\0\0");
        assert_eq!(info.index_number, cnid);
        n.set_delete(&file, &name("\\Folder\\renamed.txt"), true)
            .unwrap();
        n.cleanup(&file, None, 1);
        assert_eq!(
            n.write(&file, b"post", 8, false, false, &mut info).unwrap(),
            4
        );
        assert!(n.with(|a| a.path_info("\\Folder\\renamed.txt")).is_err());
        assert_eq!(
            n.flush_for_shutdown().unwrap_err().to_ntstatus(),
            core::Status::Busy.ntstatus() as i32
        );
        n.close(file);
        assert!(
            n.with(|a| a.read_directory(directory.handle))
                .unwrap()
                .is_empty()
        );
        n.set_delete(&directory, &name("\\Folder"), true).unwrap();
        n.cleanup(&directory, None, 1);
        n.close(directory);
        n.flush_for_shutdown().unwrap();
        let state = Arc::try_unwrap(n.state).ok().unwrap().into_inner().unwrap();
        let disk = state.adapter.shutdown().unwrap();
        let mut reopened = core::Adapter::from_device(disk).unwrap();
        let root = reopened.open("\\", core::OpenRequest::default()).unwrap();
        assert_eq!(
            reopened
                .read_directory(root)
                .unwrap()
                .into_iter()
                .map(|e| (e.name, e.info.cnid))
                .collect::<Vec<_>>(),
            baseline
        );
        reopened.close(root).unwrap();
    }
    #[test]
    fn unsupported_requests_do_not_truncate_or_create() {
        let n = native();
        let file = create(&n, "\\keep.txt", false);
        let mut info = FileInfo::default();
        n.write(&file, b"keep", 0, false, false, &mut info).unwrap();
        assert!(n.overwrite(&file, 0x800, true, 0, None, &mut info).is_err());
        assert!(
            n.overwrite(&file, 0x80, true, 4097, None, &mut info)
                .is_err()
        );
        assert!(n.set_file_size(&file, 8193, true, &mut info).is_err());
        assert!(
            n.set_basic_info(&file, 0x800, 0, 0, 0, 0, &mut info)
                .is_err()
        );
        let mut bytes = [0; 4];
        assert_eq!(n.read(&file, &mut bytes, 0).unwrap(), 4);
        assert_eq!(&bytes, b"keep");
        assert!(
            n.create(
                &name("\\missing.txt"),
                0x40,
                3,
                0x80,
                None,
                4097,
                None,
                false,
                &mut open_info()
            )
            .is_err()
        );
        assert!(n.with(|a| a.path_info("\\missing.txt")).is_err());
        n.cleanup(&file, None, 0);
        n.close(file);
        n.flush_for_shutdown().unwrap();
    }
    #[test]
    fn windows_attribute_hints_persist_without_creating_mac_folder_locks() {
        let n = native();
        let dir = create(&n, "\\Hints", true);
        let mut info = FileInfo::default();
        n.set_basic_info(&dir, 0x11, 0, 0, 0, 0, &mut info).unwrap();
        assert_eq!(info.file_attributes & 0x11, 0x11);
        let file = n
            .create(
                &name("\\Hints\\temp"),
                0x40,
                0x1011f,
                0x104,
                None,
                0,
                None,
                false,
                &mut open_info(),
            )
            .unwrap();
        n.write(&file, b"persistent bytes", 0, false, false, &mut info)
            .unwrap();
        assert_eq!(info.file_attributes & 0x104, 0x104);
        n.rename(
            &file,
            &name("\\Hints\\temp"),
            &name("\\Hints\\renamed"),
            false,
        )
        .unwrap();
        n.cleanup(&file, None, 0);
        n.close(file);
        n.cleanup(&dir, None, 0);
        n.close(dir);
        n.flush_for_shutdown().unwrap();
        let state = Arc::try_unwrap(n.state).ok().unwrap().into_inner().unwrap();
        let mut disk = state.adapter.shutdown().unwrap();
        let fs = crate::engine::open_checked(&mut disk).unwrap();
        let body = fs.catalog_record("/Hints").unwrap();
        assert_eq!(crate::volume::be16(&body, 56) & 0x1000, 0);
        assert_eq!((body[40] | body[41]) & 6, 0);
        let n = Native::new(core::Adapter::from_device(disk).unwrap()).unwrap();
        let file = n
            .open(&name("\\Hints\\renamed"), 0x40, 0x1011f, &mut open_info())
            .unwrap();
        n.get_file_info(&file, &mut info).unwrap();
        assert_eq!(info.file_attributes & 0x104, 0x104);
        let mut bytes = [0; 16];
        n.read(&file, &mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"persistent bytes");
        n.set_basic_info(&file, 0x80, 0, 0, 0, 0, &mut info)
            .unwrap();
        assert_eq!(info.file_attributes & 0x104, 0);
        n.set_basic_info(&file, 0x104, 0, 0, 0, 0, &mut info)
            .unwrap();
        n.cleanup(&file, None, 0);
        n.close(file);
        n.flush_for_shutdown().unwrap();
        let state = Arc::try_unwrap(n.state).ok().unwrap().into_inner().unwrap();
        let disk = state.adapter.shutdown().unwrap();
        if let Some(directory) = std::env::var_os("HFS_CRASH_ARTIFACT_DIR") {
            use std::io::Write;
            let output = std::path::Path::new(&directory).join("windows-attribute-hints.img");
            let mut file = crate::image::create_output(&output).unwrap();
            file.write_all(disk.as_slice()).unwrap();
            file.sync_all().unwrap();
        }
    }
    #[test]
    fn windows_folder_hint_never_clears_an_existing_native_mac_lock() {
        load_runtime().unwrap();
        let mut disk = MemoryBackend::new(32 * 1024 * 1024);
        HfsPlus::format(
            &mut disk,
            &FormatOpts {
                journaled: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut adapter = core::Adapter::from_device(disk).unwrap();
        // Generic adapter metadata retains native Mac lock semantics.
        let h = adapter
            .create_initialized(
                "\\Locked",
                core::Kind::Directory,
                core::OpenRequest::default(),
                Some(0x11),
                0,
            )
            .unwrap();
        adapter.close(h).unwrap();
        let n = Native::new(adapter).unwrap();
        let dir = n
            .open(&name("\\Locked"), 1, 0x100, &mut open_info())
            .unwrap();
        n.set_basic_info(&dir, 0x10, 0, 0, 0, 0, &mut FileInfo::default())
            .unwrap();
        assert!(
            n.create(
                &name("\\Locked\\child"),
                0x40,
                3,
                0x80,
                None,
                0,
                None,
                false,
                &mut open_info()
            )
            .is_err()
        );
        n.cleanup(&dir, None, 0);
        n.close(dir);
        assert!(n.failure().is_none());
        n.flush_for_shutdown().unwrap();
    }
    #[test]
    fn delete_on_close_keeps_nonempty_directory_without_failing_volume() {
        let n = native();
        let dir = create(&n, "\\Folder", true);
        let child = create(&n, "\\Folder\\child", false);
        assert_eq!(
            n.set_delete(&dir, &name("\\Folder"), true)
                .unwrap_err()
                .to_ntstatus(),
            core::Status::DirectoryNotEmpty.ntstatus() as i32
        );
        n.cleanup(&dir, None, 1);
        n.close(dir);
        assert!(n.failure().is_none());
        n.get_file_info(&child, &mut FileInfo::default()).unwrap();
        n.with(|a| a.path_info("\\Folder\\child")).unwrap();
        let dir = n
            .open(&name("\\Folder"), 1, 0x1011f, &mut open_info())
            .unwrap();
        n.cleanup(&child, None, 1);
        n.close(child);
        n.set_delete(&dir, &name("\\Folder"), true).unwrap();
        n.cleanup(&dir, None, 1);
        n.close(dir);
        assert!(n.with(|a| a.path_info("\\Folder")).is_err());
        assert!(n.failure().is_none());
        n.flush_for_shutdown().unwrap();
    }
    #[test]
    fn void_callback_failure_poisoning_prevents_later_success() {
        let n = native();
        let file = create(&n, "\\file", false);
        n.cleanup(&file, None, 0);
        n.cleanup(&file, None, 0); // unexpected duplicate cleanup remains fatal
        assert!(n.failure().is_some());
        assert_eq!(
            n.flush_for_shutdown().unwrap_err().to_ntstatus(),
            core::Status::FailedVolume.ntstatus() as i32
        );
        assert!(n.get_file_info(&file, &mut FileInfo::default()).is_err());
        n.close(file);
    }
    #[test]
    fn shutdown_gate_refuses_late_opens_without_dropping_live_mount() {
        let n = native();
        let file = create(&n, "\\open", false);
        assert!(n.flush_for_shutdown().is_err());
        assert!(!n.state.lock().unwrap().stopping);
        n.cleanup(&file, None, 0);
        n.close(file);
        {
            let mut state = n.state.lock().unwrap();
            state.adapter.flush_for_shutdown().unwrap();
            state.stopping = true;
        }
        assert_eq!(
            n.open(&name("\\open"), 0, 1, &mut open_info())
                .err()
                .unwrap()
                .to_ntstatus(),
            core::Status::Busy.ntstatus() as i32
        );
    }
}
