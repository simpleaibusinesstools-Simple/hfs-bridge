//! Windows-only attribute hints use a versioned HFS xattr, never Finder/BSD bits.
use super::*;
pub(super) const NAME: &str = "org.hfsbridge.windows.attributes";
const MAGIC: &[u8; 8] = b"HFSWA001";
const EXTRA: u32 = 0x104; // SYSTEM and TEMPORARY

fn encode(bits: u32) -> Option<Vec<u8>> {
    (bits != 0).then(|| {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&bits.to_be_bytes());
        bytes
    })
}
fn validate(kind: Kind, bytes: &[u8]) -> Result<u32> {
    if bytes.len() != 12 || &bytes[..8] != MAGIC {
        return Err(error(
            Status::Unsupported,
            "unrecognized HFS Bridge Windows attribute record",
        ));
    }
    let bits = volume::be32(bytes, 8);
    if bits & !(EXTRA | 1) != 0
        || (kind == Kind::Directory && bits & 0x100 != 0)
        || (kind == Kind::File && bits & 1 != 0)
    {
        return Err(error(
            Status::Unsupported,
            "Windows attribute record has incompatible flags",
        ));
    }
    Ok(bits)
}
impl<D: BlockDevice> Adapter<D> {
    #[cfg(feature = "native-mount")]
    pub(crate) fn use_windows_directory_hints(&mut self) {
        self.windows_directory_hints = true;
    }
    pub(super) fn windows_flags(&mut self, cnid: u32) -> Result<u32> {
        // HFS catalog HasAttributes is maintained with the attribute tree in
        // the same transaction. Ordinary entries need no attribute-tree scan.
        if volume::be16(&self.body(cnid)?, 2) & 4 == 0 {
            return Ok(0);
        }
        let Some(bytes) = self.read_attribute(cnid, NAME)? else {
            return Ok(0);
        };
        validate(self.record_kind(cnid)?, &bytes)
    }
    fn record_kind(&self, cnid: u32) -> Result<Kind> {
        Ok(if volume::be16(&self.body(cnid)?, 0) == 1 {
            Kind::Directory
        } else {
            Kind::File
        })
    }
    pub(super) fn validate_windows_attribute_changes(
        &self,
        kind: Kind,
        changes: &[crate::ea::Change],
    ) -> Result<()> {
        for change in changes.iter().filter(|c| c.name == NAME) {
            if let Some(bytes) = &change.value {
                validate(kind, bytes)?;
            }
        }
        Ok(())
    }
    fn extra_flags(&self, kind: Kind, attributes: u32) -> u32 {
        (attributes & EXTRA)
            | if kind == Kind::Directory && self.windows_directory_hints {
                attributes & 1
            } else {
                0
            }
    }
    pub(super) fn creation_windows_attributes(
        &self,
        kind: Kind,
        attributes: Option<u32>,
        initial: &[crate::ea::Change],
    ) -> Result<Vec<crate::ea::Change>> {
        self.validate_windows_attribute_changes(kind, initial)?;
        let mut changes = initial.to_vec();
        let bits = self.extra_flags(kind, attributes.unwrap_or(0));
        if bits != 0 {
            let value = encode(bits);
            if let Some(prior) = changes.iter().find(|c| c.name == NAME) {
                if prior.value != value {
                    return Err(error(
                        Status::InvalidParameter,
                        "conflicting Windows attribute metadata",
                    ));
                }
            } else {
                changes.push(crate::ea::Change {
                    name: NAME.into(),
                    value,
                });
            }
        }
        Ok(changes)
    }
    pub(super) fn replacement_windows_attributes(
        &mut self,
        cnid: u32,
        attributes: u32,
        initial: &[crate::ea::Change],
    ) -> Result<Vec<crate::ea::Change>> {
        let kind = self.record_kind(cnid)?;
        if !initial.iter().any(|c| c.name == NAME)
            && self.windows_flags(cnid)? == self.extra_flags(kind, attributes)
        {
            return Ok(initial.to_vec());
        }
        let mut changes = self.creation_windows_attributes(kind, Some(attributes), initial)?;
        let wanted = encode(self.extra_flags(kind, attributes));
        if wanted.is_none()
            && !changes.iter().any(|c| c.name == NAME)
            && self.windows_flags(cnid)? != 0
        {
            changes.push(crate::ea::Change {
                name: NAME.into(),
                value: None,
            });
        }
        Ok(changes)
    }
    pub(super) fn namespace_locked(&mut self, cnid: u32) -> Result<bool> {
        let info = self.info(cnid)?;
        if info.kind != Kind::Directory || !self.windows_directory_hints {
            return Ok(info.attributes & 1 != 0);
        }
        let body = self.body(cnid)?;
        // The Windows read-only folder hint is not a Mac lock. Native lock
        // bits remain authoritative and cannot be cleared by changing this hint.
        Ok((body[40] | body[41]) & 6 != 0 || volume::be16(&body, 56) & 0x1000 != 0)
    }
    pub(super) fn native_windows_attributes(
        &self,
        cnid: u32,
        attributes: Option<u32>,
    ) -> fstool::Result<Option<u32>> {
        let mut native = attributes;
        if let Some(attributes) = attributes {
            let body = self.fs.catalog_record_cnid(cnid)?;
            let kind = if volume::be16(&body, 0) == 1 {
                Kind::Directory
            } else {
                Kind::File
            };
            let mut attrs = attributes & !EXTRA;
            if kind == Kind::Directory && self.windows_directory_hints {
                attrs = (attrs & !1)
                    | u32::from(
                        volume::be16(&body, 56) & 0x1000 != 0 || (body[40] | body[41]) & 6 != 0,
                    );
            }
            native = Some(attrs);
        }
        Ok(native)
    }
}
