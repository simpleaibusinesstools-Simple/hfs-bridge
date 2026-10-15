//! Native security records are never part of ordinary EA/archive editing.
use super::*;
use crate::security_descriptor as sd;
#[cfg(all(test, feature = "native-mount"))]
#[path = "security_tests.rs"]
mod tests;
impl<D: BlockDevice> Adapter<D> {
    pub(super) fn reject_private_changes(changes: &[crate::ea::Change]) -> Result<()> {
        if changes.iter().any(|c| c.name == sd::ATTRIBUTE) {
            return Err(error(
                Status::AccessDenied,
                "Windows permissions require the security API",
            ));
        }
        if changes
            .iter()
            .any(|c| crate::timestamps::is_private_attribute(&c.name))
        {
            return Err(error(
                Status::AccessDenied,
                "private timestamp records cannot be imported",
            ));
        }
        if changes
            .iter()
            .any(|c| c.name == crate::named_streams::ATTRIBUTE)
        {
            return Err(error(
                Status::AccessDenied,
                "private named-stream storage cannot be imported through metadata APIs",
            ));
        }
        Ok(())
    }
    #[cfg(feature = "native-mount")]
    fn native_security_cnid(&mut self, cnid: u32) -> Result<Option<Vec<u8>>> {
        self.healthy()?;
        let cnid = self.metadata_cnid(cnid)?;
        if volume::be16(&self.body(cnid)?, 2) & 4 == 0 {
            return Ok(None);
        }
        let value = self.read_attribute(cnid, sd::ATTRIBUTE)?;
        value
            .map(|v| {
                sd::decode(&v)
                    .map(Vec::from)
                    .map_err(|e| error(Status::IoError, e))
            })
            .transpose()
    }
    #[cfg(feature = "native-mount")]
    pub(crate) fn native_security_by_path(&mut self, path: &str) -> Result<Option<Vec<u8>>> {
        let cnid = self.resolve(path.split_once(':').map_or(path, |(base, _)| base))?;
        self.native_security_cnid(cnid)
    }
    #[cfg(feature = "native-mount")]
    pub(crate) fn native_security(&mut self, handle: Handle) -> Result<Option<Vec<u8>>> {
        let cnid = self.context(handle)?.cnid;
        self.native_security_cnid(cnid)
    }
    #[cfg(feature = "native-mount")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_with_security(
        &mut self,
        path: &str,
        kind: Kind,
        request: OpenRequest,
        attributes: Option<u32>,
        allocation: u64,
        initial: &[crate::ea::Change],
        descriptor: Option<&[u8]>,
    ) -> Result<Handle> {
        Self::reject_private_changes(initial)?;
        let mut changes = initial.to_vec();
        // Named streams use the base object's security; they cannot replace it.
        if !path.contains(':')
            && let Some(descriptor) = descriptor
        {
            changes.push(crate::ea::Change {
                name: sd::ATTRIBUTE.into(),
                value: Some(sd::encode(descriptor).map_err(|e| error(Status::Unsupported, e))?),
            });
        }
        self.create_entry(path, kind, request, attributes, allocation, &changes)
    }
    #[cfg(feature = "native-mount")]
    pub(crate) fn set_native_security(&mut self, handle: Handle, descriptor: &[u8]) -> Result<()> {
        self.healthy()?;
        let context = self.context(handle)?;
        let cnid = self.metadata_cnid(context.cnid)?;
        let value = sd::encode(descriptor).map_err(|e| error(Status::Unsupported, e))?;
        let time = now_filetime()?;
        // Atomic planning refuses unsupported targets or disk-full conditions
        // before writes. Native callers must enforce WRITE_DAC/WRITE_OWNER.
        self.publish_entry_attributes(cnid, &[(sd::ATTRIBUTE, Some(&value))], time)
    }
}
