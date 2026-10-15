//! Committed read snapshots. Writable adapters bypass snapshots during staged
//! metadata and clear them after publication. Every hit checks the live header.
use super::*;
impl<D: BlockDevice> Adapter<D> {
    pub(super) fn read_fixed_attribute(
        &mut self,
        cnid: u32,
        name: &str,
        expected_size: usize,
    ) -> Result<Option<Vec<u8>>> {
        if !self.read_only && !self.fs.metadata_is_committed() {
            return self
                .fs
                .fixed_inline_attribute(&mut self.device, cnid, name, expected_size)
                .map_err(engine_error);
        }
        self.body(cnid)?;
        // This still reads the live header and rebuilds after a publication.
        // Use the same bounded value parser, never the generic fork decoder.
        self.readonly_attribute_names(cnid)?;
        self.fs
            .indexed_fixed_inline_attribute(
                &self.readonly_attribute_index.as_ref().unwrap().1,
                cnid,
                name,
                expected_size,
            )
            .map_err(engine_error)
    }

    /// A committed negative lookup can avoid the expensive per-entry private
    /// record probe. Pending edits keep the original, uncached validation path.
    pub(super) fn committed_attribute_absent(&mut self, cnid: u32, name: &str) -> Result<bool> {
        if !self.read_only && !self.fs.metadata_is_committed() {
            return Ok(false);
        }
        self.body(cnid)?;
        Ok(!self
            .readonly_attribute_names(cnid)?
            .iter()
            .any(|n| n == name))
    }

    fn readonly_attribute_names(&mut self, cnid: u32) -> Result<Vec<String>> {
        let mut header = [0; 112];
        self.device
            .read_at(1024, &mut header)
            .map_err(engine_error)?;
        let current = crate::timestamps::VolumeState {
            id: header[104..112].try_into().unwrap(),
            created: volume::be32(&header, 16),
            write_count: volume::be32(&header, 68),
        };
        if self
            .readonly_attribute_index
            .as_ref()
            .is_none_or(|(state, _)| *state != current)
        {
            self.readonly_attribute_index = None;
            self.readonly_attribute_values.clear();
            let index = self
                .fs
                .attribute_read_index(&mut self.device)
                .map_err(engine_error)?;
            self.readonly_attribute_index = Some((current, index));
        }
        Ok(self
            .readonly_attribute_index
            .as_ref()
            .unwrap()
            .1
            .names(cnid))
    }
    pub(super) fn read_attribute(&mut self, cnid: u32, name: &str) -> Result<Option<Vec<u8>>> {
        if (!self.read_only && !self.fs.metadata_is_committed()) || name == "com.apple.FinderInfo" {
            return self
                .fs
                .inline_attribute(&mut self.device, cnid, name)
                .map_err(engine_error);
        }
        // Validate identity even for a cached absence.
        self.body(cnid)?;
        let names = self.readonly_attribute_names(cnid)?;
        if !names.iter().any(|n| n == name) {
            return Ok(None);
        }
        let key = (cnid, name.to_owned());
        if let Some(value) = self.readonly_attribute_values.get(&key) {
            return Ok(Some(value.clone()));
        }
        let value = self
            .fs
            .indexed_attribute(
                &mut self.device,
                &self.readonly_attribute_index.as_ref().unwrap().1,
                cnid,
                name,
            )
            .map_err(engine_error)?;
        if let Some(value) = &value {
            // Bound retained payloads independently of the existing per-value cap.
            if self.readonly_attribute_values.len() >= 64
                || self
                    .readonly_attribute_values
                    .values()
                    .map(Vec::len)
                    .sum::<usize>()
                    + value.len()
                    > 16 * 1024 * 1024
            {
                self.readonly_attribute_values.clear();
            }
            self.readonly_attribute_values.insert(key, value.clone());
        }
        Ok(value)
    }
    pub(super) fn read_attribute_names(&mut self, cnid: u32) -> Result<Vec<String>> {
        if !self.read_only && !self.fs.metadata_is_committed() {
            return self
                .fs
                .attribute_names(&mut self.device, cnid)
                .map_err(engine_error);
        }
        self.body(cnid)?;
        let mut names = self.readonly_attribute_names(cnid)?;
        if names.iter().any(|n| n == "com.apple.FinderInfo") {
            return Err(error(
                Status::Unsupported,
                "duplicate catalog/tree FinderInfo",
            ));
        }
        if self.read_attribute(cnid, "com.apple.FinderInfo")?.is_some() {
            names.push("com.apple.FinderInfo".into());
            names.sort();
        }
        Ok(names)
    }
}
