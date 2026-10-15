//! Windows directory views preserve catalog names and use stable CNID aliases
//! for unrepresentable names or Windows case collisions. Aliases resolve only
//! through the current directory map; no alias is decoded into a guessed path.
use crate::Result;
use std::cmp::Ordering;
use std::collections::BTreeSet;

const PREFIX: &str = "~HFS-";

fn device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        upper.strip_prefix(prefix).is_some_and(|digit| {
            matches!(
                digit,
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

/// Rules for a shell-compatible single component, without namespace prefixes,
/// streams or path separators. This does not validate a complete host path.
pub fn windows_component(name: &str) -> bool {
    !name.is_empty()
        && name.encode_utf16().count() <= 255
        && !name.ends_with([' ', '.'])
        && !name
            .chars()
            .any(|c| c <= '\u{1f}' || "<>:\"/\\|?*".contains(c))
        && !device_name(name)
}

fn alias_namespace(name: &str) -> Result<bool> {
    let units: Vec<u16> = name.encode_utf16().take(PREFIX.len()).collect();
    Ok(units.len() == PREFIX.len()
        && ordinal(&units, &PREFIX.encode_utf16().collect::<Vec<_>>())? == Ordering::Equal)
}

/// Validate a new Windows-view name and return its normalized canonical HFS
/// component. The alias namespace belongs to existing directory entries.
pub fn new_windows_component(name: &str) -> Result<String> {
    if !windows_component(name) || alias_namespace(name)? {
        return Err("invalid Windows component or reserved HFS alias namespace".into());
    }
    Ok(fstool::fs::hfs_plus::catalog::UniStr::from_path_component_checked(name)?.to_display_name())
}

pub(crate) fn same_windows_name(a: &str, b: &str) -> Result<bool> {
    let a = fstool::fs::hfs_plus::catalog::UniStr::from_path_component_checked(a)?;
    let b = fstool::fs::hfs_plus::catalog::UniStr::from_path_component_checked(b)?;
    Ok(ordinal(&a.code_units, &b.code_units)? == Ordering::Equal)
}

#[cfg(windows)]
pub(crate) fn ordinal(a: &[u16], b: &[u16]) -> Result<Ordering> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CompareStringOrdinal(
            a: *const u16,
            a_len: i32,
            b: *const u16,
            b_len: i32,
            ignore_case: i32,
        ) -> i32;
    }
    let a_len = i32::try_from(a.len())?;
    let b_len = i32::try_from(b.len())?;
    // Buffers remain live, lengths are bounded, and this API only reads them.
    match unsafe { CompareStringOrdinal(a.as_ptr(), a_len, b.as_ptr(), b_len, 1) } {
        1 => Ok(Ordering::Less),
        2 => Ok(Ordering::Equal),
        3 => Ok(Ordering::Greater),
        _ => Err(std::io::Error::last_os_error().into()),
    }
}

#[cfg(not(windows))]
pub(crate) fn ordinal(a: &[u16], b: &[u16]) -> Result<Ordering> {
    // Development fallback. Actual Win32 ordinal behavior is verified only on
    // Windows; this fallback is not a mounted-Windows compatibility claim.
    Ok(String::from_utf16(a)?
        .to_uppercase()
        .cmp(&String::from_utf16(b)?.to_uppercase()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsEntry {
    pub cnid: u32,
    pub hfs_component: String,
    pub windows_name: String,
    pub aliased: bool,
}

#[derive(Debug)]
pub struct DirectoryNames {
    entries: Vec<WindowsEntry>,
}

impl DirectoryNames {
    pub fn build(input: impl IntoIterator<Item = (u32, String)>) -> Result<Self> {
        let mut ids = BTreeSet::new();
        let mut entries = Vec::new();
        for (cnid, name) in input {
            if cnid < 16 || !ids.insert(cnid) {
                return Err("reserved or duplicate CNID in Windows directory view".into());
            }
            if name.is_empty()
                || name == "."
                || name == ".."
                || name.contains(['/', '\0'])
                || name.encode_utf16().count() > 255
            {
                return Err("unsupported canonical HFS directory component".into());
            }
            // Confirm the candidate's String-based path view can resolve this
            // name without changing its wire representation.
            if fstool::fs::hfs_plus::catalog::UniStr::from_path_component_checked(&name)?
                .to_display_name()
                != name
            {
                return Err("noncanonical HFS name requires a raw catalog adapter".into());
            }
            let aliased = !windows_component(&name) || alias_namespace(&name)?;
            entries.push(WindowsEntry {
                cnid,
                hfs_component: name.clone(),
                windows_name: name,
                aliased,
            });
        }
        let units: Vec<Vec<u16>> = entries
            .iter()
            .map(|entry| entry.windows_name.encode_utf16().collect())
            .collect();
        let mut order: Vec<usize> = (0..entries.len()).collect();
        let mut comparison_error = None;
        order.sort_by(|&a, &b| match ordinal(&units[a], &units[b]) {
            Ok(value) => value,
            Err(error) => {
                comparison_error = Some(error);
                a.cmp(&b)
            }
        });
        if let Some(error) = comparison_error {
            return Err(error);
        }
        for pair in order.windows(2) {
            if ordinal(&units[pair[0]], &units[pair[1]])? == Ordering::Equal {
                entries[pair[0]].aliased = true;
                entries[pair[1]].aliased = true;
            }
        }
        for entry in &mut entries {
            if entry.aliased {
                let extension = entry
                    .hfs_component
                    .rsplit_once('.')
                    .map(|(_, ext)| ext)
                    .filter(|ext| {
                        !ext.is_empty()
                            && ext.encode_utf16().count() <= 32
                            && windows_component(&format!("x.{ext}"))
                    });
                entry.windows_name = format!("{PREFIX}{:08X}", entry.cnid);
                if let Some(extension) = extension {
                    entry.windows_name.push('.');
                    entry.windows_name.push_str(extension);
                }
            }
        }
        // Confirm the final namespace invariant independently of alias-prefix
        // reservation, before exposing any entry for resolution.
        let final_units: Vec<Vec<u16>> = entries
            .iter()
            .map(|entry| entry.windows_name.encode_utf16().collect())
            .collect();
        let mut final_order: Vec<usize> = (0..entries.len()).collect();
        let mut error = None;
        final_order.sort_by(|&a, &b| match ordinal(&final_units[a], &final_units[b]) {
            Ok(value) => value,
            Err(value) => {
                error = Some(value);
                a.cmp(&b)
            }
        });
        if let Some(error) = error {
            return Err(error);
        }
        for pair in final_order.windows(2) {
            if ordinal(&final_units[pair[0]], &final_units[pair[1]])? == Ordering::Equal {
                return Err("Windows directory alias collision".into());
            }
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[WindowsEntry] {
        &self.entries
    }

    /// Exact current-directory resolution under Win32 ordinal case rules.
    /// Unknown or stale aliases cannot silently address a guessed CNID.
    pub fn resolve(&self, windows_name: &str) -> Result<&WindowsEntry> {
        if !windows_component(windows_name) {
            return Err("invalid Windows component".into());
        }
        let units =
            fstool::fs::hfs_plus::catalog::UniStr::from_path_component_checked(windows_name)?
                .code_units;
        for entry in &self.entries {
            if ordinal(
                &units,
                &entry.windows_name.encode_utf16().collect::<Vec<_>>(),
            )? == Ordering::Equal
            {
                return Ok(entry);
            }
        }
        Err("Windows name is absent from the current directory view".into())
    }
}
