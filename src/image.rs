use fstool::block::BlockDevice;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path};

/// Bounded, regular-file-only device. Existing inputs are never writable.
pub struct Image {
    file: File,
    base: u64,
    length: u64,
    cursor: u64,
    writable: bool,
}

pub fn validate_path(path: &Path) -> io::Result<()> {
    let text = path.to_string_lossy().replace('/', "\\");
    if text.starts_with("\\\\") || text.starts_with("\\??\\") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "device and UNC paths are not supported by the image harness",
        ));
    }
    for component in path.components() {
        if let Component::Normal(name) = component
            && !name.to_str().is_some_and(crate::names::windows_component)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reserved device names and alternate data streams are not supported",
            ));
        }
    }
    Ok(())
}

pub fn open_source(path: &Path) -> io::Result<File> {
    validate_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1); // Readers only; no concurrent write/delete handles.
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input must be a regular image file",
        ));
    }
    Ok(file)
}

pub fn create_output(path: &Path) -> io::Result<File> {
    validate_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    options.open(path)
}

impl Image {
    pub fn read_only(path: &Path, base: u64, length: Option<u64>) -> io::Result<Self> {
        Self::from_file(open_source(path)?, base, length, false)
    }
    /// Creates a new image; refuses to open or truncate any existing file.
    pub fn create(path: &Path, length: u64) -> io::Result<Self> {
        let file = create_output(path)?;
        file.set_len(length)?;
        Self::from_file(file, 0, Some(length), true)
    }
    /// The only entry point for mutation of an existing filesystem: a new copy.
    pub fn copy_new(
        source: &Path,
        output: &Path,
        base: u64,
        length: Option<u64>,
    ) -> io::Result<Self> {
        let mut input = open_source(source)?;
        checked_slice(input.metadata()?.len(), base, length)?;
        let mut file = create_output(output)?;
        copy_contents(&mut input, &mut file)?;
        file.sync_all()?;
        Self::from_file(file, base, length, true)
    }
    fn from_file(file: File, base: u64, length: Option<u64>, writable: bool) -> io::Result<Self> {
        let length = checked_slice(file.metadata()?.len(), base, length)?;
        Ok(Self {
            file,
            base,
            length,
            cursor: 0,
            writable,
        })
    }
}

fn copy_contents(input: &mut File, output: &mut File) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let metadata = input.metadata()?;
        if metadata.file_attributes() & 0x200 != 0 {
            // Only the newly created, exclusive output handle is changed. A
            // sparse source must not force allocation of all its zero regions.
            set_sparse(output)?;
            copy_sparse(input, output, metadata.len())?;
            output.set_len(metadata.len())?;
            return Ok(());
        }
    }
    io::copy(input, output)?;
    Ok(())
}

#[cfg(windows)]
fn set_sparse(file: &File) -> io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn DeviceIoControl(
            handle: *mut c_void,
            code: u32,
            input: *const c_void,
            input_bytes: u32,
            output: *mut c_void,
            output_bytes: u32,
            returned: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
    }
    let mut returned = 0;
    // SAFETY: file owns a live regular-file handle; synchronous invocation has
    // no input/output payload and the only writable pointer is a live u32.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            0x900c4, // FSCTL_SET_SPARSE, NULL input means set (never clear).
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn copy_sparse<R: Read, W: Write + Seek>(
    input: &mut R,
    output: &mut W,
    length: u64,
) -> io::Result<()> {
    let mut buffer = vec![0; 1024 * 1024];
    let mut remaining = length;
    while remaining != 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        input.read_exact(&mut buffer[..count])?;
        if buffer[..count].iter().all(|&byte| byte == 0) {
            output.seek(SeekFrom::Current(count as i64))?;
        } else {
            output.write_all(&buffer[..count])?;
        }
        remaining -= count as u64;
    }
    let mut extra = [0];
    if input.read(&mut extra)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sparse source length changed during copy",
        ));
    }
    Ok(())
}

fn checked_slice(size: u64, base: u64, length: Option<u64>) -> io::Result<u64> {
    let available = size
        .checked_sub(base)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset exceeds image"))?;
    let length = length.unwrap_or(available);
    if length == 0 || length > available {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "volume slice is empty or exceeds image",
        ));
    }
    Ok(length)
}

impl Read for Image {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let size = (self.length - self.cursor).min(buffer.len() as u64) as usize;
        self.file.seek(SeekFrom::Start(self.base + self.cursor))?;
        let count = self.file.read(&mut buffer[..size])?;
        self.cursor += count as u64;
        Ok(count)
    }
}
impl Write for Image {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if !self.writable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "inspection device denies all writes, including journal replay",
            ));
        }
        let size = (self.length - self.cursor).min(buffer.len() as u64) as usize;
        self.file.seek(SeekFrom::Start(self.base + self.cursor))?;
        let count = self.file.write(&buffer[..size])?;
        self.cursor += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.writable {
            self.file.sync_all()
        } else {
            Ok(())
        }
    }
}
impl Seek for Image {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.cursor) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.length) + i128::from(value),
        };
        if next < 0 || next > i128::from(self.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside volume slice",
            ));
        }
        self.cursor = next as u64;
        Ok(self.cursor)
    }
}
impl BlockDevice for Image {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        self.length
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(self.flush()?)
    }
}

#[cfg(test)]
mod sparse_tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn sparse_copy_preserves_nonzero_chunks_zero_gaps_and_partial_tail() {
        let mut bytes = vec![0; 3 * 1024 * 1024 + 19];
        bytes[0] = 7;
        bytes[1024 * 1024 - 1] = 13;
        bytes[2 * 1024 * 1024] = 19;
        let mut input = Cursor::new(&bytes);
        let mut output = Cursor::new(vec![0; bytes.len()]);
        copy_sparse(&mut input, &mut output, bytes.len() as u64).unwrap();
        assert_eq!(output.position(), bytes.len() as u64);
        assert_eq!(output.into_inner(), bytes);
    }

    #[test]
    fn sparse_copy_refuses_short_and_growing_inputs() {
        for (input, expected) in [(vec![1; 19], 20), (vec![1; 21], 20)] {
            assert!(
                copy_sparse(&mut Cursor::new(input), &mut Cursor::new(vec![]), expected).is_err()
            );
        }
    }

    #[test]
    fn sparse_copy_stops_after_output_error() {
        struct FailedWriter;
        impl Write for FailedWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("injected write failure"))
            }
            fn flush(&mut self) -> io::Result<()> {
                unreachable!()
            }
        }
        impl Seek for FailedWriter {
            fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
                unreachable!()
            }
        }
        let mut input = Cursor::new(vec![1; 2 * 1024 * 1024]);
        assert!(copy_sparse(&mut input, &mut FailedWriter, 2 * 1024 * 1024).is_err());
        assert_eq!(input.position(), 1024 * 1024);
    }

    #[cfg(windows)]
    #[test]
    fn new_sparse_image_has_exact_length_source_identity_and_slice_boundaries() {
        use std::os::windows::fs::MetadataExt;
        let folder = std::env::temp_dir().join(format!(
            "hfs-sparse-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&folder).unwrap();
        let source = folder.join("source.img");
        let output = folder.join("output.img");
        let mut original = create_output(&source).unwrap();
        set_sparse(&original).unwrap();
        let length = 3 * 1024 * 1024 + 19;
        original.set_len(length).unwrap();
        original.seek(SeekFrom::Start(1024 * 1024 - 3)).unwrap();
        original.write_all(b"cross-chunk").unwrap();
        original.sync_all().unwrap();
        drop(original);
        let before = std::fs::read(&source).unwrap();
        let mut image = Image::copy_new(&source, &output, 1024 * 1024 - 3, Some(11)).unwrap();
        assert_eq!(image.file.metadata().unwrap().len(), length);
        assert_ne!(image.file.metadata().unwrap().file_attributes() & 0x200, 0);
        let mut actual = [0; 11];
        image.read_exact(&mut actual).unwrap();
        assert_eq!(&actual, b"cross-chunk");
        assert!(image.seek(SeekFrom::Start(12)).is_err());
        image.seek(SeekFrom::Start(0)).unwrap();
        image.write_all(b"new-payload").unwrap();
        image.flush().unwrap();
        drop(image);
        assert_eq!(std::fs::read(&source).unwrap(), before);
        assert!(Image::copy_new(&source, &output, 0, None).is_err());
        assert!(!folder.join("invalid.img").exists());
        assert!(Image::copy_new(&source, &folder.join("invalid.img"), length, None).is_err());
        assert!(!folder.join("invalid.img").exists());
        // Remove only this test's newly created files and then its empty folder.
        std::fs::remove_file(source).unwrap();
        std::fs::remove_file(output).unwrap();
        std::fs::remove_dir(folder).unwrap();
    }
}
