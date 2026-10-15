pub mod afp;
pub mod attribute_archive;
#[cfg(windows)]
pub mod disk;
pub mod ea;
pub mod engine;
pub mod image;
pub mod links;
pub mod named_streams;
pub mod names;
#[cfg(all(windows, feature = "native-mount"))]
pub mod native;
pub mod partitions;
pub mod read_only_device;
pub mod recovery;
pub mod sector_device;
pub mod security_descriptor;
pub mod timestamps;
pub mod transfer;
pub mod volume;
pub mod windows;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
