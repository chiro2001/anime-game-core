pub mod downloader;
pub mod archives;
pub mod installer;
pub mod diff;
pub mod free_space;

pub mod prelude {
    pub use super::downloader::{Downloader, DownloadingError};
    pub use super::archives::Archive;
    pub use super::installer::{
        Installer,
        Update as InstallerUpdate
    };
    pub use super::diff::{
        VersionDiff,
        TryGetDiff,
        DiffDownloadError,
        Update as DiffUpdate
    };
    pub use super::free_space;
}
