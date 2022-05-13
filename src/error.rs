pub type ReadImageResult<T> = std::result::Result<T, ReadImageError>;

#[derive(Debug)]
pub enum ReadImageError {
    /// An IO error occurred while reading the file.
    IO(std::io::Error),
    /// The image is not a valid CLR-compatible image.
    InvalidImage(InvalidImageReason),
}

#[derive(Debug)]
pub enum InvalidImageReason {
    Magic(u16),
    DataDirectories(u32),
}

impl From<std::io::Error> for ReadImageError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}
