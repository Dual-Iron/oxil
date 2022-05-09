pub type ReadImageResult<T> = std::result::Result<T, ReadImageError>;

#[derive(Debug)]
pub enum ReadImageError {
    /// An IO error occurred while reading the file.
    IO(std::io::Error),
    /// The image contains a string that should have been UTF-8 but wasn't.
    Utf(std::str::Utf8Error),
    /// The image is not a valid CLR-compatible image.
    InvalidImage,
}

impl From<std::io::Error> for ReadImageError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl From<std::str::Utf8Error> for ReadImageError {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::Utf(e)
    }
}
