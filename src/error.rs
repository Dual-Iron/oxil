use std::fmt::Display;

pub type ReadImageResult<T> = std::result::Result<T, ReadImageError>;

#[derive(Debug)]
pub enum ReadImageError {
    /// An IO error occurred while reading the file.
    IO(std::io::Error),
    /// The image is not a valid CLR-compatible image.
    InvalidImage(InvalidImageReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidImageReason {
    Magic(u16),
    DataDirectories(u32),
}

impl From<std::io::Error> for ReadImageError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl Display for ReadImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ReadImageError::*;

        match self {
            IO(e) => e.fmt(f),
            InvalidImage(r) => r.fmt(f),
        }
    }
}

impl Display for InvalidImageReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use InvalidImageReason::*;

        match self {
            Magic(m) => f.write_fmt(format_args!(
                "bad Magic field. expected 0x10B or 0x20B, got {m}"
            )),
            DataDirectories(d) => f.write_fmt(format_args!(
                "bad NumberOfRvaAndSizes field. expected 16, got {d}"
            )),
        }
    }
}
