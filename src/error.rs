use arrayvec::ArrayString;
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
    PeSignature([u8; 4]),
    Magic(u16),
    DataDirectories(u32),
    MetadataSignature(u32),
    StreamCount(u16),
    StreamName(ArrayString<32>),
    StreamDuplicate(ArrayString<32>),
    TableCount(u64),
    CodedIndex(u8),
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
        macro_rules! f {
            ($($t:tt)+) => {
                f.write_fmt(format_args!($($t)+))
            };
        }

        use InvalidImageReason::*;

        match self {
            PeSignature(pe) => f!("invalid PE signature: {pe:#?}"),
            Magic(m) => f!("invalid Magic: 0x{m:X}"),
            DataDirectories(d) => f!("invalid NumberOfRvaAndSizes: {d}"),
            MetadataSignature(m) => f!("invalid metadata signature: 0x{m:X}"),
            StreamCount(s) => f!("invalid stream count: {s}"),
            StreamName(n) => f!("invalid metadata stream name: {n}"),
            StreamDuplicate(n) => f!("duplicate metadata stream: {n}"),
            TableCount(n) => f!("too many valid tables: {n:b}"),
            CodedIndex(n) => f!("invalid coded index value: {n:b}"),
        }
    }
}
