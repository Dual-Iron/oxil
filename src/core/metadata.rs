use crate::{
    core::pe::DataDirectory,
    error::{
        InvalidImageReason::{self, *},
        ReadImageError::*,
        ReadImageResult,
    },
    io::{r, ReadExt, SeekExt},
};
use arrayvec::ArrayString;
use std::io::{BufRead, Seek};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NulString(pub String);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CliHeader {
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    pub metadata: DataDirectory,
    pub flags: u32,
    pub entry_point_token: u32,
    pub resources: DataDirectory,
    pub strong_name_signature: DataDirectory,
    pub vtable_fixups: DataDirectory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MetadataRoot {
    pub file_offset: u64,
    pub version: CliVersion,
    pub strings: StreamHeader,
    pub us: StreamHeader,
    pub blob: StreamHeader,
    pub guid: StreamHeader,
    pub tables: StreamHeader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CliVersion(pub ArrayString<256>);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamHeader {
    pub offset: u32,
    pub size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamName(pub ArrayString<32>);

impl CliHeader {
    pub fn read(data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self> {
        data.jump(4)?;
        Ok(Self {
            major_runtime_version: data.readv()?,
            minor_runtime_version: data.readv()?,
            metadata: data.readv()?,
            flags: data.readv()?,
            entry_point_token: data.readv()?,
            resources: data.readv()?,
            strong_name_signature: r!(eval data.readv()?, then data.jump(8)?), // skip CodeManagerTable, always 0
            vtable_fixups: r!(eval data.readv()?, then data.jump(16)?), // skip ExportAddressTableJumps + ManagedNativeHeader, always 0
        })
    }
}

impl MetadataRoot {
    pub fn read(data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self> {
        let file_offset = data.stream_position()?;
        let signature = data.readv()?;
        if signature != 0x424A5342 {
            return Err(InvalidImage(MetadataSignature(signature)));
        }
        data.jump(8)?; // skip MajorVersion + MinorVersion, always 1
        let version: CliVersion = data.readv()?;
        data.jump(2)?; // skip Flags, always 0
        let stream_count = data.readv()?;
        if stream_count != 5 {
            return Err(InvalidImage(StreamCount(stream_count)));
        }

        // String, UserString, Blob, Guid, and Table streams respectively.
        let (mut s, mut u, mut b, mut g, mut t) = Default::default();

        for _ in 0..5 {
            let offset: u32 = data.readv()?;
            let size: u32 = data.readv()?;
            let name: StreamName = data.readv()?;

            // Don't allow streams other than those specified in ECMA-335.
            let stream = match name.0.as_str() {
                "#Strings\0\0\0\0" => &mut s,
                "#US\0" => &mut u,
                "#Blob\0\0\0" => &mut b,
                "#GUID\0\0\0" => &mut g,
                "#~\0\0" => &mut t,
                _ => return Err(InvalidImage(InvalidImageReason::StreamName(name.0))),
            };

            // Don't allow duplicate streams.
            match stream {
                Some(_) => return Err(InvalidImage(StreamDuplicate(name.0))),
                None => *stream = Some(StreamHeader { offset, size }),
            };
        }

        // By this point, five unique streams have been parsed, so all the streams are Some.

        Ok(Self {
            file_offset,
            version,
            strings: s.unwrap(),
            us: u.unwrap(),
            blob: b.unwrap(),
            guid: g.unwrap(),
            tables: t.unwrap(),
        })
    }
}
