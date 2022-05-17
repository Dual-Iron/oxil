use crate::{
    error::{
        ReadImageError::{self, *},
        ReadImageResult,
    },
    io::{r, ReadExt, SeekExt},
    pe::DataDirectory,
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
        let signature = data.readv()?;
        if signature != 0x424A5342 {
            return Err(MetadataSignature(signature));
        }
        data.jump(8)?; // skip MajorVersion + MinorVersion, always 1
        let version: CliVersion = data.readv()?;
        data.jump(2)?; // skip Flags, always 0
        let stream_count = data.readv()?;
        if stream_count != 5 {
            return Err(StreamCount(stream_count));
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
                _ => return Err(ReadImageError::StreamName(name.0)),
            };

            // Don't allow duplicate streams.
            match stream {
                Some(_) => return Err(StreamDuplicate(name.0)),
                None => *stream = Some(StreamHeader { offset, size }),
            };
        }

        // By this point, five unique streams have been parsed, so all the streams are Some.

        Ok(Self {
            version,
            strings: s.unwrap(),
            us: u.unwrap(),
            blob: b.unwrap(),
            guid: g.unwrap(),
            tables: t.unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{offset_from, ImageHeader};

    #[test]
    fn metadata() {
        fn get_metadata(data: &mut (impl BufRead + Seek)) -> ReadImageResult<MetadataRoot> {
            let image = ImageHeader::read(data)?;
            let offset = offset_from(&image.sections, image.opt.clr_runtime_header.rva).unwrap();
            data.goto(offset.into())?;
            let cli_header = CliHeader::read(data)?;
            let offset = offset_from(&image.sections, cli_header.metadata.rva).unwrap();
            data.goto(offset.into())?;

            MetadataRoot::read(data)
        }

        let metadata = get_metadata(&mut crate::hello_world_test()).unwrap();

        assert_eq!(metadata, hello_world_metadata());
    }

    fn hello_world_metadata() -> MetadataRoot {
        MetadataRoot {
            version: CliVersion("v4.0.30319\u{0}\u{0}".try_into().unwrap()),
            strings: StreamHeader {
                offset: 0x1E4,
                size: 0x1F4,
            },
            us: StreamHeader {
                offset: 0x3D8,
                size: 0x20,
            },
            blob: StreamHeader {
                offset: 0x408,
                size: 0xC4,
            },
            guid: StreamHeader {
                offset: 0x3F8,
                size: 0x10,
            },
            tables: StreamHeader {
                offset: 0x6C,
                size: 0x178,
            },
        }
    }
}
