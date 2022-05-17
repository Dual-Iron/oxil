use crate::{
    error::{
        ReadImageError::{self, *},
        ReadImageResult,
    },
    mod_read,
    pe::DataDirectory,
    ModuleRead,
};
use arrayvec::ArrayString;

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
    pub version: ArrayString<256>,
    pub strings: StreamHeader,
    pub us: StreamHeader,
    pub blob: StreamHeader,
    pub guid: StreamHeader,
    pub tables: StreamHeader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamHeader {
    pub offset: u32,
    pub size: u32,
}

impl CliHeader {
    pub fn read(data: &mut impl ModuleRead) -> ReadImageResult<Self> {
        data.skip(4)?;
        Ok(Self {
            major_runtime_version: data.u16()?,
            minor_runtime_version: data.u16()?,
            metadata: data.data_dir()?,
            flags: data.u32()?,
            entry_point_token: data.u32()?,
            resources: data.data_dir()?,
            strong_name_signature: mod_read!(eval data.data_dir()?, then data.skip(8)?), // skip CodeManagerTable, always 0
            vtable_fixups: mod_read!(eval data.data_dir()?, then data.skip(16)?), // skip ExportAddressTableJumps + ManagedNativeHeader, always 0
        })
    }
}

impl MetadataRoot {
    pub fn read(data: &mut impl ModuleRead) -> ReadImageResult<Self> {
        let signature = data.u32()?;
        if signature != 0x424A5342 {
            return Err(MetadataSignature(signature));
        }
        data.skip(8)?; // skip MajorVersion + MinorVersion, always 1
        let version = data.cli_version()?;
        data.skip(2)?; // skip Flags, always 0
        let stream_count = data.u16()?;
        if stream_count != 5 {
            return Err(StreamCount(stream_count));
        }

        // String, UserString, Blob, Guid, and Table streams respectively.
        let (mut s, mut u, mut b, mut g, mut t) = Default::default();

        for _ in 0..5 {
            let offset = data.u32()?;
            let size = data.u32()?;
            let name = data.stream_name()?;

            // Don't allow streams other than those specified in ECMA-335.
            let stream = match name.as_str() {
                "#Strings\0\0\0\0" => &mut s,
                "#US\0" => &mut u,
                "#Blob\0\0\0" => &mut b,
                "#GUID\0\0\0" => &mut g,
                "#~\0\0" => &mut t,
                _ => return Err(ReadImageError::StreamName(name)),
            };

            // Don't allow duplicate streams.
            match stream {
                Some(_) => return Err(StreamDuplicate(name)),
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
    use crate::{
        pe::{offset_from, ImageHeader},
        ModuleRead,
    };

    #[test]
    fn metadata() {
        fn get_metadata(data: &mut impl ModuleRead) -> ReadImageResult<MetadataRoot> {
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
            version: "v4.0.30319\u{0}\u{0}".try_into().unwrap(),
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
