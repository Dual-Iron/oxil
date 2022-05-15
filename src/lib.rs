pub mod error;

mod core;
mod io;

#[cfg(test)]
mod tests {
    use crate::core::{
        metadata::{CliHeader, MetadataRoot, StreamHeader},
        pe::{self, DataDirectory, ImageHeader},
        schema::Database,
    };
    use std::io::{BufRead, Cursor, Seek, SeekFrom};

    fn data() -> impl BufRead + Seek {
        Cursor::new(include_bytes!("../cs/HelloWorld.dll"))
    }

    #[test]
    fn test_image_header() {
        let image = ImageHeader::read(&mut data()).expect("image header");
        let expected_clr_dir = DataDirectory {
            rva: 8200,
            size: 72,
        };

        assert_eq!(image.opt.clr_runtime_header, expected_clr_dir);
    }

    #[test]
    fn test_metadata() {
        let mut data = data();
        let image = ImageHeader::read(&mut data).unwrap();

        let offset = pe::offset_from(&image.sections, image.opt.clr_runtime_header.rva).unwrap();
        data.seek(SeekFrom::Start(offset.into())).unwrap();

        let cli_header = CliHeader::read(&mut data).unwrap();

        let offset = pe::offset_from(&image.sections, cli_header.metadata.rva).unwrap();
        data.seek(SeekFrom::Start(offset.into())).unwrap();

        let metadata = MetadataRoot::read(&mut data).unwrap();

        assert_eq!(
            metadata.tables,
            StreamHeader {
                offset: 108,
                size: 376,
            }
        )
    }

    #[test]
    fn test_tables() {
        let mut data = data();

        let database = {
            let image = ImageHeader::read(&mut data).unwrap();

            let offset =
                pe::offset_from(&image.sections, image.opt.clr_runtime_header.rva).unwrap();
            data.seek(SeekFrom::Start(offset.into())).unwrap();

            let cli_header = CliHeader::read(&mut data).unwrap();

            let offset = pe::offset_from(&image.sections, cli_header.metadata.rva).unwrap();
            data.seek(SeekFrom::Start(offset.into())).unwrap();

            let metadata = MetadataRoot::read(&mut data).unwrap();

            data.seek(SeekFrom::Start(
                metadata.file_offset + metadata.tables.offset as u64,
            ))
            .unwrap();

            Database::read(&mut data).unwrap()
        };
    }
}
