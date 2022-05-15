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

    fn get_metadata(mut data: impl BufRead + Seek) -> MetadataRoot {
        let image = ImageHeader::read(&mut data).unwrap();
        let offset = pe::offset_from(&image.sections, image.opt.clr_runtime_header.rva).unwrap();
        data.seek(SeekFrom::Start(offset.into())).unwrap();
        let cli_header = CliHeader::read(&mut data).unwrap();
        let offset = pe::offset_from(&image.sections, cli_header.metadata.rva).unwrap();
        data.seek(SeekFrom::Start(offset.into())).unwrap();
        MetadataRoot::read(&mut data).unwrap()
    }

    #[test]
    fn test_image_header() {
        let image = ImageHeader::read(&mut data()).expect("image header");

        assert_eq!(
            image.opt.clr_runtime_header,
            DataDirectory {
                rva: 8200,
                size: 72,
            }
        );
    }

    #[test]
    fn test_metadata() {
        let metadata = get_metadata(&mut data());

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

        let metadata = get_metadata(&mut data);

        data.seek(SeekFrom::Start(
            metadata.file_offset + metadata.tables.offset as u64,
        ))
        .unwrap();

        let db = Database::read(&mut data).unwrap();

        dbg!(db);
    }
}
