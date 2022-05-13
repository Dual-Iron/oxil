pub mod error;
pub mod pe;

mod io;

#[cfg(test)]
mod tests {
    use crate::pe::{DataDirectories, DataDirectory, ImageHeader};
    use std::io::Cursor;

    #[test]
    fn image_header() {
        let mut data = Cursor::new(include_bytes!("../cs/HelloWorld.dll").as_ref());

        let image = ImageHeader::read(&mut data).expect("image header");

        assert_eq!(
            image.dirs[DataDirectories::ClrRuntimeHeader as usize],
            DataDirectory {
                rva: 8200,
                size: 72
            }
        )
    }
}
