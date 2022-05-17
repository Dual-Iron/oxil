use crate::{
    error::{ReadImageError::*, ReadImageResult},
    metadata::{CliHeader, MetadataRoot},
    pe::{self, ImageHeader},
    schema::{parsing, Db},
    ModuleRead,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Image {
    pub pe: ImageHeader,
    pub cli: CliHeader,
    pub metadata: MetadataRoot,
    pub db: Db,

    pub metadata_offset: u64,
    pub tables_offset: u64,
}

impl Image {
    pub fn read(data: &mut impl ModuleRead) -> ReadImageResult<Self> {
        let pe = ImageHeader::read(data)?;
        let rva = pe.opt.clr_runtime_header.rva;
        data.goto(
            pe::offset_from(&pe.sections, rva)
                .ok_or(RvaOutOfRange(rva))?
                .into(),
        )?;
        let cli = CliHeader::read(data)?;
        let rva = cli.metadata.rva;
        data.goto(
            pe::offset_from(&pe.sections, rva)
                .ok_or(RvaOutOfRange(rva))?
                .into(),
        )?;
        let metadata_offset = data.pos()?;
        let metadata = MetadataRoot::read(data)?;
        data.goto(metadata_offset + metadata.tables.offset as u64)?;
        let db = Db::read(data)?;
        let tables_offset = data.pos()?;

        Ok(Self {
            pe,
            cli,
            metadata,
            db,
            metadata_offset,
            tables_offset,
        })
    }
}

pub struct DeferredReader<T: ModuleRead> {
    image: Image,
    data: T,
}

impl<T: ModuleRead> DeferredReader<T> {
    pub fn read(mut data: T) -> ReadImageResult<Self> {
        Ok(Self {
            image: Image::read(&mut data)?,
            data,
        })
    }

    pub fn row<Table: parsing::Table>(&mut self, row_index: u32) -> ReadImageResult<Option<Table>> {
        self.image
            .db
            .row::<Table, T>(&mut self.data, self.image.tables_offset, row_index)
    }

    pub fn image(&self) -> &Image {
        &self.image
    }

    pub fn into_inner(self) -> (Image, T) {
        (self.image, self.data)
    }
}

impl<T: ModuleRead + Clone> Clone for DeferredReader<T> {
    fn clone(&self) -> Self {
        Self {
            image: self.image.clone(),
            data: self.data.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{structures::*, table::Module};

    #[test]
    fn module_table() {
        let mut reader = DeferredReader::read(crate::hello_world_test()).unwrap();
        let module: Option<Module> = reader.row(0).unwrap();

        assert_eq!(
            module.unwrap(),
            Module {
                generation: 0,
                name: StringIndex(0x16D),
                mvid: GuidIndex(1),
                enc_id: GuidIndex(0),
                enc_base_id: GuidIndex(0)
            }
        )
    }
}
