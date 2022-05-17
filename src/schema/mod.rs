pub mod structures;
pub mod table;

pub(crate) mod parsing;

use crate::{
    error::{ReadImageError::*, ReadImageResult},
    io::{ReadExt, SeekExt},
};
use num_enum::TryFromPrimitive;
use parsing::{DbMeta, Table, TableIndex};
use std::io::{BufRead, Seek};

const TABLE_COUNT: usize = 0x2D;

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Db {
    lstreams: u8,
    row_count: [u32; TABLE_COUNT], // The number of rows in the table. Used for bounds checking tables and calculating table index sizes
    row_size: [u8; TABLE_COUNT], // The row size in bytes. Used for reading from a specific row in a table
    offsets: [u32; TABLE_COUNT], // The file offset from metadata root. Used for quickly jumping to the start of a table
}

impl Db {
    pub fn read(data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self> {
        data.jump(6)?;
        let lstreams = data.readv()?;
        data.jump(1)?;
        let valid: u64 = data.readv()?;
        if valid >> TABLE_COUNT != 0 {
            return Err(TableCount(valid));
        }
        data.jump(8)?; // Tables that should be sorted are listed in section II.24 and never change

        let mut row_count = [0u32; TABLE_COUNT];

        for i in 0..TABLE_COUNT {
            if (valid >> i) & 1 != 0 {
                row_count[i] = data.readv()?;
            }
        }

        macro_rules! get_sizes {
            ( $($table:ident),+ ) => {{
                let mut i = 0;
                let mut row_size = [0u8; TABLE_COUNT];
                let mut offsets = [0u32; TABLE_COUNT];
                $(
                    row_size[i] = $table::row_size(DbMeta { lstreams, rows: &row_count });
                    if i + 1 < TABLE_COUNT {
                        // NextTableOffset = CurrentOffset + Rows * SizePerRow
                        offsets[i + 1] = offsets[i] + row_count[i] * row_size[i] as u32;
                    }
                    #[allow(unused_assignments)] {
                        i += 1;
                    }
                )+
                (row_size, offsets)
            }};
        }

        use table::*;

        let (row_size, offsets) = get_sizes!(Module, TypeRef);

        Ok(Self {
            lstreams,
            row_count,
            row_size,
            offsets,
        })
    }

    pub fn row_size(&self, idx: TableIndex) -> u8 {
        self.row_size[idx as usize]
    }

    pub fn row_count(&self, idx: TableIndex) -> u32 {
        self.row_count[idx as usize]
    }

    pub fn offset(&self, idx: TableIndex) -> u32 {
        self.offsets[idx as usize]
    }

    pub fn row<Table: parsing::Table, Data: BufRead + Seek>(
        &self,
        data: &mut Data,
        table_stream_offset: u64,
        row_index: u32,
    ) -> ReadImageResult<Option<Table>> {
        if row_index >= self.row_count(Table::INDEX) {
            return Ok(None);
        }

        let root_pos = table_stream_offset + self.offset(Table::INDEX) as u64;
        let row_offset = row_index * self.row_size(Table::INDEX) as u32;

        data.goto(root_pos + row_offset as u64)?;

        Ok(Some(Table::row(self.meta(), data)?))
    }

    fn meta(&self) -> DbMeta {
        DbMeta {
            lstreams: self.lstreams,
            rows: &self.row_count,
        }
    }
}

trait DbRead: Sized {
    fn size(db: DbMeta<'_>) -> u8;
    fn read(db: DbMeta<'_>, data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self>;
}

macro_rules! db_read {
    ($t:ty = $e:expr) => {
        impl DbRead for $t {
            fn size(_: DbMeta<'_>) -> u8 {
                $e
            }
            fn read(_: DbMeta<'_>, data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self> {
                Ok(data.readv()?)
            }
        }
    };
}

db_read!(u8 = 1);
db_read!(u16 = 2);
db_read!(u32 = 4);
db_read!(u64 = 8);
db_read!(structures::AssemblyFlags = 4);
db_read!(structures::AssemblyHashAlgorithm = 4);
