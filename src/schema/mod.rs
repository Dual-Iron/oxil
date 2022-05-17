pub mod index;
pub mod table;
pub mod values;

use crate::{
    error::{InvalidImageReason::*, ReadImageError::*, ReadImageResult},
    io::{ReadExt, SeekExt},
};
use num_enum::TryFromPrimitive;
use std::io::{BufRead, Seek};
use table::*;
use values::*;

const TABLE_COUNT: usize = 0x2D;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Database(DatabaseInfo);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct DatabaseInfo {
    lstreams: LargeStreams,
    row_count: [u32; TABLE_COUNT], // The number of rows in the table. Used for bounds checking tables and calculating table index sizes
    row_size: [u8; TABLE_COUNT], // The row size in bytes. Used for reading from a specific row in a table
    offsets: [u32; TABLE_COUNT], // The file offset from metadata root. Used for quickly jumping to the start of a table
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, TryFromPrimitive)]
enum TableIndex {
    Module = 0x00,
    TypeRef = 0x01,
    TypeDef = 0x02,
    FieldPtr = 0x03,
    Field = 0x04,
    MethodPtr = 0x05,
    Method = 0x06,
    ParamPtr = 0x07,
    Param = 0x08,
    InterfaceImpl = 0x09,
    MemberRef = 0x0a,
    Constant = 0x0b,
    CustomAttribute = 0x0c,
    FieldMarshal = 0x0d,
    DeclSecurity = 0x0e,
    ClassLayout = 0x0f,
    FieldLayout = 0x10,
    StandAloneSig = 0x11,
    EventMap = 0x12,
    EventPtr = 0x13,
    Event = 0x14,
    PropertyMap = 0x15,
    PropertyPtr = 0x16,
    Property = 0x17,
    MethodSemantics = 0x18,
    MethodImpl = 0x19,
    ModuleRef = 0x1a,
    TypeSpec = 0x1b,
    ImplMap = 0x1c,
    FieldRva = 0x1d,
    EncLog = 0x1e,
    EncMap = 0x1f,
    Assembly = 0x20,
    AssemblyProcessor = 0x21,
    AssemblyOs = 0x22,
    AssemblyRef = 0x23,
    AssemblyRefProcessor = 0x24,
    AssemblyRefOs = 0x25,
    File = 0x26,
    ExportedType = 0x27,
    ManifestResource = 0x28,
    NestedClass = 0x29,
    GenericParam = 0x2a,
    MethodSpec = 0x2b,
    GenericParamConstraint = 0x2c,
}

bitflags::bitflags! {
    struct LargeStreams: u8 {
        const STRING = 0x1;
        const GUID = 0x2;
        const BLOB = 0x4;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct DbCtor<'a> {
    lstreams: LargeStreams,
    rows: &'a [u32],
}

trait Table: Sized {
    const INDEX: TableIndex;
    fn row_size(db: DbCtor<'_>) -> u8;
    fn row(db: DbCtor<'_>, data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self>;
}

impl Database {
    pub fn read(data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self> {
        data.jump(6)?;
        let lstreams = LargeStreams {
            bits: data.readv()?, // HeapSizes
        };
        data.jump(1)?;
        let valid: u64 = data.readv()?;
        if valid >> TABLE_COUNT != 0 {
            return Err(InvalidImage(TableCount(valid)));
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
                    row_size[i] = $table::row_size(DbCtor { lstreams, rows: &row_count });
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

        let (row_size, offsets) = get_sizes!(Module, TypeRef);

        Ok(Self(DatabaseInfo {
            lstreams,
            row_count,
            row_size,
            offsets,
        }))
    }
}

trait DbRead: Sized {
    fn size(db: DbCtor<'_>) -> u8;
    fn read(db: DbCtor<'_>, data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self>;
}

macro_rules! db_read {
    ($t:ty = $e:expr) => {
        impl DbRead for $t {
            fn size(_: DbCtor<'_>) -> u8 {
                $e
            }
            fn read(_: DbCtor<'_>, data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self> {
                Ok(data.readv()?)
            }
        }
    };
}

db_read!(u8 = 1);
db_read!(u16 = 2);
db_read!(u32 = 4);
db_read!(u64 = 8);
db_read!(AssemblyFlags = 4);
db_read!(AssemblyHashAlgorithm = 4);
