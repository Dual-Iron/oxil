use num_enum::TryFromPrimitive;
use std::io::{BufRead, Seek};

use crate::{
    error::{InvalidImageReason::*, ReadImageError::*, ReadImageResult},
    io::{ReadExt, SeekExt},
};

const TABLE_COUNT: usize = 0x2D;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, TryFromPrimitive)]
pub enum Tables {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Database {
    info: DatabaseInfo,
    // pub assembly: Table<0x20, Assembly>
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DatabaseInfo {
    lstreams: LargeStreams,
    row_count: [u32; TABLE_COUNT], // The number of rows in the table. Used for bounds checking tables and calculating table index sizes
    row_size: [u8; TABLE_COUNT], // The row size in bytes. Used for reading from a specific row in a table
    offsets: [u32; TABLE_COUNT], // The file offset from metadata root. Used for quickly jumping to the start of a table
}

bitflags::bitflags! {
    pub struct LargeStreams: u8 {
        const STRING = 0x1;
        const GUID = 0x2;
        const BLOB = 0x4;
    }
    pub struct AssemblyFlags: u32 {
        const PUBLIC_KEY = 0x1;
        const RETARGETABLE = 0x100;
        const DISABLE_JIT_COMPILE_OPTIMIZER = 0x4000;
        const ENABLE_JIT_COMPILE_TRACKING = 0x8000;
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, TryFromPrimitive)]
pub enum AssemblyHashAlgorithm {
    None = 0,
    MD5 = 0x8003,
    SHA1 = 0x8004,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StringIndex(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GuidIndex(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlobIndex(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SimpleIndex<const TABLE: usize>(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct DbCtor<'a> {
    lstreams: LargeStreams,
    rows: &'a [u32],
}

trait TableKind: Sized {
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

        Ok(Self {
            info: DatabaseInfo {
                lstreams,
                row_count,
                row_size,
                offsets,
            },
        })
    }
}

// # Ugly parsing time!

// ## DbRead

trait DbRead: Sized {
    fn size(db: DbCtor<'_>) -> u8;
    fn read(db: DbCtor<'_>, data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self>;
}

impl<const TABLE: usize> DbRead for SimpleIndex<TABLE> {
    fn size(db: DbCtor<'_>) -> u8 {
        if db.rows[TABLE] > u16::MAX.into() {
            4
        } else {
            2
        }
    }

    fn read(db: DbCtor<'_>, data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self> {
        Ok(if db.rows[TABLE] > u16::MAX.into() {
            // Read 4 bits
            Self(data.readv()?)
        } else {
            // Read 2 bits
            Self(ReadExt::<u16>::readv(data)?.into())
        })
    }
}

macro_rules! db_read_stream {
    ($name:ident, $bit:literal) => {
        impl DbRead for $name {
            fn size(db: DbCtor<'_>) -> u8 {
                if db.lstreams.bits & $bit != 0 {
                    4
                } else {
                    2
                }
            }

            fn read(db: DbCtor<'_>, data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self> {
                Ok(if db.lstreams.bits & $bit != 0 {
                    Self(data.readv()?)
                } else {
                    Self(ReadExt::<u16>::readv(data)?.into())
                })
            }
        }
    };
}

db_read_stream!(StringIndex, 0x1);
db_read_stream!(GuidIndex, 0x2);
db_read_stream!(BlobIndex, 0x4);

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

// ## Coded indexes

macro_rules! coded_indices {
    ( $( $name:ident [$bits:literal] ( $($vname:ident),+ ) )+ ) => {$(
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name(pub Tables, pub u32);

        impl DbRead for $name {
            fn size(db: DbCtor<'_>) -> u8 {
                let max_rows = 0 $(.max(db.rows[Tables::$vname as usize]))+ ;
                if max_rows > 2u32.pow(16 - $bits) {
                    4
                } else {
                    2
                }
            }

            fn read(db: DbCtor<'_>, data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self> {
                #[repr(u8)]
                #[derive(TryFromPrimitive)]
                enum IndexType {
                    $($vname,)+
                }

                // Read
                let int = if Self::size(db) == 4 {
                    data.readv()?
                } else {
                    ReadExt::<u16>::readv(data)? as u32
                };

                // Get the tag bits
                let tag = int & ((1 << $bits) - 1);
                let tag = tag as u8;

                // Get matching table for the tag bits
                let index_type = tag.try_into().map_err(|_| InvalidImage(CodedIndex(tag)))?;
                let table = match index_type {
                    $( IndexType::$vname => Tables::$vname, )+
                };

                // Row index is just a bit shift away!
                Ok(Self(table, int >> $bits))
            }
        }
    )+};
}

coded_indices! {
TypeDefOrRef[2](TypeDef, TypeRef, TypeSpec)
HasConstant[2](Field, Param, Property)
ResolutionScope[2](Module, ModuleRef, AssemblyRef, TypeRef)
}

// ## Tables

macro_rules! tables {
    ( $($name:ident ( $($fname:ident: $ftype:ty),* ) )+ ) => {$(
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name {
            $(pub $fname: $ftype),*
        }

        impl $name {
            pub const INDEX: Tables = Tables::$name;
        }

        impl TableKind for $name {
            fn row_size(db: DbCtor<'_>) -> u8 {
                // Sum the fields' sizes.
                0 $(+ <$ftype as DbRead>::size(db))*
            }
            fn row(db: DbCtor<'_>, data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self> {
                // Read each field.
                Ok(Self {
                    $($fname: <$ftype as DbRead>::read(db, data)?,)*
                })
            }
        })+
    };
}

tables! {
Module(generation: u16, name: StringIndex, mvid: GuidIndex, enc_id: GuidIndex, enc_base_id: GuidIndex)
TypeRef(resolution_scope: ResolutionScope, type_name: StringIndex, type_namespace: StringIndex)
Assembly(
    hash_alg_id: AssemblyHashAlgorithm,
    major_version: u16,
    minor_version: u16,
    build_number: u16,
    revision_number: u16,
    flags: AssemblyFlags,
    public_key: BlobIndex,
    name: StringIndex,
    culture: StringIndex
)
AssemblyOs(os_platform_id: u32, os_major_version: u32, os_minor_version: u32)
AssemblyProcessor(processor: u32)

}
