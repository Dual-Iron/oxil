use super::{parsing::*, *};
use num_enum::TryFromPrimitive;

// Flags

bitflags::bitflags! {
    pub struct AssemblyFlags: u32 {
        const PUBLIC_KEY = 0x1;
        const RETARGETABLE = 0x100;
        const DISABLE_JIT_COMPILE_OPTIMIZER = 0x4000;
        const ENABLE_JIT_COMPILE_TRACKING = 0x8000;
    }
}

// Enums

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, TryFromPrimitive)]
pub enum AssemblyHashAlgorithm {
    None = 0,
    MD5 = 0x8003,
    SHA1 = 0x8004,
}

// Indexes

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StringIndex(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GuidIndex(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlobIndex(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RowIndex<const TABLE: usize>(pub u32);

macro_rules! db_read_stream {
    ($name:ident, $bit:literal) => {
        impl DbRead for $name {
            fn size(db: DbMeta<'_>) -> u8 {
                if db.lstreams & $bit != 0 {
                    4
                } else {
                    2
                }
            }

            fn read(db: DbMeta<'_>, data: &mut impl ModuleRead) -> ReadImageResult<Self> {
                Ok(Self(if db.lstreams & $bit != 0 {
                    data.u32()?
                } else {
                    data.u16()? as u32
                }))
            }
        }
    };
}

db_read_stream!(StringIndex, 0x1);
db_read_stream!(GuidIndex, 0x2);
db_read_stream!(BlobIndex, 0x4);

impl<const TABLE: usize> DbRead for RowIndex<TABLE> {
    fn size(db: DbMeta<'_>) -> u8 {
        if db.rows[TABLE] > u16::MAX.into() {
            4
        } else {
            2
        }
    }

    fn read(db: DbMeta<'_>, data: &mut impl ModuleRead) -> ReadImageResult<Self> {
        Ok(Self(if db.rows[TABLE] > u16::MAX.into() {
            data.u32()?
        } else {
            data.u16()? as u32
        }))
    }
}

// # Coded indices

macro_rules! coded_indices {
    ( $( $name:ident [$bits:literal] ( $($vname:ident),+ ) )+ ) => {$(
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name(TableIndex, pub u32);

        impl DbRead for $name {
            fn size(db: DbMeta<'_>) -> u8 {
                let max_rows = 0 $(.max(db.rows[TableIndex::$vname as usize]))+ ;
                if max_rows > 2u32.pow(16 - $bits) {
                    4
                } else {
                    2
                }
            }

            fn read(db: DbMeta<'_>, data: &mut impl ModuleRead) -> ReadImageResult<Self> {
                #[repr(u8)]
                #[derive(TryFromPrimitive)]
                enum IndexType {
                    $($vname,)+
                }

                // Read
                let int = if Self::size(db) == 4 {
                    data.u32()?
                } else {
                    data.u16()? as u32
                };

                // Get the tag bits
                let tag = int & ((1 << $bits) - 1);
                let tag = tag as u8;

                // Get matching table for the tag bits
                let index_type = tag.try_into().map_err(|_| CodedIndex(tag))?;
                let table = match index_type {
                    $( IndexType::$vname => TableIndex::$vname, )+
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
