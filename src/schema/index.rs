use super::*;

// # Simple indices

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct String(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Guid(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Blob(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Row<const TABLE: usize>(pub u32);

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

db_read_stream!(String, 0x1);
db_read_stream!(Guid, 0x2);
db_read_stream!(Blob, 0x4);

impl<const TABLE: usize> DbRead for Row<TABLE> {
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

// # Coded indices

macro_rules! coded_indices {
    ( $( $name:ident [$bits:literal] ( $($vname:ident),+ ) )+ ) => {$(
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name(TableIndex, pub u32);

        impl DbRead for $name {
            fn size(db: DbCtor<'_>) -> u8 {
                let max_rows = 0 $(.max(db.rows[TableIndex::$vname as usize]))+ ;
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
