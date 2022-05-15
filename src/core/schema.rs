use num_enum::TryFromPrimitive;
use std::io::{BufRead, Seek};

use crate::{
    error::{InvalidImageReason::*, ReadImageError::*, ReadImageResult},
    io::{ReadExt, SeekExt},
};

const TABLE_COUNT: usize = 0x2D;

pub struct Database {
    info: DatabaseInfo,
    // pub assembly: Table<0x20, Assembly>
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DatabaseInfo {
    lstreams: LargeStreams,
    row_count: [u32; TABLE_COUNT], // Used for bounds checking tables and calculating table index sizes
    row_size: [u8; TABLE_COUNT],   // Used for reading from a specific row in a table
    offsets: [u32; TABLE_COUNT],   // Used for quickly jumping to the start of a table
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
pub struct StreamIndex<const STREAM: u8>(pub u32);

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
        if valid << TABLE_COUNT != 0 {
            return Err(InvalidImage(TableCount(valid)));
        }
        data.jump(8)?; // Tables that should be sorted are listed in section II.24 and never change

        let mut row_count = [0u32; TABLE_COUNT];

        for i in 0..TABLE_COUNT {
            if valid & (1 << i) != 0 {
                row_count[i] = data.readv()?;
            }
        }

        macro_rules! get_size {
            ( $($table:ident),+ ) => {{
                let mut i = 0;
                let mut row_size = [0u8; TABLE_COUNT];
                let mut offsets = [0u32; TABLE_COUNT];
                $(
                    row_size[i] = $table::row_size(DbCtor { lstreams, rows: &row_count });
                    if i > 0 {
                        offsets[i] = offsets[i - 1] + row_count[i] * row_size[i] as u32;
                    }
                    #[allow(unused_assignments)]
                    { i += 1; }
                )+
                (row_size, offsets)
            }};
        }

        let (row_size, offsets) = get_size!(Assembly, AssemblyOs);

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

// --- UGLY PARSING ---

trait DbRead: Sized {
    fn size(db: DbCtor<'_>) -> u8;
    fn read(db: DbCtor<'_>, data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self>;
}

impl<const STREAM: u8> DbRead for StreamIndex<STREAM> {
    fn size(db: DbCtor<'_>) -> u8 {
        if db.lstreams.bits & STREAM != 0 {
            4
        } else {
            2
        }
    }

    fn read(db: DbCtor<'_>, data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self> {
        Ok(if db.lstreams.bits & STREAM != 0 {
            let n: u32 = data.readv()?;
            Self(n)
        } else {
            let n: u16 = data.readv()?;
            Self(n.into())
        })
    }
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
            let n: u32 = data.readv()?;
            Self(n)
        } else {
            let n: u16 = data.readv()?;
            Self(n.into())
        })
    }
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

macro_rules! define_table {
    ( $($rowname:ident($($fname:ident: $ftype:ty),*))+ ) => {$(
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $rowname {
            $(pub $fname: $ftype),*
        }

        impl TableKind for $rowname {
            fn row_size(db: DbCtor<'_>) -> u8 {
                $(<$ftype as DbRead>::size(db) +)* 0
            }
            fn row(db: DbCtor<'_>, data: &mut (impl BufRead + Seek)) -> ReadImageResult<Self> {
                Ok(Self {
                    $($fname: <$ftype as DbRead>::read(db, data)?,)*
                })
            }
        })+
    };
}

// Reminder: STRING = 1, GUID = 2, BLOB = 4
define_table!(
Assembly(
    hash_alg_id: AssemblyHashAlgorithm,
    major_version: u16,
    minor_version: u16,
    build_number: u16,
    revision_number: u16,
    flags: AssemblyFlags,
    public_key: StreamIndex<4>,
    name: StreamIndex<1>,
    culture: StreamIndex<1>
)
AssemblyOs(os_platform_id: u32, os_major_version: u32, os_minor_version: u32)
AssemblyProcessor(processor: u32)
);
