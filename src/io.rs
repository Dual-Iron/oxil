use crate::pe::{DataDirectory, SectionName};
use std::io::{Error, ErrorKind, Read, Result, Seek, SeekFrom};

fn utf8_err(e: std::str::Utf8Error) -> Error {
    Error::new(ErrorKind::InvalidData, e)
}

// -- Seek --

pub trait SeekExt {
    fn jump(&mut self, offset: i64) -> Result<u64>;
    fn goto(&mut self, offset: u64) -> Result<u64>;
}

impl<T: Seek> SeekExt for T {
    fn jump(&mut self, offset: i64) -> Result<u64> {
        self.seek(SeekFrom::Current(offset))
    }

    fn goto(&mut self, offset: u64) -> Result<u64> {
        self.seek(SeekFrom::Start(offset))
    }
}

// -- Read --

pub trait ReadBytes {
    fn read_bytes<const LEN: usize>(&mut self) -> Result<[u8; LEN]>;
}

impl<T: Read> ReadBytes for T {
    fn read_bytes<const LEN: usize>(&mut self) -> Result<[u8; LEN]> {
        let mut bytes = [0; LEN];
        self.read_exact(&mut bytes).map(|_| bytes)
    }
}

pub trait ReadExt<T> {
    fn readv(&mut self) -> Result<T>;
}

impl<T: Read> ReadExt<DataDirectory> for T {
    fn readv(&mut self) -> Result<DataDirectory> {
        Ok(DataDirectory {
            rva: self.readv()?,
            size: self.readv()?,
        })
    }
}

impl<T: Read> ReadExt<SectionName> for T {
    fn readv(&mut self) -> Result<SectionName> {
        Ok(SectionName(
            ArrayString::from_byte_string(&self.read_bytes()?).map_err(utf8_err)?,
        ))
    }
}

macro_rules! integral_read {
    ($t:ty) => {
        impl<T: Read> ReadExt<$t> for T {
            fn readv(&mut self) -> Result<$t> {
                self.read_bytes().map(<$t>::from_le_bytes)
            }
        }
    };
}

integral_read!(u8);
integral_read!(u16);
integral_read!(u32);
integral_read!(u64);

// -- Read + Seek --

macro_rules! r {
    (eval $e:expr, then $jmp:expr) => {{
        let temp = $e;
        $jmp;
        temp
    }};
    ($data:ident: if $cond:expr => $t1:ty | $t2:ty) => {
        if $cond {
            crate::io::ReadExt::<$t1>::readv(&mut $data)?.into()
        } else {
            crate::io::ReadExt::<$t2>::readv(&mut $data)?.into()
        }
    };
}

use arrayvec::ArrayString;
pub(crate) use r;
