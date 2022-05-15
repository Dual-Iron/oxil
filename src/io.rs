use crate::core::{
    metadata::{CliVersion, NulString, StreamName},
    pe::{DataDirectory, SectionName},
    schema::{AssemblyFlags, AssemblyHashAlgorithm},
};
use arrayvec::{ArrayString, ArrayVec};
use std::{
    io::{BufRead, Error, ErrorKind, Read, Result, Seek, SeekFrom},
    str::Utf8Error,
};

fn utf8_err(e: Utf8Error) -> Error {
    Error::new(ErrorKind::InvalidData, e)
}

/// Panicky. Ensure `b.len()` < `CAP` always.
fn arrstr_from<const CAP: usize>(b: &[u8]) -> std::result::Result<ArrayString<CAP>, Utf8Error> {
    std::str::from_utf8(b).map(|s| ArrayString::try_from(s).unwrap())
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

impl<T: Read> ReadExt<CliVersion> for T {
    fn readv(&mut self) -> Result<CliVersion> {
        // Read length into `len`, then create a slice-buffer of size `len`
        // SAFETY: arrstr_from cannot panic because `len` <= 256 always
        let len: u32 = self.readv()?;
        let buf = &mut [0; 256][..len.try_into().unwrap()];
        self.read_exact(buf)?;
        arrstr_from(buf).map(CliVersion).map_err(utf8_err)
    }
}

impl<T: Read> ReadExt<StreamName> for T {
    fn readv(&mut self) -> Result<StreamName> {
        let mut strbuf = ArrayVec::<_, 32>::new();
        let mut buf = [0; 4];

        loop {
            self.read_exact(&mut buf)?;

            // SAFETY: arrstr_from cannot panic because `strbuf` stops reading if it reaches length of 32
            strbuf.try_extend_from_slice(&buf).unwrap();

            if strbuf.len() == 32 || buf.contains(&0) {
                break arrstr_from(&strbuf).map(StreamName).map_err(utf8_err);
            }
        }
    }
}

impl<T: BufRead> ReadExt<NulString> for T {
    fn readv(&mut self) -> Result<NulString> {
        let mut strbuf = Vec::new();

        self.read_until(b'\0', &mut strbuf)?;

        if let Some(b'\0') = strbuf.last() {
            strbuf.pop();
        }

        Ok(NulString(
            String::from_utf8(strbuf).map_err(|e| Error::new(ErrorKind::InvalidData, e))?,
        ))
    }
}

macro_rules! readext {
    (int $t:ty) => {
        impl<T: Read> ReadExt<$t> for T {
            fn readv(&mut self) -> Result<$t> {
                self.read_bytes().map(<$t>::from_le_bytes)
            }
        }
    };
    (flags $t:ty) => {
        impl<T: Read> ReadExt<$t> for T {
            fn readv(&mut self) -> Result<$t> {
                let bits = self.readv()?;
                Ok(<$t>::from_bits(bits).ok_or_else(|| {
                    Error::new(ErrorKind::Other, format!("invalid bit pattern: {bits:b}"))
                })?)
            }
        }
    };
    (enum $t:ty: $prim:ty) => {
        impl<T: Read> ReadExt<$t> for T {
            fn readv(&mut self) -> Result<$t> {
                let raw: $prim = self.readv()?;
                Ok(raw
                    .try_into()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?)
            }
        }
    };
}

readext!(int u8);
readext!(int u16);
readext!(int u32);
readext!(int u64);
readext!(flags AssemblyFlags);
readext!(enum AssemblyHashAlgorithm: u32);

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

pub(crate) use r;
