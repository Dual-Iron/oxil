use arrayvec::{ArrayString, ArrayVec};
use pe::DataDirectory;
use std::io::{BufRead, Error, ErrorKind, Result, Seek, SeekFrom};

pub mod error;
pub mod read;
pub mod schema;

mod metadata;
mod pe;

#[cfg(test)]
pub(crate) fn hello_world_test() -> impl ModuleRead {
    std::io::Cursor::new(include_bytes!("../cs/HelloWorld.dll"))
}

macro_rules! read_fn {
    ($int:ident) => {
        fn $int(&mut self) -> Result<$int> {
            self.read_bytes().map($int::from_le_bytes)
        }
    };
}

macro_rules! invalid_data {
    () => {
        |e| Error::new(ErrorKind::InvalidData, e)
    };
}

macro_rules! arrstr {
    ($b:ident) => {
        std::str::from_utf8(&$b).map(|s| ArrayString::try_from(s).unwrap())
    };
}

pub trait ModuleRead {
    fn goto(&mut self, pos: u64) -> Result<u64>;
    fn skip(&mut self, skip_by: i64) -> Result<u64>;
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()>;
    fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> Result<usize>;

    fn pos(&mut self) -> Result<u64> {
        self.skip(0)
    }

    fn read_bytes<const LEN: usize>(&mut self) -> Result<[u8; LEN]> {
        let mut buf = [0; LEN];
        self.read_exact(&mut buf).map(|()| buf)
    }

    read_fn!(u8);
    read_fn!(u16);
    read_fn!(u32);
    read_fn!(u64);

    fn data_dir(&mut self) -> Result<DataDirectory> {
        Ok(DataDirectory {
            rva: self.u32()?,
            size: self.u32()?,
        })
    }

    fn section_name(&mut self) -> Result<ArrayString<8>> {
        self.read_bytes()
            .and_then(|b| ArrayString::from_byte_string(&b).map_err(invalid_data!()))
    }

    fn cli_version(&mut self) -> Result<ArrayString<256>> {
        // Read length into `len`, then create a slice-buffer of size `len`
        // SAFETY: arrstr_from cannot panic because `len` <= 256 always
        let len = self.u32()?;
        if len > 256 {
            return Err(Error::new(ErrorKind::InvalidData, "cli version len > 256"));
        }
        let buf = &mut [0; 256][..len.try_into().unwrap()];
        self.read_exact(buf)?;
        arrstr!(buf).map_err(invalid_data!())
    }

    fn stream_name(&mut self) -> Result<ArrayString<32>> {
        let mut strbuf = ArrayVec::<_, 32>::new();
        let mut buf = [0; 4];

        loop {
            self.read_exact(&mut buf)?;

            // SAFETY: arrstr_from cannot panic because `strbuf` stops reading if it reaches length of 32
            strbuf.try_extend_from_slice(&buf).unwrap();

            if strbuf.len() == 32 || buf.contains(&0) {
                break arrstr!(strbuf).map_err(invalid_data!());
            }
        }
    }

    fn null_terminated_str(&mut self) -> Result<String> {
        let mut strbuf = Vec::new();
        self.read_until(0, &mut strbuf)?;
        if let Some(0) = strbuf.last() {
            strbuf.pop();
        }
        String::from_utf8(strbuf).map_err(invalid_data!())
    }
}

impl<T: BufRead + Seek> ModuleRead for T {
    fn goto(&mut self, pos: u64) -> Result<u64> {
        self.seek(SeekFrom::Start(pos))
    }

    fn skip(&mut self, skip_by: i64) -> Result<u64> {
        self.seek(SeekFrom::Current(skip_by))
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        self.read_exact(buf)
    }

    fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> Result<usize> {
        self.read_until(byte, buf)
    }
}

macro_rules! mod_read {
    (eval $e:expr, then $jmp:expr) => {{
        let temp = $e;
        $jmp;
        temp
    }};
    (fit $data:ident to $pe64:ident) => {
        if $pe64 {
            $data.u64()?
        } else {
            $data.u32()?.into()
        }
    };
}

use mod_read;
