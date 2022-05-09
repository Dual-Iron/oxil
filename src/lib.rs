mod error;
mod pe;

macro_rules! read {
    ($data:ident for: $($etc:tt)*) => {
        read!($data $($etc)*)
    };
    ($data:ident skip $n:expr, $($etc:tt)*) => {
        ::std::io::Seek::seek(&mut $data, ::std::io::SeekFrom::Current($n as i64))?;
        read!($data $($etc)*)
    };
    ($data:ident goto $n:expr, $($etc:tt)*) => {
        ::std::io::Seek::seek(&mut $data, ::std::io::SeekFrom::Start($n as u64))?;
        read!($data $($etc)*)
    };
    ($data:ident $v:ident: str8, $($etc:tt)*) => {
        let $v = {
            let mut buf = [0; 8];
            $data.read_exact(&mut buf)?;
            let len_before_nul = buf.split(|&u| u == b'\0').next().unwrap().len();
            let mut result = ::arrayvec::ArrayString::from_byte_string(&buf)?;
            result.truncate(len_before_nul);
            result
        };
        read!($data $($etc)*)
    };
    ($data:ident $v:ident: $t:ty, $($etc:tt)*) => {
        let $v = {
            let mut buf = [0; ::std::mem::size_of::<$t>()];
            ::std::io::Read::read_exact(&mut $data, &mut buf)?;
            <$t>::from_le_bytes(buf)
        };
        read!($data $($etc)*)
    };
    ($data:ident $t:ty) => {
        {
            let mut buf = [0; ::std::mem::size_of::<$t>()];
            ::std::io::Read::read_exact(&mut $data, &mut buf)?;
            <$t>::from_le_bytes(buf)
        }
    };
    ($data:ident) => {}
}

pub(crate) use read;

use arrayvec::ArrayString;

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    #[test]
    fn it_works() -> std::io::Result<()> {
        let mut data = include_bytes!("../HelloWorld.dll").as_ref();
        let mut data = Cursor::new(&mut data);

        dbg!();

        Ok(())
    }
}
