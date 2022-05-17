pub mod error;
pub mod read;
pub mod schema;

mod io;
mod metadata;
mod pe;

#[cfg(test)]
pub(crate) fn hello_world_test() -> impl std::io::BufRead + std::io::Seek {
    std::io::Cursor::new(include_bytes!("../cs/HelloWorld.dll"))
}
