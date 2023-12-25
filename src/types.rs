use anyhow::Result as AnyhowResult;

pub type Result<T> = AnyhowResult<T>;
pub type ByteCursor = std::io::Cursor<Vec<u8>>;
