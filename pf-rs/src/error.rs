use std::result;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("error when parsing: {0}")]
    ParseError(String),
}

pub type Result<T> = result::Result<T, Error>;
