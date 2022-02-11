use std::result;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("compile error: {0}")]
    Compile(String),
    #[error("system error: {0}")]
    System(i32),
}

pub type Result<T> = result::Result<T, Error>;
