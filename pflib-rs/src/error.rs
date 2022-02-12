use std::result;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("error when building pf: {0}")]
    Load(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = result::Result<T, Error>;
