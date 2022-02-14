use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("error when parsing: {0}")]
    ParseError(String),
}
