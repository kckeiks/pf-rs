use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("error when building: {0}")]
    Build(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}
