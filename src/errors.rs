use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("Input length is invalid")]
    InvalidInputLength,

    #[error("Invalid value for Eta")]
    InvalidEta,
}
