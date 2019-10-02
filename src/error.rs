use std::io;
use hex;
use base64;

#[derive(Debug)]
pub enum AppError {
    IoError(io::Error),
    HexError(hex::FromHexError),
    Base64Error(base64::DecodeError),
    FromUtf8Error(std::string::FromUtf8Error),
}

impl From<std::string::FromUtf8Error> for AppError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        AppError::FromUtf8Error(error)
    }
}

impl From<io::Error> for AppError {
    fn from(error: io::Error) -> Self {
        AppError::IoError(error)
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(error: base64::DecodeError) -> Self {
        AppError::Base64Error(error)
    }
}

impl From<hex::FromHexError> for AppError {
    fn from(error: hex::FromHexError) -> Self {
        AppError::HexError(error)
    }
}
