use std::io;
use hex;
use base64;
use std::marker::Send;
use std::any::Any;
use std::boxed::Box;

#[derive(Debug)]
pub enum AppError {
    IoError(io::Error),
    HexError(hex::FromHexError),
    Base64Error(base64::DecodeError),
    FromUtf8Error(std::string::FromUtf8Error),
    BoxedError(Box<dyn Any + Send>),
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

impl From<Box<dyn Any + Send>> for AppError {
    fn from(error: Box<dyn Any + Send>) -> Self {
        AppError::BoxedError(error)
    }
}
