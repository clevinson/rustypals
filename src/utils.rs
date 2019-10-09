use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::ops::BitXor;
use crate::error::AppError;

#[derive(Debug, PartialEq)]
pub struct ByteArray(pub Vec<u8>);

impl BitXor for ByteArray {
    type Output = Self;

    fn bitxor(self, ByteArray(rhs): Self) -> Self::Output {
        let ByteArray(lhs) = self;
        if lhs.len() != rhs.len() {
            panic!("Cannot perform `^` (bitxor) on ByteArrays of different length")
        } else {
            let res = lhs.iter().zip(rhs.iter()).map(|(x, y)| (x ^ y)).collect();
            ByteArray(res)
        }
    }
}


pub fn read_and_decode_base64_file(filename: &str) -> Result<Vec<u8>, AppError> {
    let f = File::open(filename)?;

    let file_reader = BufReader::new(f);

    let mut data = String::new();

    for line in file_reader.lines() {
        data.extend(line);
    }

    let bytes = base64::decode(&data)?;

    Ok(bytes)
}
