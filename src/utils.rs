use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::ops::BitXor;
use failure::{Error, format_err};
use std::collections::HashMap;

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


pub fn read_and_decode_base64_file(filename: &str) -> Result<Vec<u8>, Error> {
    let f = File::open(filename)?;

    let file_reader = BufReader::new(f);

    let mut data = String::new();

    for line in file_reader.lines() {
        data.extend(line);
    }

    let bytes = base64::decode(&data)?;

    Ok(bytes)
}

pub fn read_and_decode_base64_lines(filename: &str) -> Result<Vec<Vec<u8>>, Error> {
    let f = File::open(filename)?;

    let file_reader = BufReader::new(f);

    let mut data = Vec::new();

    for line in file_reader.lines() {
        let bytes = base64::decode(&line?)?;
        data.push(bytes);
    }

    Ok(data)
}


fn load_char_table(filename: &str, count_col: &str) -> Result<HashMap<char, f32>, Error> {
    let f = File::open(filename)?;
    let file_reader = BufReader::new(f);
    let mut lines = file_reader.lines();

    let header = lines.next().unwrap().unwrap();
    let count_col_idx = header
        .split("\t")
        .position(|x| x == count_col)
        .ok_or(format_err!("Cannot find header column {}", count_col))?;

    let mut ref_table = lines
        .map(|line| {
            let raw_line = line.unwrap();
            let row: Vec<_> = raw_line.split("\t").collect();
            let c: char = row[0].chars().next().ok_or(format_err!(""))?;

            let val = row[count_col_idx].parse::<f32>()?;

            Ok((c, val))
        })
        .collect::<Result<HashMap<char, f32>, Error>>()?;

    let total_count: f32 = ref_table.values().sum();

    let ref_word_length = 4.7;
    let ws_factor = ref_word_length / (ref_word_length + 1.0);

    for val in ref_table.values_mut() {
        *val = ws_factor * *val / total_count;
    }

    ref_table.insert(' ', 1.0 / (ref_word_length + 1.0));

    Ok(ref_table)
}
