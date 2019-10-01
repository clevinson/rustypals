use hex;
use std::cmp::Ordering::Equal;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader};
use std::ops::BitXor;


fn char_freqs_ref(c: char) -> Option<f32> {
    let ref_word_length = 4.7;
    let ws_factor = ref_word_length / (ref_word_length + 1.0);

    match c {
        ' ' => Some(100.0 / (ref_word_length + 1.0)),
        'E' => Some(12.02 * ws_factor),
        'T' => Some(9.02 * ws_factor),
        'A' => Some(8.12 * ws_factor),
        'O' => Some(7.68 * ws_factor),
        'I' => Some(7.31 * ws_factor),
        'N' => Some(6.95 * ws_factor),
        'S' => Some(6.28 * ws_factor),
        'R' => Some(6.02 * ws_factor),
        'H' => Some(5.92 * ws_factor),
        'D' => Some(4.32 * ws_factor),
        'L' => Some(3.98 * ws_factor),
        'U' => Some(2.88 * ws_factor),
        'C' => Some(2.71 * ws_factor),
        'M' => Some(2.61 * ws_factor),
        'F' => Some(2.30 * ws_factor),
        'Y' => Some(2.11 * ws_factor),
        'W' => Some(2.09 * ws_factor),
        'G' => Some(2.03 * ws_factor),
        'P' => Some(1.82 * ws_factor),
        'B' => Some(1.49 * ws_factor),
        'V' => Some(1.11 * ws_factor),
        'K' => Some(0.69 * ws_factor),
        'X' => Some(0.17 * ws_factor),
        'Q' => Some(0.11 * ws_factor),
        'J' => Some(0.10 * ws_factor),
        'Z' => Some(0.07 * ws_factor),
        _ => None,
    }
}

#[derive(Debug, PartialEq)]
struct ByteArray(Vec<u8>);

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

fn repeated_key_xor(bytes: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let key_length = key.len();
    let bytes_length = bytes.len();

    let key_repeat = bytes_length / key_length;
    let key_remainder = bytes_length % key_length;

    let mut repeated_key = Vec::with_capacity(bytes_length);

    for _ in 0..key_repeat {
        repeated_key.extend(key);
    }

    repeated_key.extend(&key[0..key_remainder]);

    let ByteArray(xord_bytes) = ByteArray(bytes.to_owned()) ^ ByteArray(repeated_key.to_owned());

    return xord_bytes;
}

fn get_char_freqs(msg: &String) -> HashMap<char, f32> {
    let increment_size = 100.0 / msg.len() as f32;
    let mut char_freqs = HashMap::new();

    for c in msg.chars() {
        let upcase_c = c.to_ascii_uppercase();
        let counter = char_freqs.entry(upcase_c).or_insert(0.0);
        *counter += increment_size;
    }

    char_freqs
}

fn get_score(msg: &String) -> f32 {
    let char_freqs = get_char_freqs(msg);

    let summed_scores: f32 = char_freqs
        .iter()
        .map(|(&c, score)| (char_freqs_ref(c).unwrap_or(0.0) - score).powi(2))
        .sum();

    return summed_scores.sqrt();
}

#[allow(dead_code)]
fn ex2() {
    let bytes1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
    let bytes2 = hex::decode("686974207468652062756c6c277320657965").unwrap();

    let ByteArray(result) = ByteArray(bytes1) ^ ByteArray(bytes2);
    println!("The final result: {} ", hex::encode(result));
}

#[derive(Debug)]
struct ScoredString {
    decrypted_msg: String,
    key: String,
    score: f32,
}

#[allow(dead_code)]
fn ex3() {
    let hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    let mut strings_and_scores = hex_msg_to_scored_strings(&hex_str).unwrap();

    strings_and_scores.sort_by(|s1, s2| s1.score.partial_cmp(&s2.score).unwrap_or(Equal));

    let winner = &strings_and_scores[0];

    println!("Decrypted Message: \"{}\"", winner.decrypted_msg);
    println!("Found with key: {}", winner.key);
    println!("{:#?}", &strings_and_scores[0..6]);
}

fn hex_msg_to_scored_strings(hex_msg: &str) -> Result<Vec<ScoredString>, hex::FromHexError> {
    let encrypted_bytes = hex::decode(hex_msg)?;

    // Map over all characters (potential keys)
    Ok((b' '..b'~' + 1)
        .filter_map(|key| {
            let decrypted_bytes = repeated_key_xor(&encrypted_bytes, &vec![key]);
            String::from_utf8(decrypted_bytes)
                .ok()
                .map(|decrypted_msg| ScoredString {
                    score: get_score(&decrypted_msg),
                    decrypted_msg: decrypted_msg,
                    key: (key as char).to_string(),
                })
        })
        .collect())
}

fn ex4() {
    let filename = "data/ex1-4.txt";

    match File::open(filename) {
        Err(_) => {
            println!("Could not read file: {}\nCheck that it exists?", filename);
        },
        Ok(f) => {

            let file_reader = BufReader::new(f);

            let mut strings_and_scores = Vec::new();

            let mut line_number= 0;

            for line in file_reader.lines() {
                line_number += 1;

                let hex_str = line.unwrap();

                match hex_msg_to_scored_strings(&hex_str) {
                    Ok(mut scores) => strings_and_scores.append(&mut scores),
                    Err(_) => {
                        println!("[Error] Failed to parse hex string \"{}\" at line {}", hex_str, line_number)
                    }
                }
            }

            println!(
                "Ranking {} strings_and_scores over {} hex encoded strings...",
                strings_and_scores.len(),
                line_number
            );

            strings_and_scores.sort_by(|s1, s2| s1.score.partial_cmp(&s2.score).unwrap_or(Equal));

            let winner = &strings_and_scores[0];

            println!("Found winner!");
            println!("Decrypted Message: {:?}", winner.decrypted_msg);
            println!("Encrypted with key: \"{}\"", winner.key);

        }
    }

}

fn main() {
    //ex2();
    //ex3();
    ex4();
}
