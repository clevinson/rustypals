mod error;

use base64;
use bit_vec;
use error::AppError;
use hex;
use itertools::Itertools;
use std::cmp::Ordering::Equal;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
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

#[derive(Debug, Clone)]
struct ScoredString {
    decrypted_msg: String,
    key: char,
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
                    key: (key as char),
                })
        })
        .collect())
}

fn break_single_char_xor(cyphertext: &Vec<u8>) -> Result<ScoredString, AppError> {
    let mut scores: Vec<ScoredString> = (b' '..b'~' + 1)
        .filter_map(|key| {
            let decrypted_bytes = repeated_key_xor(cyphertext, &vec![key]);
            String::from_utf8(decrypted_bytes)
                .ok()
                .map(|decrypted_msg| ScoredString {
                    score: get_score(&decrypted_msg),
                    decrypted_msg: decrypted_msg,
                    key: (key as char),
                })
        })
        .collect();

    scores.sort_by(|s1, s2| s1.score.partial_cmp(&s2.score).unwrap_or(Equal));

    Ok(scores[0].clone())
}

#[allow(dead_code)]
fn ex4() {
    let filename = "data/ex1-4.txt";

    match File::open(filename) {
        Err(_) => println!("[Error] Failed to read file: {}", filename),
        Ok(f) => {
            let file_reader = BufReader::new(f);

            let mut strings_and_scores = Vec::new();

            let mut line_number = 0;

            for line in file_reader.lines() {
                line_number += 1;

                let hex_str = line.unwrap();

                match hex_msg_to_scored_strings(&hex_str) {
                    Ok(mut scores) => strings_and_scores.append(&mut scores),
                    Err(_) => println!(
                        "[Error] Failed to parse hex string \"{}\" at line {}",
                        hex_str, line_number
                    ),
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

#[allow(dead_code)]
fn ex5() {
    let text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

    let key = "ICE";

    let encrypted_text = repeated_key_xor(&text.as_bytes().to_vec(), &key.as_bytes().to_vec());

    println!("{}", hex::encode(encrypted_text));
}

fn read_base64_from_file(filename: &str) -> Result<Vec<u8>, AppError> {
    let f = File::open(filename)?;

    let file_reader = BufReader::new(f);

    let mut data = String::new();

    for line in file_reader.lines() {
        data.extend(line);
    }

    let bytes = base64::decode(&data)?;

    Ok(bytes)
}

fn hamming_distance(s1: Vec<u8>, s2: Vec<u8>) -> u32 {
    let ByteArray(xord_bytes) = ByteArray(s1) ^ ByteArray(s2);

    let bits = bit_vec::BitVec::from_bytes(xord_bytes.as_slice());

    bits.iter().fold(0, |acc, x| acc + (x as u32))
}

fn key_size_score(key_size: usize, data: &Vec<u8>) -> f32 {
    let sample_size_bytes = 16;

    let mut pair_scores = Vec::new();

    let mut num_combinations = 0;

    for (i, j) in (0..sample_size_bytes).tuple_combinations() {
        num_combinations += 1;
        let s1 = data[i * key_size..(i + 1) * key_size].to_vec();
        let s2 = data[j * key_size..(j + 1) * key_size].to_vec();

        pair_scores.push(hamming_distance(s1, s2));
    }

    (pair_scores.iter().sum::<u32>() as f32) / ((key_size * num_combinations) as f32)
}

fn find_key_size(data: &Vec<u8>, min_key_size: usize, max_key_size: usize) -> usize {
    let mut scorings = (min_key_size..max_key_size)
        .map(|ks| (ks, key_size_score(ks, &data)))
        .collect::<Vec<(usize, f32)>>();

    scorings.sort_by(|s1, s2| s1.1.partial_cmp(&s2.1).unwrap_or(Equal));

    scorings[0].0
}

fn break_repeating_key_xor(cyphertext: &Vec<u8>) -> Result<Vec<u8>, AppError> {
    let key_size = find_key_size(&cyphertext, 1, 50);

    // create a series of n transposed cyphertexts, where each new cyphertext
    // is encrypted with a single_char_xor, corresponding to the ith character
    // in the key
    let mut owned_cyphertext = cyphertext.clone();
    owned_cyphertext.reverse();
    let mut transposed_cyphertexts = vec![Vec::new(); key_size];
    'transposition: loop {
        for tc in &mut transposed_cyphertexts {
            match owned_cyphertext.pop() {
                Some(byte) => tc.push(byte),
                None => break 'transposition,
            }
        }
    }

    // for each transposed cyphertext, find the single char encyrption key
    let my_key = transposed_cyphertexts
        .iter()
        .map(|tc| break_single_char_xor(tc).map(|scored_string| scored_string.key))
        .collect::<Result<String, _>>()?;

    Ok(repeated_key_xor(cyphertext, &my_key.as_bytes().to_vec()))
}

#[allow(dead_code)]
fn ex6() -> Result<(), AppError> {
    let data = read_base64_from_file("data/ex1-6.txt")?;

    let message_bytes = break_repeating_key_xor(&data).unwrap();
    let message_str = String::from_utf8(message_bytes).unwrap();

    println!("Big file: {} bytes to be exact!", data.len());
    println!("Decrypted message:");
    println!("{}", message_str);

    Ok(())
}

fn main() -> Result<(), AppError> {
    //ex2();
    //ex3();
    //ex4();
    ex6()
}
