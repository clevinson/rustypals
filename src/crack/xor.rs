use crate::cipher::xor::{repeated_key_xor, single_char_xor};
use crate::utils::ByteArray;
use bit_vec::BitVec;
use failure::{format_err, Error, ResultExt};
use itertools::Itertools;
use std::cmp::Ordering::Equal;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ScoredString {
    pub decrypted_msg: String,
    pub key: char,
    pub score: f32,
}

pub fn get_english_distance(msg: &str) -> f32 {
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

    fn get_char_freqs(msg: &str) -> HashMap<char, f32> {
        let increment_size = 100.0 / msg.len() as f32;
        let mut char_freqs = HashMap::new();
        for c in msg.chars() {
            let upcase_c = c.to_ascii_uppercase();
            let counter = char_freqs.entry(upcase_c).or_insert(0.0);
            *counter += increment_size;
        }
        char_freqs
    }

    let char_freqs = get_char_freqs(msg);

    let summed_scores: f32 = char_freqs
        .iter()
        .map(|(&c, score)| (char_freqs_ref(c).unwrap_or(0.0) - score).powi(2))
        .sum();

    return summed_scores.sqrt();
}

pub fn break_single_char_xor(cyphertext: &[u8]) -> Result<ScoredString, Error> {
    let start_byte = b' ';
    let end_byte = b'~';
    let mut scores: Vec<ScoredString> = (start_byte..=end_byte)
        .filter_map(|key| {
            let decrypted_bytes = single_char_xor(cyphertext, key);
            String::from_utf8(decrypted_bytes)
                .ok()
                .map(|decrypted_msg| ScoredString {
                    score: get_english_distance(&decrypted_msg),
                    decrypted_msg: decrypted_msg,
                    key: (key as char),
                })
        })
        .collect();

    scores.sort_by(|s1, s2| s1.score.partial_cmp(&s2.score).unwrap_or(Equal));

    if scores.len() == 0 {
        return Err(format_err!("Error breaking single_char_xor: Failed to find valid UTF8 plaintext with any key in {:?}..{:?}", start_byte as char, end_byte as char));
    } else {
        return Ok(scores[0].clone());
    }
}

fn key_size_score(key_size: usize, data: &[u8]) -> f32 {
    fn hamming_distance(s1: &[u8], s2: &[u8]) -> u32 {
        let ByteArray(xord_bytes) = ByteArray(s1.to_vec()) ^ ByteArray(s2.to_vec());

        let bits = BitVec::from_bytes(xord_bytes.as_slice());

        bits.iter().fold(0, |acc, x| acc + (x as u32))
    }

    let sample_size_bytes = 16;

    let mut pair_scores = Vec::new();

    let mut num_combinations = 0;

    for (i, j) in (0..sample_size_bytes).tuple_combinations() {
        num_combinations += 1;
        let s1 = &data[i * key_size..(i + 1) * key_size];
        let s2 = &data[j * key_size..(j + 1) * key_size];

        pair_scores.push(hamming_distance(s1, s2));
    }

    (pair_scores.iter().sum::<u32>() as f32) / ((key_size * num_combinations) as f32)
}

fn find_key_size(data: &[u8], min_key_size: usize, max_key_size: usize) -> usize {
    let mut scorings = (min_key_size..max_key_size)
        .map(|ks| (ks, key_size_score(ks, &data)))
        .collect::<Vec<(usize, f32)>>();

    scorings.sort_by(|s1, s2| s1.1.partial_cmp(&s2.1).unwrap_or(Equal));

    scorings[0].0
}

pub fn break_repeating_key_xor(cyphertext: &[u8]) -> Result<(String, Vec<u8>), Error> {
    let key_size = find_key_size(&cyphertext, 1, 50);

    // create a series of n transposed cyphertexts, where each new cyphertext
    // is encrypted with a single_char_xor, corresponding to the ith character
    // in the key
    let mut owned_cyphertext = cyphertext.to_vec();
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
    let key = transposed_cyphertexts
        .iter()
        .map(|tc| {
            break_single_char_xor(tc)
                .map(|result| result.key)
                .context(format!(
                    "Cannot decrypt {:?} with break_single_char_xor",
                    tc
                ))
        })
        .collect::<Result<String,_>>()?;

    let decrypted_msg = repeated_key_xor(cyphertext, &key.as_bytes().to_vec());

    Ok((key, decrypted_msg))
}
