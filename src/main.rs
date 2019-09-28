use hex;
use std::collections::HashMap;
use std::ops::BitXor;
use std::cmp::Ordering::Equal;

//  static ref ENGLISH_CHAR_FREQS: HashMap<char, f32> = vec![
//      ('E', 2.02),
//      ('T', 9.02),
//      ('A', 8.12),
//      ('O', 7.68),
//      ('I', 7.31),
//      ('N', 6.95),
//      ('S', 6.28),
//      ('R', 6.02),
//      ('H', 5.92),
//      ('D', 4.32),
//      ('L', 3.98),
//      ('U', 2.88),
//      ('C', 2.71),
//      ('M', 2.61),
//      ('F', 2.30),
//      ('Y', 2.11),
//      ('W', 2.09),
//      ('G', 2.03),
//      ('P', 1.82),
//      ('B', 1.49),
//      ('V', 1.11),
//      ('K', 0.69),
//      ('X', 0.17),
//      ('Q', 0.11),
//      ('J', 0.10),
//      ('Z', 0.07),
//  ].into_iter().collect();

fn char_freqs_ref(c: char) -> Option<f32> {
    match c {
        'E' => Some(2.02),
        'T' => Some(9.02),
        'A' => Some(8.12),
        'O' => Some(7.68),
        'I' => Some(7.31),
        'N' => Some(6.95),
        'S' => Some(6.28),
        'R' => Some(6.02),
        'H' => Some(5.92),
        'D' => Some(4.32),
        'L' => Some(3.98),
        'U' => Some(2.88),
        'C' => Some(2.71),
        'M' => Some(2.61),
        'F' => Some(2.30),
        'Y' => Some(2.11),
        'W' => Some(2.09),
        'G' => Some(2.03),
        'P' => Some(1.82),
        'B' => Some(1.49),
        'V' => Some(1.11),
        'K' => Some(0.69),
        'X' => Some(0.17),
        'Q' => Some(0.11),
        'J' => Some(0.10),
        'Z' => Some(0.07),
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
    let filtered_msg = msg
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect::<Vec<char>>();
    let counter = 100.0 / filtered_msg.len() as f32;
    let mut char_freqs = HashMap::new();

    for c in filtered_msg {
        let upcase_c = c.to_ascii_uppercase();
        match char_freqs.get_mut(&upcase_c) {
            Some(x) => {
                *x += counter;
            }
            None => {
                char_freqs.insert(upcase_c, counter);
            }
        }
    }

    return char_freqs;
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

#[allow(dead_code)]
fn ex3() {
    let encoded_bytes =
        hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
            .unwrap();

    let mut strings_and_scores: Vec<(String, char, f32)> = (b'A'..b'Z').map( |key| {
        let decrypted_bytes = repeated_key_xor(&encoded_bytes, &vec![key]);
        let decrypted_str = String::from_utf8(decrypted_bytes).unwrap();
        let score = get_score(&decrypted_str);

        (decrypted_str, key as char, score)
    }).collect();

    strings_and_scores.sort_by(|(_, _, s1), (_, _, s2)|
        s1.partial_cmp(s2).unwrap_or(Equal)
    );

    let winner = &strings_and_scores[0];

    println!( "Decrypted Message: \"{}\"", winner.0);
    println!( "Found with key: {}", winner.1);
}

fn main() {
    //ex2();
    ex3();
}
