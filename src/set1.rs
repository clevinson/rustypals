use hex;

#[test]
pub fn exercise_2() {
    use crate::utils::ByteArray;
    let bytes1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
    let bytes2 = hex::decode("686974207468652062756c6c277320657965").unwrap();

    let ByteArray(result) = ByteArray(bytes1) ^ ByteArray(bytes2);
    assert_eq!("746865206b696420646f6e277420706c6179", hex::encode(result));
}

#[test]
fn exercise_3() {
    use crate::crack::xor::break_single_char_xor;

    let hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    let encrypted_bytes = hex::decode(hex_str).unwrap();

    let result = break_single_char_xor(&encrypted_bytes, None).unwrap();

    assert_eq!(
        (result.key as char, result.decrypted_msg),
        ('X', String::from("Cooking MC's like a pound of bacon"))
    );
}

#[test]
fn exercise_4() {
    use crate::crack::xor::{break_single_char_xor, ScoredString};
    use std::cmp::Ordering::Equal;
    use std::fs::File;
    use std::io::prelude::*;
    use std::io::BufReader;

    let f = File::open("data/4.txt").unwrap();
    let file_reader = BufReader::new(f);

    let mut line_number = 0;

    let mut candidates = file_reader
        .lines()
        .filter_map(|line| {
            line_number += 1;

            let hex_str = line.unwrap();

            let encrypted_bytes = hex::decode(&hex_str).unwrap();

            break_single_char_xor(&encrypted_bytes, None).map(|scored_string| (hex_str, scored_string)).ok()
        })
        .collect::<Vec<(String, ScoredString)>>();

    candidates.sort_by(|s1, s2| s1.1.score.partial_cmp(&s2.1.score).unwrap_or(Equal));

    let winner = &candidates[0];

    assert_eq!(
        winner.0,
        (String::from("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"))
    );

    assert_eq!(winner.1.key as char, '5');
    assert_eq!(
        winner.1.decrypted_msg,
        String::from("Now that the party is jumping\n")
    );
}

#[test]
fn exercise_5() {
    use crate::cipher::xor::repeated_key_xor;
    let text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

    let key = "ICE";

    let encrypted_text = repeated_key_xor(&text.as_bytes().to_vec(), &key.as_bytes().to_vec());

    assert_eq!(hex::encode(encrypted_text), String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"));
}

#[test]
fn exercise_6() {
    use crate::crack::xor::break_repeating_key_xor;
    use crate::utils::read_and_decode_base64_file;
    use std::fs::File;
    use std::io::Read;
    let data = read_and_decode_base64_file("data/6.txt").unwrap();

    let message_bytes = break_repeating_key_xor(&data).unwrap().1;
    let message_str = String::from_utf8(message_bytes).unwrap();

    let mut file = File::open("data/funky-lyrics.txt").unwrap();
    let mut cracked_text = String::new();
    file.read_to_string(&mut cracked_text).unwrap();

    assert_eq!(message_str, cracked_text);
}

#[test]
fn exercise_7() {
    use crate::cipher::aes;
    use crate::utils::read_and_decode_base64_file;
    use std::fs::File;
    use std::io::Read;

    let ciphertext = read_and_decode_base64_file("data/7.txt").unwrap();

    let decrypted_bytes = aes::ecb_decrypt(b"YELLOW SUBMARINE", &ciphertext).unwrap();

    let mut file = File::open("data/funky-lyrics.txt").unwrap();
    let mut cracked_text = String::new();
    file.read_to_string(&mut cracked_text).unwrap();

    assert_eq!(String::from_utf8(decrypted_bytes).unwrap(), cracked_text);
}

#[test]
fn exercise_8() {
    use crate::crack::aes;
    use std::fs::File;
    use std::io::prelude::*;
    use std::io::BufReader;
    let filename = "data/8.txt";

    let f = File::open(filename).unwrap();

    let br = BufReader::new(f);

    let mut line_number = 0;

    let candidates: Vec<Vec<u8>> = br
        .lines()
        .filter_map(|line| {
            line_number += 1;

            let hex_str = line.unwrap();

            let encrypted_bytes = hex::decode(&hex_str).unwrap();

            if aes::prob_ecb_encrypted(&encrypted_bytes) {
                return Some(encrypted_bytes);
            } else {
                return None;
            }
        })
        .collect();

    assert_eq!(
        hex::encode(&candidates[0]),
        String::from("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")
    );
}
