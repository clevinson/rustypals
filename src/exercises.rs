use crate::xor::*;

use hex;

#[allow(dead_code)]
pub fn ex2() {
    let bytes1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
    let bytes2 = hex::decode("686974207468652062756c6c277320657965").unwrap();

    let ByteArray(result) = ByteArray(bytes1) ^ ByteArray(bytes2);
    println!("The final result: {} ", hex::encode(result));
}

#[test]
fn exercise_3() {
    let hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    let encrypted_bytes = hex::decode(hex_str).unwrap();

    let result = break_single_char_xor(&encrypted_bytes).unwrap();

    assert_eq!(
        (result.key, result.decrypted_msg),
        ('X', String::from("Cooking MC's like a pound of bacon"))
    );
}

#[test]
fn exercise_4() {
    use std::cmp::Ordering::Equal;
    use std::fs::File;
    use std::io::prelude::*;
    use std::io::BufReader;

    let filename = "data/ex1-4.txt";

    match File::open(filename) {
        Err(_) => println!("[Error] Failed to read file: {}", filename),
        Ok(f) => {
            let file_reader = BufReader::new(f);

            let mut line_number = 0;

            let mut candidates = file_reader
                .lines()
                .filter_map(|line| {
                    line_number += 1;

                    let hex_str = line.unwrap();

                    let encrypted_bytes = hex::decode(&hex_str).unwrap();

                    break_single_char_xor(&encrypted_bytes)
                        .map(|scored_string| (hex_str, scored_string))
                })
                .collect::<Vec<(String, ScoredString)>>();

            println!(
                "Ranking {} strings_and_scores over {} hex encoded strings...",
                candidates.len(),
                line_number
            );

            candidates.sort_by(|s1, s2| s1.1.score.partial_cmp(&s2.1.score).unwrap_or(Equal));

            let winner = &candidates[0];

            assert_eq!(
                winner.0,
                (String::from("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"))
            );

            assert_eq!(winner.1.key, '5');
            assert_eq!(
                winner.1.decrypted_msg,
                String::from("Now that the party is jumping\n")
            );
        }
    }
}

#[test]
fn exercise_5() {
    let text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

    let key = "ICE";

    let encrypted_text = repeated_key_xor(&text.as_bytes().to_vec(), &key.as_bytes().to_vec());

    assert_eq!(hex::encode(encrypted_text), String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"));
}

#[test]
fn exercise_6() {
    use std::fs::File;
    use std::io::Read;
    let data = read_and_decode_base64_file("data/ex1-6.txt").unwrap();

    let message_bytes = break_repeating_key_xor(&data).unwrap().1;
    let message_str = String::from_utf8(message_bytes).unwrap();

    let mut file = File::open("data/ex1-6-cracked.txt").unwrap();
    let mut cracked_text = String::new();
    file.read_to_string(&mut cracked_text).unwrap();

    println!("Big file: {} bytes to be exact!", data.len());

    assert_eq!(message_str, cracked_text);
}

pub fn exercise_7() {
    println!("something");

}
