use openssl::error::ErrorStack;

#[test]
fn exercise_9() {
    use super::cipher::aes;

    let msg = String::from("YELLOW SUBMARINE");
    let padded_msg = aes::pkcs7_pad(&msg.as_bytes(), 20);

    let padded_str = String::from_utf8(padded_msg).unwrap();

    assert_eq!(
        padded_str,
        String::from("YELLOW SUBMARINE\u{4}\u{4}\u{4}\u{4}")
    );
}

#[test]
fn test_cbc_encryption() {
    use super::cipher::aes;

    let msg = String::from("Testing that things thing works...");
    let key = b"YELLOW SUBMARINE";

    let encrypted_msg = aes::cbc_encrypt(key, &[0; 16], msg.as_bytes()).unwrap();

    let decrypted_msg = aes::cbc_decrypt(key, &[0; 16], &encrypted_msg).unwrap();

    assert_eq!(msg.as_bytes(), decrypted_msg.as_slice());
}

#[test]
fn exercise_10() {
    use crate::cipher::aes;
    use crate::utils;

    use std::fs::File;
    use std::io::Read;

    let cyphertext = utils::read_and_decode_base64_file("data/10.txt").unwrap();
    let key = b"YELLOW SUBMARINE";

    let decrypted_msg = aes::cbc_decrypt(key, &[0; 16], &cyphertext).unwrap();

    let mut file = File::open("data/funky-lyrics.txt").unwrap();
    let mut funky_lyrics = String::new();
    file.read_to_string(&mut funky_lyrics).unwrap();

    assert_eq!(funky_lyrics, String::from_utf8(decrypted_msg).unwrap());
}

pub fn test_exercise() {
    println!("run da tests!");
}

#[test]
fn exercise_11() {
    use crate::crack::aes::{detect_cipher_mode, encryption_oracle_in_mode, CipherMode};

    let prob_ecb =
        detect_cipher_mode(|data| encryption_oracle_in_mode(CipherMode::ECB, data)).unwrap();
    let prob_cbc =
        detect_cipher_mode(|data| encryption_oracle_in_mode(CipherMode::CBC, data)).unwrap();

    assert_eq!(prob_ecb, CipherMode::ECB);
    assert_eq!(prob_cbc, CipherMode::CBC);
}

#[test]
fn exercise_12() {
    use crate::crack::aes::{blackbox_ecb, detect_cipher_mode, guess_ecb_blocksize_up_to};

    let block_size = guess_ecb_blocksize_up_to(30, blackbox_ecb).unwrap();
    println!("Guessing blocksize of: {:?}", block_size);
    let cipher_mode = detect_cipher_mode(blackbox_ecb).unwrap();
    println!("Guessing cipher mode of: {:?}", cipher_mode);
    let cracked_msg = String::from_utf8(crack_aes_ecb(block_size, blackbox_ecb).unwrap()).unwrap();
    println!("    Cracked the Code!");
    println!("    =================");
    println!("     =============== ");
    println!("      =============  ");
    println!("       ===========   ");
    println!("       ===========   ");
    println!("        =========    ");
    println!("         =======     ");
    println!("         =======     ");
    println!("         =======     ");
    println!("          =====      ");
    println!("          =====      ");
    println!("           ===       ");
    println!("           ===       ");
    println!("           ===       ");
    println!("            =        ");
    println!("            =        ");
    println!("            =        ");
    println!("            =        ");
    println!("            v        ");
    println!("");
    println!("");
    println!("{}", cracked_msg);

    let ex_12_poem = "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\n\
        The girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n";

    assert_eq!(ex_12_poem, cracked_msg);
}

fn crack_aes_ecb(
    blocksize: usize,
    blackbox: fn(&[u8]) -> Result<Vec<u8>, ErrorStack>,
) -> Result<Vec<u8>, ErrorStack> {
    let mut collected_result: Vec<u8> = Vec::new();

    loop {
        let block_offset = collected_result.len() / blocksize;
        let prefix_length = blocksize - 1 - (collected_result.len() % blocksize);
        let prefix = vec![0; prefix_length];

        let encrypted_bytes = blackbox(&prefix)?;
        let encrypted_block =
            encrypted_bytes[blocksize * block_offset..blocksize * (block_offset + 1)].to_vec();

        let dict_prefix = if block_offset == 0 {
            let mut dp = prefix.clone();
            dp.extend(&collected_result);
            dp
        } else {
            let start_index = blocksize * block_offset - prefix_length;
            collected_result[start_index..].to_vec()
        };

        let dict = get_crack_block_dict(&dict_prefix, blackbox);

        let next_byte = dict.get(&encrypted_block).cloned().unwrap();

        if next_byte == 1 {
            return Ok(collected_result);
        }

        collected_result.push(next_byte);
    }
}

use std::collections::HashMap;

fn get_crack_block_dict(
    prefix: &[u8],
    blackbox: fn(&[u8]) -> Result<Vec<u8>, ErrorStack>,
) -> HashMap<Vec<u8>, u8> {
    let mut prefix = prefix.to_vec();

    let mut dict: HashMap<Vec<u8>, u8> = HashMap::new();

    for b in 0..128 {
        prefix.push(b);

        let encrypted_bytes = blackbox(&prefix).unwrap();

        let first_block = encrypted_bytes[0..prefix.len()].to_vec();

        dict.insert(first_block, b);
        prefix.pop();
    }

    dict
}
