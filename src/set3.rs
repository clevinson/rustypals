#[allow(dead_code)]
use crate::cipher::aes::CipherError;

#[test]
fn exercise_17() {
    use crate::cipher::aes::cbc_encrypt;
    use crate::crack::aes::{crack_aes_cbc, deterministic_key};
    use crate::utils::read_and_decode_base64_lines;
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let key = deterministic_key(16, 999);
    let iv = rng.gen::<[u8; 16]>();

    for line in read_and_decode_base64_lines("data/17.txt").unwrap() {
        let cyphertext = cbc_encrypt(&key, &iv, &line).unwrap();

        let bytes = crack_aes_cbc(&iv, &cyphertext, valid_padding_oracle).unwrap();

        assert_eq!(
            String::from_utf8_lossy(&bytes),
            String::from_utf8_lossy(&line)
        )
    }
}

fn valid_padding_oracle(iv: &[u8], cyphertext: &[u8]) -> Result<bool, CipherError> {
    use crate::cipher::aes::cbc_decrypt;
    use crate::crack::aes::deterministic_key;

    let key = deterministic_key(16, 999);

    match cbc_decrypt(&key, iv, cyphertext) {
        Ok(_) => Ok(true),
        Err(CipherError::InvalidPadding(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

#[test]
fn exercise_18() {
    use crate::cipher::aes::ctr_cipher;
    let cyphertext =
        base64::decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
            .unwrap();

    let key = b"YELLOW SUBMARINE";

    let plaintext = ctr_cipher(key, 0u64, &cyphertext);

    assert_eq!(
        String::from_utf8_lossy(&plaintext),
        String::from("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")
    );
}

#[test]
fn exercise_19() {
    use crate::cipher::aes::ctr_cipher;
    use crate::crack::aes::deterministic_key;
    use crate::utils::{read_and_decode_base64_lines, ByteArray};
    use std::cmp;

    fn get_plaintexts_from_guess(
        cyphertexts: Vec<Vec<u8>>,
        guess_idx: usize,
        guess: &[u8],
    ) -> Vec<String> {
        let partial_key: Vec<u8> = guess
            .iter()
            .enumerate()
            .map(|(i, c)| c ^ cyphertexts[guess_idx][i])
            .collect();

        cyphertexts
            .iter()
            .map(|cyphertext| {
                let cmp_len = cmp::min(partial_key.len(), cyphertext.len());

                let ByteArray(res) = ByteArray(cyphertext[..cmp_len].to_vec())
                    ^ ByteArray(partial_key[..cmp_len].to_owned());

                String::from_utf8(res)
                    .unwrap_or("[ERROR]: Cannot decode decrypted bytes to UTF-8".to_string())
            })
            .collect::<Vec<String>>()
    }

    let key = deterministic_key(16, 1234);

    let cyphertexts = read_and_decode_base64_lines("data/19.txt")
        .unwrap()
        .iter()
        .map(|line| ctr_cipher(&key, 0u64, &line))
        .collect::<Vec<Vec<u8>>>();

    let plaintexts =
        get_plaintexts_from_guess(cyphertexts, 37, b"He, too, has been changed in his turn ");

    let yeates_poem = "I have met them at close of day\n\
                       Coming with vivid faces\n\
                       From counter or desk among grey\n\
                       Eighteenth-century houses.\n\
                       I have passed with a nod of the head\n\
                       Or polite meaningless words,\n\
                       Or have lingered awhile and said\n\
                       Polite meaningless words,\n\
                       And thought before I had done\n\
                       Of a mocking tale or a gibe\n\
                       To please a companion\n\
                       Around the fire at the club,\n\
                       Being certain that they and I\n\
                       But lived where motley is worn:\n\
                       All changed, changed utterly:\n\
                       A terrible beauty is born.\n\
                       That woman's days were spent\n\
                       In ignorant good will,\n\
                       Her nights in argument\n\
                       Until her voice grew shrill.\n\
                       What voice more sweet than hers\n\
                       When young and beautiful,\n\
                       She rode to harriers?\n\
                       This man had kept a school\n\
                       And rode our winged horse.\n\
                       This other his helper and friend\n\
                       Was coming into his force;\n\
                       He might have won fame in the end,\n\
                       So sensitive his nature seemed,\n\
                       So daring and sweet his thought.\n\
                       This other man I had dreamed\n\
                       A drunken, vain-glorious lout.\n\
                       He had done most bitter wrong\n\
                       To some who are near my heart,\n\
                       Yet I number him in the song;\n\
                       He, too, has resigned his part\n\
                       In the casual comedy;\n\
                       He, too, has been changed in his turn \n\
                       Transformed utterly:\n\
                       A terrible beauty is born.";

    assert_eq!(plaintexts.join("\n"), yeates_poem);
}

use crate::crack::xor::get_english_distance;
use failure::Error;

fn ctr_get_scored_guesses(cyphertexts: Vec<Vec<u8>>, idx: usize) {
    let mut scores: Vec<(char, f32)> = Vec::new();

    for guess in b' '..b'~' {
        if let Ok(score) = ctr_try_col(&cyphertexts, idx, &guess) {
            scores.push((guess as char, score));
        }
    }

    scores.sort_by(|(_, s1), (_, s2)| s1.partial_cmp(s2).unwrap());

    println!("{:#?}", scores);
}

fn ctr_try_col(cyphertexts: &[Vec<u8>], idx: usize, guess: &u8) -> Result<f32, Error> {
    let key_idx = cyphertexts[0][idx] ^ guess;
    let result: Vec<u8> = cyphertexts
        .iter()
        .map(|cyphertext| cyphertext[idx] ^ key_idx)
        .collect();

    Ok(get_english_distance(&String::from_utf8(result)?, None))
}

#[test]
fn exercise_20() {
    use crate::crack::xor::break_repeating_key_xor;
    use crate::crack::aes::deterministic_key;
    use crate::cipher::aes::ctr_cipher;
    use crate::utils::read_and_decode_base64_lines;
    use std::cmp;

    let key = deterministic_key(16, 1234);

    let cyphertexts = read_and_decode_base64_lines("data/20.txt")
        .unwrap()
        .iter()
        .map(|line| ctr_cipher(&key, 0u64, &line))
        .collect::<Vec<Vec<u8>>>();

    let min_length = cyphertexts
        .iter()
        .fold(None, |min, x| match min {
            None => Some(x.len()),
            Some(y) => Some(cmp::min(x.len(), y)),
        })
        .unwrap();

    let mega_text = cyphertexts
        .iter()
        .flat_map(|line| (&line[..min_length]).to_vec())
        .collect::<Vec<u8>>();

    let (_, decrypted_bytes) = break_repeating_key_xor(&mega_text).unwrap();


    let chunked = decrypted_bytes.chunks(min_length).collect::<Vec<&[u8]>>();

    let plaintext = chunked.into_iter().fold("".to_string(), |res, line| {
        let new_str = String::from_utf8(line.to_vec())
            .unwrap_or("[ERROR]: line cannot be decoded as UTF-8".to_string());
        format!("{}{}\n", res, new_str)
    });

    assert_eq!(&plaintext[..33], "I'm rated \"R\"...this is a warning");

}
