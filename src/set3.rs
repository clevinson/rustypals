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
