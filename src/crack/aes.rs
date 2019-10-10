use crate::cipher::aes::{cbc_encrypt, ecb_encrypt, AES_BLOCK_SIZE};
use itertools::Itertools;
use openssl::error::ErrorStack;
use rand::prelude::StdRng;
use rand::Rng;
use rand::SeedableRng;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CipherMode {
    ECB,
    CBC,
}

fn random_key(key_size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    (0..key_size).map(|_| rng.gen::<u8>()).collect()
}

pub fn deterministic_key(key_size: usize, seed: u64) -> Vec<u8> {
    let mut rng: StdRng = SeedableRng::seed_from_u64(seed);

    (0..key_size).map(|_| rng.gen::<u8>()).collect()
}

pub fn encryption_oracle_in_mode(mode: CipherMode, msg: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let mut rng = rand::thread_rng();

    let key = random_key(16);

    let pre_bytes = (0..rng.gen_range(5, 11)).map(|_| rng.gen::<u8>()).collect();
    let mut post_bytes = (0..rng.gen_range(5, 11)).map(|_| rng.gen::<u8>()).collect();

    let mut data: Vec<u8> = pre_bytes;
    data.extend(msg);
    data.append(&mut post_bytes);

    match mode {
        CipherMode::ECB => ecb_encrypt(&key, &data),
        CipherMode::CBC => {
            let iv = rng.gen::<[u8; 16]>();
            cbc_encrypt(&key, &iv, &data)
        }
    }
}

pub fn prob_ecb_encrypted(data: &[u8]) -> bool {
    let blocks = data.chunks(AES_BLOCK_SIZE);
    let unique_blocks: Vec<&[u8]> = blocks.clone().unique().collect();

    unique_blocks.len() < blocks.len()
}

pub fn blackbox_ecb(prefix_bytes: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let key = deterministic_key(16, 23422);
    let msg_to_decode = base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
    let mut msg_with_prefix = prefix_bytes.to_owned();
    msg_with_prefix.extend(&msg_to_decode);
    ecb_encrypt(&key, &msg_with_prefix)
}

pub fn detect_cipher_mode(
    blackbox: fn(&[u8]) -> Result<Vec<u8>, ErrorStack>,
) -> Result<CipherMode, ErrorStack> {
    let data = blackbox(&vec![0; 128])?;

    if prob_ecb_encrypted(&data) {
        Ok(CipherMode::ECB)
    } else {
        Ok(CipherMode::CBC)
    }
}

pub fn guess_ecb_blocksize_up_to(
    n: usize,
    blackbox: fn(&[u8]) -> Result<Vec<u8>, ErrorStack>,
) -> Option<usize> {
    let mut prev_result: Vec<u8> = vec![0; n];

    for prefix_len in 1..n {
        let prefix = vec![b'A'; prefix_len];
        let encrypted_data = &blackbox(&prefix).unwrap()[0..prefix_len];

        if prev_result[..] == encrypted_data[0..prefix_len - 1] {
            return Some(prefix_len - 1);
        }

        prev_result = encrypted_data.to_owned();
    }

    return None;
}

pub fn crack_aes_ecb(
    blocksize: usize,
    blackbox: fn(&[u8]) -> Result<Vec<u8>, ErrorStack>,
) -> Result<Vec<u8>, ErrorStack> {
    // given:
    // - an attacker-controlled-string (prefix) of blocksize-1 length
    // - a blackbox ECB cipher
    // - a known encrypted string to check against (generated from the blackbox)
    //
    // this function iterates through a number
    // of bytes to try and find the one that produces the target string
    fn crack_next_byte(
        prefix: &[u8],
        blackbox: fn(&[u8]) -> Result<Vec<u8>, ErrorStack>,
        target: &[u8],
    ) -> Option<u8> {
        let mut prefix = prefix.to_vec();
        for b in 0..128 {
            prefix.push(b);
            let encrypted_bytes = blackbox(&prefix).unwrap();
            let first_block = encrypted_bytes[0..prefix.len()].to_vec();
            if first_block == target {
                return Some(b);
            }
            prefix.pop();
        }

        return None;
    }

    fn get_block(data: &[u8], blocksize: usize, block_nr: usize) -> Vec<u8> {
        data[blocksize * block_nr..blocksize * (block_nr + 1)].to_vec()
    }

    let prefix_length = blocksize - 1;
    let mut prefixed_result: Vec<u8> = vec![0; prefix_length];
    let mut shift_width = prefix_length;

    loop {
        let shifter = vec![0; shift_width];
        let encrypted_bytes = blackbox(&shifter)?;
        shift_width = if shift_width == 0 {
            prefix_length
        } else {
            shift_width - 1
        };

        let block_nr = (prefixed_result.len() - prefix_length) / blocksize;
        let target_block = get_block(&encrypted_bytes, blocksize, block_nr);

        // test_buffer is always the last {prefix_length} bytes
        // that we've successfully decrypted so far.
        // (or \x00 if we have not decrypted enough bytes yet)
        let test_buffer = prefixed_result[prefixed_result.len() - prefix_length..].to_vec();

        let next_byte = crack_next_byte(&test_buffer, blackbox, &target_block).unwrap();

        if next_byte == 1 {
            return Ok(prefixed_result[prefix_length..].to_vec());
        }

        prefixed_result.push(next_byte);
    }
}
