use crate::cipher::aes::{cbc_encrypt, ecb_encrypt, pkcs7_unpad, AES_BLOCK_SIZE, CipherError};
use itertools::Itertools;
use failure::{Error, format_err, ResultExt};
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

pub fn encryption_oracle_in_mode(mode: CipherMode, msg: &[u8]) -> Result<Vec<u8>, CipherError> {
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


pub fn detect_cipher_mode(
    blackbox: fn(&[u8]) -> Result<Vec<u8>, CipherError>,
) -> Result<CipherMode, CipherError> {
    let data = blackbox(&vec![0; 128])?;

    if prob_ecb_encrypted(&data) {
        Ok(CipherMode::ECB)
    } else {
        Ok(CipherMode::CBC)
    }
}

pub struct ECBBlackboxMetadata {
    pub blocksize: usize,
    pub prebuffer_len: usize,
    pub attacker_str_idx: usize,
}

// these Options could be better represented
// with proper Error Types in the future,
// illustrating why a given portion of the metadata
// calculation failed
pub fn get_ecb_blackbox_metadata(
    blackbox: impl Fn(&[u8]) -> Result<Vec<u8>, CipherError>,
) -> Option<ECBBlackboxMetadata> {
    fn get_first_varying_block_idx(
        blackbox: impl Fn(&[u8]) -> Result<Vec<u8>, CipherError>,
    ) -> Option<usize> {
        let bb_output = blackbox(&[b'0']).unwrap();
        let mut first_varying_block_idx = None;

        for b in b'A'..b'Z' {
            let alt_output = blackbox(&[b]).unwrap();

            for (i, val) in bb_output.iter().enumerate() {
                if val != &alt_output[i] {
                    // if we've found a match already, and the current
                    // match is the same index, we're done!
                    if let Some(prev_vbi) = first_varying_block_idx {
                        if i == prev_vbi {
                            return first_varying_block_idx;
                        }
                    }
                    // if we found a first match, or different
                    // match than previously, cycle through another
                    // input byte and validate an additional time that
                    // we get the same result
                    first_varying_block_idx = Some(i);
                    break;
                }
            }
        }
        None
    }

    // find what size of attacker_str will fill the rest of the
    // first varying block in cyphertext
    fn get_blockbreak_input_len(
        blackbox: impl Fn(&[u8]) -> Result<Vec<u8>, CipherError>,
        // vbi = index of the first varying block (in blackbox's output)
        vbi: usize,
    ) -> Option<usize> {
        let mut next_encrypted_data = blackbox(&[b'0']).unwrap();

        for input_len in 1..next_encrypted_data.len() - vbi - 1 {
            let encrypted_data = next_encrypted_data;
            let next_input_bytes = vec![b'0'; input_len + 1];
            next_encrypted_data = blackbox(&next_input_bytes).unwrap();

            if encrypted_data[vbi..vbi + input_len] == next_encrypted_data[vbi..vbi + input_len] {
                return Some(input_len);
            }
        }
        None
    }

    fn get_blocksize(
        blackbox: impl Fn(&[u8]) -> Result<Vec<u8>, CipherError>,
        vbi: usize,
        blockbreak_input_len: usize,
    ) -> Option<usize> {
        let mut input = vec![b'0'; blockbreak_input_len + 1];
        let output = blackbox(&input).unwrap();
        let mut varying_byte_idx = None;
        for b in b'A'..b'Z' {
            input.pop();
            input.push(b);
            let alt_output = blackbox(&input).unwrap();

            for (i, val) in output[vbi..].iter().enumerate() {
                if val != &alt_output[vbi + i] {
                    // if we've found a match already, and the current
                    // match is the same index, we're done!
                    if let Some(prev_idx) = varying_byte_idx {
                        if i == prev_idx {
                            return varying_byte_idx;
                        }
                    }
                    // if we found a first match, or different
                    // match than previously, cycle through another
                    // input byte and validate an additional time that
                    // we get the same result
                    varying_byte_idx = Some(i);
                    break;
                }
            }
        }
        None
    }

    let vbi = get_first_varying_block_idx(&blackbox)?;
    let blockbreak_input_len = get_blockbreak_input_len(&blackbox, vbi)?;
    let blocksize = get_blocksize(&blackbox, vbi, blockbreak_input_len)?;

    let attacker_str_idx = vbi + blocksize - blockbreak_input_len;
    Some(ECBBlackboxMetadata {
        attacker_str_idx,
        prebuffer_len: blockbreak_input_len % blocksize,
        blocksize,
    })
}

pub fn crack_aes_ecb(
    blackbox: impl Fn(&[u8]) -> Result<Vec<u8>, CipherError>,
) -> Result<Vec<u8>, CipherError> {
    // given:
    // - an attacker-controlled-string (prefix) of blocksize-1 length
    // - a blackbox ECB cipher
    // - a known encrypted string to check against (generated from the blackbox)
    //
    // this function iterates through a number
    // of bytes to try and find the one that produces the target string
    fn crack_next_byte(
        attacker_str_idx: &usize,
        prebuffer_len: &usize,
        prefix: &[u8],
        blackbox: impl Fn(&[u8]) -> Result<Vec<u8>, CipherError>,
        target: &[u8],
    ) -> Option<u8> {
        let mut prefix = prefix.to_vec();
        for b in 0..128 {
            prefix.push(b);
            let mut padded_prefix = vec![0; *prebuffer_len];
            padded_prefix.extend(&prefix);
            let encrypted_bytes = blackbox(&padded_prefix).unwrap();
            let first_block = encrypted_bytes[(attacker_str_idx + prebuffer_len)
                ..(attacker_str_idx + prebuffer_len + prefix.len())]
                .to_vec();
            if first_block == target {
                return Some(b);
            }
            prefix.pop();
        }
        None
    }

    fn get_block(data: &[u8], blocksize: usize, block_nr: usize) -> Vec<u8> {
        data[blocksize * block_nr..blocksize * (block_nr + 1)].to_vec()
    }

    let ECBBlackboxMetadata {
        attacker_str_idx,
        prebuffer_len,
        blocksize
    } = get_ecb_blackbox_metadata(&blackbox).expect("
        Should be able to calculate attacker string index, \
        prebuffer_len, and blocksize of blackbox encryption \
        function\
    ");

    let prefix_length = blocksize - 1;
    let mut prefixed_result: Vec<u8> = vec![0; prefix_length];
    let mut shift_width = prebuffer_len + prefix_length;

    loop {
        let shifter = vec![0; shift_width];
        let encrypted_bytes = blackbox(&shifter)?;
        shift_width = if shift_width == prebuffer_len {
            prebuffer_len + prefix_length
        } else {
            shift_width - 1
        };

        let block_nr =
            (attacker_str_idx + prebuffer_len + prefixed_result.len() - prefix_length) / blocksize;
        let target_block = get_block(&encrypted_bytes, blocksize, block_nr);

        // test_buffer is always the last {prefix_length} bytes
        // that we've successfully decrypted so far.
        // (or \x00 if we have not decrypted enough bytes yet)
        let test_buffer = prefixed_result[prefixed_result.len() - prefix_length..].to_vec();

        let next_byte = crack_next_byte(
            &attacker_str_idx,
            &prebuffer_len,
            &test_buffer,
            &blackbox,
            &target_block,
        )
        .expect("Should be able to find next byte");

        if next_byte == 1 {
            return Ok(prefixed_result[prefix_length..].to_vec());
        }

        prefixed_result.push(next_byte);
    }
}


pub fn crack_aes_cbc(
    iv: &[u8],
    cyphertext: &[u8],
    padding_oracle: fn(iv: &[u8], cyphertext: &[u8]) -> Result<bool,CipherError>,
) -> Result<Vec<u8>, Error> {

    fn crack_single_block(
        iv: &[u8],
        cyphertext: &[u8],
        padding_is_valid: fn(&[u8], &[u8]) -> Result<bool,CipherError>,
    ) -> Result<Vec<u8>, Error> {
        let mut iv = iv.to_owned();
        let mut found_chars: Vec<u8> = Vec::new();

        fn update_padding_slice(slice: &mut [u8], old_val: u8, new_val: u8) {
            for x in slice.iter_mut() {
                *x ^= old_val ^ new_val;
            }
        }

        'outer: for byte_index in (0..16).rev() {
            let padding_val = 16 - byte_index as u8;

            for byte_guess in 0..=255 {
                // first guess all bytes, excluding the
                // padding_val we are looking for
                if padding_val == byte_guess {
                    continue;
                }
                // xor byte by padding_val and our byte_guess
                iv[byte_index] ^= padding_val ^ byte_guess;
                if padding_is_valid(&iv, cyphertext)? {
                    found_chars.push(byte_guess);
                    update_padding_slice(&mut iv[byte_index..], padding_val, padding_val + 1);
                    continue 'outer;
                }
                // undo xor
                iv[byte_index] ^= padding_val ^ byte_guess;
            }
            // if we still haven't found anything yet
            // try without any bitflipping at all,
            // aka byte_guess == padding_val
            if padding_is_valid(&iv, cyphertext)? {
                found_chars.push(padding_val);
                update_padding_slice(&mut iv[byte_index..], padding_val, padding_val + 1);
            } else {
                return Err(format_err!("Could not guess byte for creating valid padding"));
            }
        }

        found_chars.reverse();

        Ok(found_chars)
    }

    let mut cyphertext_with_iv = iv.to_vec();

    cyphertext_with_iv.extend(cyphertext);

    let padded_bytes = cyphertext_with_iv
        .chunks(16)
        .collect::<Vec<_>>()
        .windows(2)
        .flat_map(|pair| crack_single_block(pair[0], pair[1], padding_oracle).unwrap())
        .collect::<Vec<u8>>();

    let plaintext = pkcs7_unpad(&padded_bytes, 16).context("Decrypted ciphertext, but resulting plaintext is not PKCS7 padded, maybe bad padding_oracle?")?;

    Ok(plaintext)
}
