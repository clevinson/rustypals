use crate::utils::ByteArray;
use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, Mode};

pub const AES_BLOCK_SIZE: usize = 16;

#[derive(Fail, Debug, PartialEq, Eq)]
#[fail(display = "Invalid PKCS7 Padding")]
pub struct InvalidPaddingError;

#[derive(Fail, Debug)]
pub enum CipherError {
    #[fail(display = "{}", _0)]
    InvalidPadding(#[fail(cause)] InvalidPaddingError),
    #[fail(display = "{}", _0)]
    OpenSslError(#[fail(cause)] openssl::error::ErrorStack),
}

impl From<InvalidPaddingError> for CipherError {
    fn from(e: InvalidPaddingError) -> Self {
        CipherError::InvalidPadding(e)
    }
}

impl From<openssl::error::ErrorStack> for CipherError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        CipherError::OpenSslError(e)
    }
}


pub fn pkcs7_pad(bytes: &[u8], blocksize: usize) -> Vec<u8> {
    let pad_length = blocksize - (bytes.len() % blocksize);

    let mut pad = vec![pad_length as u8; pad_length];
    let mut result = bytes.to_vec();

    result.append(&mut pad);

    return result;
}

pub fn pkcs7_unpad(bytes: &[u8], blocksize: usize) -> Result<Vec<u8>, InvalidPaddingError> {
    // return none if bytes is not multiple of blocksize
    if !(bytes.len() % blocksize == 0 && bytes.len() != 0) {
        return Err(InvalidPaddingError);
    }

    let mut bytes = bytes.to_vec();

    let last_byte = *bytes.last().ok_or(InvalidPaddingError)? as usize;

    if !(last_byte > 0 && last_byte <= blocksize) {
        return Err(InvalidPaddingError);
    }

    let pad_slice = bytes.split_off(bytes.len() - last_byte);

    if pad_slice == vec![last_byte as u8; last_byte] {
        return Ok(bytes);
    } else {
        return Err(InvalidPaddingError);
    }
}

fn aes_128_ecb(mode: Mode, key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let cipher = Cipher::aes_128_ecb(); 
    let mut c = Crypter::new(cipher, mode, key, None)?;
    c.pad(false);
    let mut out = vec![0; data.len() + cipher.block_size()];
    let count = c.update(data, &mut out)?;
    let rest = c.finalize(&mut out[count..])?;
    out.truncate(count + rest);
    Ok(out)
}

pub fn ecb_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherError> {
    let padded_data = pkcs7_pad(data, AES_BLOCK_SIZE);
    aes_128_ecb(Mode::Encrypt, key, &padded_data).map_err(CipherError::from)
}

pub fn ecb_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherError> {
    let padded_result = aes_128_ecb(Mode::Decrypt, key, data)?;
    let result = pkcs7_unpad(&padded_result, AES_BLOCK_SIZE)?;
    Ok(result)
}

pub fn cbc_encrypt(key: &[u8], iv: &[u8], msg: &[u8]) -> Result<Vec<u8>, CipherError> {
    let padded_msg = pkcs7_pad(msg, AES_BLOCK_SIZE);

    let mut prev_encrypted = iv.to_vec();
    let blocks = padded_msg.chunks(AES_BLOCK_SIZE);

    let mut encrypted_msg = Vec::with_capacity(padded_msg.len());

    for block in blocks {
        let ByteArray(to_encrypt) = ByteArray(prev_encrypted.to_vec()) ^ ByteArray(block.to_vec());

        let mut encrypted_block = aes_128_ecb(Mode::Encrypt, key, &to_encrypt)?;
        prev_encrypted = encrypted_block.clone();

        encrypted_msg.append(&mut encrypted_block);
    }

    return Ok(encrypted_msg);
}

pub fn cbc_decrypt(key: &[u8], iv: &[u8], msg: &[u8]) -> Result<Vec<u8>, CipherError> {
    let blocks = msg.chunks(AES_BLOCK_SIZE);

    let mut xor_vec = iv.to_vec();

    let mut decrypted_msg = Vec::new();

    for encrypted_block in blocks {
        let decrypted_block = aes_128_ecb(Mode::Decrypt, key, &encrypted_block)?;

        let ByteArray(mut xord_and_decrypted) =
            ByteArray(xor_vec.clone()) ^ ByteArray(decrypted_block);

        xor_vec = encrypted_block.to_vec();

        decrypted_msg.append(&mut xord_and_decrypted);
    }

    decrypted_msg = pkcs7_unpad(&decrypted_msg, 16)?;

    return Ok(decrypted_msg);
}
