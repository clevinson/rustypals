use crate::utils::ByteArray;


pub fn single_char_xor(bytes: &[u8], key: u8) -> Vec<u8> {
    let repeated_key = vec![key; bytes.len()];

    let ByteArray(xord_bytes) = ByteArray(bytes.to_owned()) ^ ByteArray(repeated_key);

    return xord_bytes;
}

pub fn repeated_key_xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
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
