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
fn exercise_10() {
    use crate::cipher::aes;
    use crate::utils;

    use std::fs::File;
    use std::io::Read;

    fn test_cbc_encryption() {
        let msg = String::from("Testing that things thing works...");
        let key = b"YELLOW SUBMARINE";
        let encrypted_msg = aes::cbc_encrypt(key, &[0; 16], msg.as_bytes()).unwrap();
        let decrypted_msg = aes::cbc_decrypt(key, &[0; 16], &encrypted_msg).unwrap();
        assert_eq!(msg.as_bytes(), decrypted_msg.as_slice());
    }

    let cyphertext = utils::read_and_decode_base64_file("data/10.txt").unwrap();
    let key = b"YELLOW SUBMARINE";

    let decrypted_msg = aes::cbc_decrypt(key, &[0; 16], &cyphertext).unwrap();

    let mut file = File::open("data/funky-lyrics.txt").unwrap();
    let mut funky_lyrics = String::new();
    file.read_to_string(&mut funky_lyrics).unwrap();

    // Verify that CBC encyrption & decryption work as expected
    // (this function has internal assertions)
    test_cbc_encryption();

    assert_eq!(funky_lyrics, String::from_utf8(decrypted_msg).unwrap());
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
//
// blackbox encryption for exercise_12

// blackbox encryption for exercise_14

#[test]
fn exercise_12() {
    use crate::cipher::aes::ecb_encrypt;
    use crate::crack::aes::{
        crack_aes_ecb, detect_cipher_mode, deterministic_key, get_ecb_blackbox_metadata,
        CipherMode, ECBBlackboxMetadata,
    };
    use openssl::error::ErrorStack;

    pub fn blackbox_ecb(attacker_str: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let key = deterministic_key(16, 23422);
        let msg_to_decode = base64::decode("\
            Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaG\
            FpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0\
            IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
        let mut msg_with_attacker_str = attacker_str.to_owned();
        msg_with_attacker_str.extend(&msg_to_decode);
        ecb_encrypt(&key, &msg_with_attacker_str)
    }

    let ECBBlackboxMetadata { blocksize, .. } = get_ecb_blackbox_metadata(blackbox_ecb).unwrap();
    assert_eq!(blocksize, 16);

    let cipher_mode = detect_cipher_mode(blackbox_ecb).unwrap();
    assert_eq!(cipher_mode, CipherMode::ECB);

    let cracked_bytes = crack_aes_ecb(blackbox_ecb).unwrap();
    let cracked_msg = String::from_utf8(cracked_bytes).unwrap();

    let ex_12_poem =
        "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\n\
         The girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n";

    assert_eq!(ex_12_poem, cracked_msg);
}

#[test]
fn exercise_13() {
    use crate::crack::user_profile::make_encrypted_admin;
    use crate::user_profile::{encryption_key, UserProfile, UserRole};
    use std::str::FromStr;

    let input_str = "email=foobar@baz.com&uid=23&role=admin";
    let profile = UserProfile::from_str(input_str).unwrap();

    // verify that parsing of UserProfile from &str works as expected
    assert_eq!(
        profile,
        UserProfile {
            email: "foobar@baz.com".to_string(),
            uid: 23,
            role: UserRole::Admin
        }
    );

    // verify that serialization of UserProfile to String works as expected
    assert_eq!(profile.to_string(), input_str);

    let key = encryption_key();

    // verify that encryption & decryption of profiles work as expected
    let encrypted_profile = profile.encrypt(&key).unwrap();
    let decryped_profile = UserProfile::decrypt(&key, &encrypted_profile).unwrap();
    assert_eq!(profile, decryped_profile);

    // make me an admin!
    let encrypted_admin = make_encrypted_admin();
    let admin_profile = UserProfile::decrypt(&key, &encrypted_admin).unwrap();
    assert_eq!(admin_profile.role, UserRole::Admin);
}

#[test]
fn exercise_14() {
    use crate::cipher::aes::ecb_encrypt;
    use crate::crack::aes::{crack_aes_ecb, deterministic_key};
    use openssl::error::ErrorStack;
    use rand::prelude::StdRng;
    use rand::{Rng, SeedableRng};

    pub fn blackbox_ecb_with_prefix(attacker_bytes: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        const RAND_SEED: u64 = 211;
        let mut rng: StdRng = SeedableRng::seed_from_u64(RAND_SEED);

        let key = deterministic_key(16, RAND_SEED);
        let msg_to_decode = base64::decode("\
            Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjY\
            W4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQ\
            pEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();

        let mut msg_with_prefix: Vec<u8> =
            (0..rng.gen_range(5, 50)).map(|_| rng.gen::<u8>()).collect();

        msg_with_prefix.extend(attacker_bytes);
        msg_with_prefix.extend(msg_to_decode);
        ecb_encrypt(&key, &msg_with_prefix)
    }

    let cracked_bytes = crack_aes_ecb(blackbox_ecb_with_prefix).unwrap();
    let cracked_msg = String::from_utf8(cracked_bytes).unwrap();

    let ex_12_poem =
        "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\n\
         The girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n";

    assert_eq!(ex_12_poem, cracked_msg);
}

#[test]
fn exercise_15() {
    use crate::cipher::aes::{pkcs7_unpad, InvalidPaddingError};

    let str1 = b"ICE ICE BABY\x04\x04\x04\x04";
    assert_eq!(pkcs7_unpad(str1, 16), Ok(b"ICE ICE BABY".to_vec()));

    let str2 = b"ICE ICE BABY\x05\x05\x05\x05";
    assert_eq!(pkcs7_unpad(str2, 16), Err(InvalidPaddingError));

    let str3 = b"ICE ICE BABY\x01\x02\x03\x04";
    assert_eq!(pkcs7_unpad(str3, 16), Err(InvalidPaddingError));

    let str4 = vec![
        65, 65, 65, 65, 65, 65, 65, 65, 66, 66, 66, 66, 66, 66, 66, 0,
    ];
    assert_eq!(pkcs7_unpad(&str4, 16), Err(InvalidPaddingError));

    let str5 = vec![
        65, 65, 65, 65, 65, 65, 65, 65, 66, 66, 66, 66, 66, 66, 66, 66,
    ];
    assert_eq!(pkcs7_unpad(&str5, 16), Err(InvalidPaddingError));
}

#[test]
fn exercise_16() {
    use crate::cipher::aes::{cbc_decrypt, cbc_encrypt};
    use crate::crack::aes::deterministic_key;
    use rand::Rng;

    fn is_admin(key: &[u8], iv: &[u8], encrypted_str: &[u8]) -> bool {
        let decrypted_bytes =
            cbc_decrypt(key, iv, encrypted_str).expect("Should be able to decrypt cyphertext");
        let decrypted_str = String::from_utf8_lossy(&decrypted_bytes);

        decrypted_str
            .split(";")
            .map(|kv| {
                let kv_list: Vec<&str> = kv.splitn(2, "=").collect();
                (kv_list[0], kv_list[1])
            })
            .any(|tup| tup == ("admin", "true"))
    }

    fn make_user(input: &str) -> String {
        let escaped_input = input.replace(";", "%3B").replace("=", "%3D");
        format!(
            "comment1=cooking%20MCs;\
             userdata={};\
             comment2=%20like%20a%20pound%20of%20bacon",
            escaped_input
        )
    }

    let mut attacker_vec = vec![b'0'; 16];
    attacker_vec.extend(":admin<true".as_bytes());
    let attacker_str = String::from_utf8(attacker_vec).unwrap();

    let user_str = make_user(&attacker_str);

    let mut rng = rand::thread_rng();
    let key = deterministic_key(16, 999);
    let iv = rng.gen::<[u8; 16]>();

    let encrypted_user = cbc_encrypt(&key, &iv, &user_str.as_bytes()).unwrap();

    let bitflipped: Vec<u8> = encrypted_user
        .iter()
        .enumerate()
        .map(|(i, &val)| {
            // bitflip so the ':' and '<' chars in the plaintext become ';' and '='
            if i == 32 || i == 38 {
                val ^ 1
            } else {
                val
            }
        })
        .collect();

    assert_eq!(is_admin(&key, &iv, &bitflipped), true);
}
