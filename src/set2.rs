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

#[test]
fn exercise_12() {
    use crate::crack::aes::{
        blackbox_ecb, crack_aes_ecb, detect_cipher_mode, guess_ecb_blocksize_up_to, CipherMode,
    };

    let block_size = guess_ecb_blocksize_up_to(30, blackbox_ecb).unwrap();
    assert_eq!(block_size, 16);

    let cipher_mode = detect_cipher_mode(blackbox_ecb).unwrap();
    assert_eq!(cipher_mode, CipherMode::ECB);

    let cracked_bytes = crack_aes_ecb(block_size, blackbox_ecb).unwrap();
    let cracked_msg = String::from_utf8(cracked_bytes).unwrap();

    let ex_12_poem =
        "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\n\
         The girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n";

    assert_eq!(ex_12_poem, cracked_msg);
}

#[test]
fn exercise_13() {
    use crate::user_profile::{UserProfile, UserRole, encryption_key};
    use crate::crack::user_profile::make_encrypted_admin;
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
