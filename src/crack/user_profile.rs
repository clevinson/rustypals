use crate::cipher::aes::pkcs7_pad;
use crate::user_profile::UserProfile;

pub fn make_encrypted_admin() -> Vec<u8> {
    // create an attack-string that can be inserted as an "email", with enough
    // buffer to make it start at a new block, and enough padding to make it
    // take up an entire block (deterministically)
    fn buffer_and_pad(msg: &str) -> String {
        // "email=" is the only text that is before our attack-string
        let buffer: String = vec!['0'; 16 - "email=".len()].into_iter().collect();
        let padded_msg = String::from_utf8(pkcs7_pad(msg.as_bytes(), 16)).unwrap();
        format!("{}{}", buffer, padded_msg)
    }

    // create an attack-string for finding an encrypt block corresponding to "user{padding}"
    let buffered_user_str = buffer_and_pad("user");
    let encrypted_user_bytes = &UserProfile::encrypted_profile_from(&buffered_user_str)[16..32];


    // create an attack-string for pushing the "role" value (e.g. "user")
    // to be on its own block with nothing but the value, and padding at the end
    let preexisting_text = "email=&uid=10&role=user";
    let isolated_role_buffer_length = (16 - (preexisting_text.len() % 16)) + "user".len();
    let isolated_role_buffer: String = vec!['0'; isolated_role_buffer_length].into_iter().collect();

    let num_blocks = ((preexisting_text.len() + isolated_role_buffer_length) / 16) + 1;

    let trailing_role_bytes =
        &UserProfile::encrypted_profile_from(&isolated_role_buffer)[16 * (num_blocks - 1)..];

    assert_eq!(encrypted_user_bytes, trailing_role_bytes);

    // Make an email that is exactly as long as necessary to pop out
    // the "role" value (e.g. "user") into its own block
    let my_email = "cjlevinson999999999@gmail.com";
    assert_eq!(my_email.len() % 16, isolated_role_buffer_length);
    let mut encrypted_profile = UserProfile::encrypted_profile_from(&my_email);

    // create an attack-string for finding an encrypted block corresponding to "admin{padding}"
    let buffered_admin_str = buffer_and_pad("admin");
    let encrypted_admin_bytes =
        UserProfile::encrypted_profile_from(&buffered_admin_str)[16..32].to_owned();

    // splice the final "user" block out, and replace it with our new "admin" block
    let splicing_index = 16 * ((preexisting_text.len() + my_email.len()) / 16);
    let spliced_bytes: Vec<u8> = encrypted_profile
        .splice(splicing_index.., encrypted_admin_bytes)
        .collect();

    assert_eq!(spliced_bytes, encrypted_user_bytes);

    encrypted_profile
}
