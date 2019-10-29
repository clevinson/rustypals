use crate::cipher::aes::{ecb_decrypt, ecb_encrypt, CipherError};
use crate::crack::aes::deterministic_key;
use std::error;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq)]
pub struct UserProfile {
    pub email: String,
    pub uid: u8,
    pub role: UserRole,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UserRole {
    Admin,
    User,
}

pub fn encryption_key() -> Vec<u8> {
    deterministic_key(16, 8889)
}

impl UserProfile {
    pub fn to_string(&self) -> String {
        [
            ["email", &self.email].join("="),
            ["uid", &self.uid.to_string()].join("="),
            [
                "role",
                match self.role {
                    UserRole::Admin => "admin",
                    UserRole::User => "user",
                },
            ]
            .join("="),
        ]
        .join("&")
    }

    pub fn encrypt(&self, aes_key: &[u8]) -> Result<Vec<u8>, CipherError> {
        let data = self.to_string();
        ecb_encrypt(aes_key, data.as_bytes())
    }

    pub fn decrypt(aes_key: &[u8], data: &[u8]) -> Option<UserProfile> {
        ecb_decrypt(aes_key, data)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|up_string| up_string.parse::<UserProfile>().ok())
    }

    pub fn profile_for(email: &str) -> UserProfile {
        UserProfile {
            email: email.replace(&['&', '='][..], ""),
            uid: 10,
            role: UserRole::User,
        }
    }

    pub fn encrypted_profile_from(email: &str) -> Vec<u8> {
        let user = UserProfile {
            email: email.replace(&['&', '='][..], ""),
            uid: 10,
            role: UserRole::User,
        };
        user.encrypt(&encryption_key()).unwrap()
    }
}

#[derive(Debug)]
pub struct ParseUserProfileError(String);
// should this be str instead of String?
// if i replace with str, i get "FromStr doesn't have
// known size at compiletime" !!!

impl fmt::Display for ParseUserProfileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ParseUserProfileError(bad_string) = self;

        write!(
            f,
            "Unable to parse UserProfile from string: {:?}",
            bad_string
        )
    }
}

// This is important for other errors to wrap this one.
impl error::Error for ParseUserProfileError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

impl FromStr for UserProfile {
    type Err = ParseUserProfileError;

    fn from_str(input_str: &str) -> Result<Self, Self::Err> {
        let terms = input_str
            .split("&")
            .map(|term| term.splitn(2, "=").collect())
            .collect::<Vec<Vec<_>>>();

        let email = terms
            .iter()
            .find(|t| t[0] == "email")
            .and_then(|t| t.get(1))
            .ok_or(ParseUserProfileError(input_str.to_owned()))?
            .to_string();
        let uid = terms
            .iter()
            .find(|t| t[0] == "uid")
            .and_then(|t| t.get(1))
            .and_then(|val| val.parse::<u8>().ok())
            .ok_or(ParseUserProfileError(input_str.to_owned()))?;
        let role = terms
            .iter()
            .find(|t| t[0] == "role")
            .and_then(|t| t.get(1))
            .and_then(|&val| match val {
                "user" => Some(UserRole::User),
                "admin" => Some(UserRole::Admin),
                _ => None,
            })
            .ok_or(ParseUserProfileError(input_str.to_owned()))?;

        // u8::from_str_radix(src: &str, radix: u32) converts a string
        // slice in a given base to u8
        Ok(UserProfile { email, uid, role })
    }
}
