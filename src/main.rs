use hex;
use std::ops::BitXor;

#[derive(Debug, PartialEq)]
struct ByteArray(Vec<u8>);


fn main() {

    let bytes1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
    let bytes2 = hex::decode("686974207468652062756c6c277320657965").unwrap();

    let ByteArray(result) = ByteArray(bytes1) ^ ByteArray(bytes2);
    println!("The final result: {} ", hex::encode(result));
}

impl BitXor for ByteArray {
    type Output = Self;

    fn bitxor(self, ByteArray(rhs): Self) -> Self::Output {
        let ByteArray(lhs) = self;
        if lhs.len() != rhs.len() {
            panic!("Cannot perform `^` (bitxor) on ByteArrays of different length")
        } else {
            let res = lhs.iter()
                         .zip(rhs.iter())
                         .map(|(x, y)| (x ^ y))
                         .collect();
            ByteArray(res)
        }
    }
}


