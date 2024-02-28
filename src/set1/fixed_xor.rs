use std::char;
use std::fmt::Write;

//https://stackoverflow.com/a/52992629
pub fn hex_decode(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .unwrap()
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn fixed_xor(buffer1: &[u8], buffer2: &[u8]) -> Vec<u8> {
    assert!(buffer1.len() == buffer2.len());
    let it = buffer1.iter().zip(buffer2.iter());
    it.map(|(b1, b2)| b1 ^ b2).collect()
}

pub fn fixed_xor_mut(buffer1: &mut [u8], buffer2: &[u8]) {
    assert!(buffer1.len() == buffer2.len());
    let it = buffer1.iter_mut().zip(buffer2.iter());
    it.for_each(|(b1, b2)| *b1 ^= b2);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set1::single_byte_xor_cipher::*;
    #[test]
    fn it_works() {
        let a = hex_decode("1c0111001f010100061a024b53535009181c");
        let b = hex_decode("686974207468652062756c6c277320657965");
        let xor = fixed_xor(&a, &b);
        println!("{}", hex_encode(&xor));
    }
}
