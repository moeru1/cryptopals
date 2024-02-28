use base64::{engine::general_purpose, Engine};
use std::str;

pub fn hex_to_base64(hex: &str) -> String {
    let mut bytes = Vec::new();
    for i in 0..(hex.len() / 2) {
        let res = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16);
        match res {
            Ok(v) => bytes.push(v),
            Err(e) => println!("Problem with hex: {}", e),
        };
    }
    general_purpose::STANDARD.encode(&bytes)
}

pub fn hex_to_base64_u8(hex: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..(hex.len() / 2) {
        let slice = &hex[2 * i..2 * i + 2];
        let slice = str::from_utf8(slice).unwrap();
        let res = u8::from_str_radix(slice, 16);
        match res {
            Ok(v) => bytes.push(v),
            Err(e) => println!("Problem with hex {}", e),
        };
    }
    let mut buf = Vec::new();
    buf.resize(bytes.len() * 4 / 3 + 4, 0);
    let bytes_written = general_purpose::STANDARD
        .encode_slice(bytes, &mut buf)
        .unwrap();
    buf.truncate(bytes_written);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let output = hex_to_base64(input);
        assert!(
            output
                == String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
        );
    }
}
