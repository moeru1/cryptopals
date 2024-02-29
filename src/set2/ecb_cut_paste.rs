use super::cbc::{aes_ecb_decrypt, aes_ecb_encrpyt};
use crate::set2::pkcs7::pad_to_multiple;
use itertools::Itertools;
use rand::{thread_rng, Rng};
use std::str;

const BLOCK_SIZE: usize = 16;

fn kv_formatter<'a>(input: impl Iterator<Item = (&'a str, &'a str)>) -> String {
    let mut output = String::new();
    output.push_str("{\n");
    for (k, v) in input {
        output.push_str(&format!("  {}: '{}',\n", k, v));
    }
    if output.len() > 2 {
        output.pop();
        output.pop();
    }
    output.push_str("\n}");
    output
}
fn kv_parsing(input: &str) -> String {
    let a = input
        .split('&')
        .filter_map(|s| s.split('=').collect_tuple::<(&str, &str)>());
    kv_formatter(a)
}

fn profile_for(email: &str) -> String {
    let email = email.replace(&['&', '='], "");
    format!("email={}&uid=10&role=user", email)
}

fn encrypt_user(encoded_user: &str) -> (Vec<u8>, [u8; BLOCK_SIZE]) {
    let mut key = [0u8; BLOCK_SIZE];
    thread_rng().fill(&mut key);
    let mut encoded_user = encoded_user.as_bytes().to_vec();
    pad_to_multiple(&mut encoded_user, BLOCK_SIZE as u8);
    (aes_ecb_encrpyt(&encoded_user, &key).unwrap(), key)
}

fn decrypt_and_parse(encrypted_user: &[u8], key: &[u8; BLOCK_SIZE]) -> String {
    let mut plaintext = aes_ecb_decrypt(encrypted_user, key).unwrap();
    //TODO: remove padding
    let last = *plaintext.last().unwrap();
    if last <= BLOCK_SIZE as u8 {
        loop {
            let c = *plaintext.last().unwrap();
            if c != last {
                break;
            }
            plaintext.pop();
        }
    }
    kv_parsing(str::from_utf8(&plaintext).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let output = kv_parsing("foo=bar&baz=qux&zap=zazzle");
        let p = profile_for("foo@bar.com");
        let (e, key) = encrypt_user(&p);
        let d = decrypt_and_parse(&e, &key);
        println!("{:?} {}", d.as_bytes(), d.len());
    }
}
