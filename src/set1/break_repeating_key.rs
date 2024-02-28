use crate::set1::{repeating_key_xor, single_byte_xor_cipher::decrypt_single_xor};
use base64::{engine::general_purpose, Engine};
use itertools::Itertools;
use std::fs::File;
use std::io::{self, prelude::*, BufReader};

pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b).map(|(a, b)| (a ^ b).count_ones()).sum()
}

pub fn read_file(filename: &str) -> Vec<u8> {
    let file = File::open(filename).unwrap();
    let reader = BufReader::new(file);

    let mut bytes = Vec::new();
    for line in reader.lines() {
        let line = line.unwrap();
        let line_bytes = general_purpose::STANDARD.decode(&line).unwrap();
        bytes.extend(line_bytes.into_iter());
    }
    bytes
}

fn estimate_keysize(bytes: &[u8]) -> std::vec::IntoIter<(f32, usize)> {
    (2..=40)
        .map(|keysize| {
            //TODO: do not give advantages to the large keys
            let normalized: f32 = bytes
                .chunks_exact(keysize * 2)
                .map(|chunk| {
                    let b1 = &chunk[0..keysize];
                    let b2 = &chunk[keysize..2 * keysize];
                    let h = hamming_distance(b1, b2);
                    h as f32
                })
                .sum();
            (normalized, keysize)
        })
        .sorted_by(|(f1, _), (f2, _)| f1.partial_cmp(&f2).unwrap())
}

fn transpose_blocks(keysize: usize, bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut slices = vec![Vec::new(); keysize];
    for (i, &byte) in bytes.iter().enumerate() {
        slices[i % keysize].push(byte);
    }
    slices
}

pub fn decrpyt_repeating_xor(bytes: &[u8]) -> Vec<u8> {
    let mut sizes = estimate_keysize(bytes);
    for s in sizes.clone() {
        println!("{:?}", s);
    }
    let (_, keysize) = sizes.next().unwrap();
    let blocks = transpose_blocks(keysize, bytes);
    let key = blocks
        .iter()
        .map(|blk| (decrypt_single_xor(blk))[0].1)
        .map(|c| c as u8)
        .collect();
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let bytes = read_file("6.txt");
        let key = decrpyt_repeating_xor(&bytes);
        println!("{:?}", key.iter().map(|&c| c as char).collect::<Vec<_>>());
        let msg = repeating_key_xor::encrypt(&bytes, &key);
        println!("{}", msg.iter().map(|&c| c as char).collect::<String>());
    }
}
