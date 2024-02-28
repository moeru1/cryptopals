use crate::set1::{break_repeating_key::hamming_distance, fixed_xor::hex_decode};
use base64::{self, alphabet::STANDARD, engine::general_purpose, Engine};
use itertools::Itertools;
use std::{
    cmp::min,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    vec,
};

const BLOCK_SIZE: usize = 16;

fn count_occurrences(bytes: &[u8], count: &mut [u32; 256]) {
    for &b in bytes {
        count[b as usize] += 1;
    }
}

pub fn entropy_bytes(bytes: &[u8]) -> f32 {
    let mut count = [0; 256];
    count_occurrences(bytes, &mut count);
    entropy_from_count(&count, bytes.len())
}

fn entropy<'a>(p: impl Iterator<Item = &'a f64>) -> f64 {
    p.map(|px| if *px > 0. { -px * px.log2() } else { 0. })
        .sum()
}

fn entropy_from_count(count: &[u32; 256], n: usize) -> f32 {
    (0..255)
        .map(|x| {
            let px = count[x] as f32 / n as f32;
            if px > 0. {
                -px * px.log2()
            } else {
                0.
            }
        })
        .sum()
}

pub fn evaluate(bytes: &[u8]) -> f32 {
    assert!(bytes.len() % BLOCK_SIZE == 0);
    let sum: f32 = (0..BLOCK_SIZE)
        .map(|offset| {
            let v = bytes
                .chunks_exact(BLOCK_SIZE)
                .map(|chunk| chunk[offset])
                .collect::<Vec<_>>();
            entropy_bytes(&v)
        })
        .sum();
    sum / BLOCK_SIZE as f32
}

//fn evaluate(bytes: &[u8], block_size: usize) -> f32 {
//    let factor = bytes.len() / block_size;
//    let sum = bytes
//        .chunks_exact(block_size * 2)
//        .fold(f32::MAX, |acc, chunk| {
//            let b1 = &chunk[0..block_size];
//            let b2 = &chunk[block_size..2 * block_size];
//            let h = hamming_distance(b1, b2);
//            let acc_h = acc;
//            f32::min(h as f32, acc_h)
//        });
//    sum / factor as f32
//}
//

fn asd(reader: impl BufRead) -> vec::IntoIter<(f32, String)> {
    reader
        .lines()
        .map(|line| {
            let line = line.unwrap();
            let data = hex_decode(&line);
            (evaluate(&data), line)
        })
        .sorted_by(|(f1, _), (f2, _)| f1.partial_cmp(&f2).unwrap())
}

fn detect_aes_ecb(filename: impl AsRef<Path>) -> vec::IntoIter<(f32, String)> {
    let file = File::open(filename).unwrap();
    let reader = BufReader::new(file);
    asd(reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set1::single_byte_xor_cipher::probabilities_table;
    use rand::rngs::StdRng;
    use rand::{thread_rng, Rng, SeedableRng};
    #[test]
    fn it_works() {
        let stream = detect_aes_ecb("8.txt");
        stream.for_each(|s| println!("{:?}", s));
    }

    #[test]
    fn entropy_alphabet() {
        let probabilites = probabilities_table();
        let ent = entropy(probabilites.iter());
        println!("ENTROPY OF ALPHABETH {}", ent);
    }
}
