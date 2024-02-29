use super::cbc::{aes_cbc_encrpyt, aes_ecb_encrpyt};
use crate::set1::detect_aes_ecb::evaluate;
use crate::set2::pkcs7;
use itertools::Itertools;
use rand::{
    self, distributions::Standard, prelude::Distribution, seq::SliceRandom, thread_rng, Rng,
};

const BLOCK_SIZE: usize = 16;
#[derive(Debug)]
struct Threshold(f32);
struct OracleTrainer {}
struct Oracle {
    threshold: Threshold,
}

enum EncryptionType {
    ECB,
    CBC,
}

impl Distribution<EncryptionType> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> EncryptionType {
        match rng.gen_range(0..=1) {
            0 => EncryptionType::ECB,
            1 => EncryptionType::CBC,
            _ => unreachable!(),
        }
    }
}

pub fn encryption_oracle(input: &[u8]) -> Vec<u8> {
    let mut key = [0u8; 16];
    thread_rng().fill(&mut key);

    let len_prefix = thread_rng().gen_range(5..=10);
    let mut prefix = vec![0u8; len_prefix];
    prefix.iter_mut().for_each(|e| {
        *e = thread_rng().gen();
    });
    let len_suffix = thread_rng().gen_range(5..=10);
    let mut suffix = vec![0u8; len_suffix];
    suffix.iter_mut().for_each(|e| {
        *e = thread_rng().gen();
    });

    let mut padded_input = Vec::new();
    padded_input.extend_from_slice(&prefix);
    padded_input.extend_from_slice(input);
    padded_input.extend_from_slice(&suffix);

    let choice = thread_rng().gen::<EncryptionType>();
    let bytes = match choice {
        EncryptionType::CBC => {
            let mut iv = [0u8; 16];
            thread_rng().fill(&mut iv);
            aes_cbc_encrpyt(&padded_input, &key, &iv)
        }
        EncryptionType::ECB => aes_ecb_encrpyt(&padded_input, &key).unwrap(),
    };
    bytes
}

impl OracleTrainer {
    fn train_oracle<'a>(input: impl IntoIterator<Item = Vec<u8>>) -> Threshold {
        let it = std::iter::from_fn(|| Some(thread_rng().gen::<EncryptionType>()));
        let mut choice_ecb = 0;
        let mut choice_cbc = 0;
        let entropies = input
            .into_iter()
            .zip(it)
            .map(|(bytes, choice)| {
                let mut key = [0u8; 16];
                let mut iv = [0u8; 16];
                thread_rng().fill(&mut key);
                thread_rng().fill(&mut iv);
                let bytes = match choice {
                    EncryptionType::CBC => {
                        choice_cbc += 1;
                        aes_cbc_encrpyt(&bytes, &key, &iv)
                    }
                    EncryptionType::ECB => {
                        choice_ecb += 1;
                        aes_ecb_encrpyt(&bytes, &key).unwrap()
                    }
                };
                //normalize entropy
                let e = evaluate(&bytes) / (bytes.len() as f32);
                (e, choice)
            })
            .sorted_by(|(f1, _), (f2, _)| f1.partial_cmp(&f2).unwrap())
            .collect::<Vec<_>>();
        let mut max_diff = 0.;
        // entropy function generate values greater than 0
        let mut threshold = 0.;
        for ((e1, choice), (e2, _)) in entropies.iter().tuple_windows() {
            let choice = match choice {
                EncryptionType::ECB => "ECB",
                EncryptionType::CBC => "CBC",
            };
            println!("{}, {}", e1, choice);
            if e2 - e1 > max_diff {
                threshold = *e1;
                max_diff = e2 - e1;
            }
        }
        println!("ECB = {}, CBC = {}", choice_ecb, choice_cbc);
        Threshold(threshold)
    }
}

impl Oracle {
    fn new(threshold: Threshold) -> Oracle {
        Oracle { threshold }
    }
    fn ecb_cbc_oracle(&self, value: f32) -> EncryptionType {
        if self.threshold.0 <= value {
            EncryptionType::ECB
        } else {
            EncryptionType::CBC
        }
    }
}

#[cfg(test)]
mod tests {
    use ascii::IntoAsciiString;

    use super::*;
    use std::fs::{self, File};
    use std::io::{BufRead, BufReader};
    #[test]
    fn it_works() {
        let file = fs::read_to_string("2554-0.txt").unwrap();
        let iter = file
            .split_terminator("\n\n")
            .filter(|line| !line.trim().is_empty())
            .filter(|line| line.len() >= BLOCK_SIZE * 15 && line.len() < BLOCK_SIZE * 16)
            .collect::<Vec<_>>();
        println!("len = {}", iter.len());
        let threshold = OracleTrainer::train_oracle(iter.into_iter().map(|a| {
            let mut a = a.as_bytes().to_owned();
            pkcs7::pad_to_multiple(&mut a, 16);
            a
        }));
        println!("threshold = {:?}", threshold);
        let oracle = Oracle::new(threshold);
        //let a = Oracle
    }
}
