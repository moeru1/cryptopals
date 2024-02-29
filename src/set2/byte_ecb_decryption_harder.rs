use std::{
    collections::HashMap,
    collections::VecDeque,
    iter::{repeat, repeat_with, zip},
    slice::ChunksExact,
};

use super::{
    cbc::{aes_ecb_decrypt, aes_ecb_encrpyt},
    pkcs7::pad_to_multiple,
};
use crate::set1::detect_aes_ecb::evaluate;
use base64::{engine::general_purpose, Engine};
use itertools::Itertools;
use once_cell::sync::Lazy;
use rand::{
    self, distributions::Standard, prelude::Distribution, seq::SliceRandom, thread_rng, Rng,
};

const BLOCK_SIZE: usize = 16;
static KEY: Lazy<[u8; BLOCK_SIZE]> = Lazy::new(|| {
    let mut key = [0u8; BLOCK_SIZE];
    thread_rng().fill(&mut key);
    key
});

static RANDOM_PREFIX: Lazy<Box<[u8]>> = Lazy::new(|| {
    let rnd = thread_rng().gen_range(5..=10);
    //let rnd = 5;
    let mut random_prefix = vec![0u8; rnd];
    random_prefix
        .iter_mut()
        .for_each(|b| *b = thread_rng().gen());
    random_prefix.into_boxed_slice()
});

struct EncryptionOracle<'a> {
    random_prefix: &'a [u8]
}

impl<'a> EncryptionOracle<'a> {
    fn new(random_prefix: &'a [u8]) -> Self {
        EncryptionOracle {random_prefix}
    }

    fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
        let unknown_string = general_purpose::STANDARD.decode(&unknown_string).unwrap();
        let mut padded_input = Vec::new();
        padded_input.extend_from_slice(&self.random_prefix);
        padded_input.extend_from_slice(&input);
        padded_input.extend_from_slice(&unknown_string);
        pad_to_multiple(&mut padded_input, 16);
        let encrypted = aes_ecb_encrpyt(&padded_input, &*KEY).unwrap();
        encrypted
    }
}

// AES-128-ECB(your-string || unknown-string, random-key)
pub fn encryption_oracle(input: &[u8]) -> Vec<u8> {
    let unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let unknown_string = general_purpose::STANDARD.decode(&unknown_string).unwrap();
    let mut padded_input = Vec::new();
    padded_input.extend_from_slice(&RANDOM_PREFIX);
    padded_input.extend_from_slice(&input);
    padded_input.extend_from_slice(&unknown_string);
    pad_to_multiple(&mut padded_input, 16);
    let encrypted = aes_ecb_encrpyt(&padded_input, &*KEY).unwrap();
    encrypted
}

// find block size and total lenght of the ciphertext
fn find_block_size(encryption_oracle: &EncryptionOracle) -> (usize, usize) {
    let n = encryption_oracle.encrypt(b"").len();
    for i in 1.. {
        let a = repeat('A' as u8).take(i).collect::<Vec<_>>();
        let m = encryption_oracle.encrypt(&a).len();
        if m > n {
            return (m - n, n);
        }
    }
    unreachable!()
}

fn find_prefix_len(encryption_oracle: &EncryptionOracle) -> usize {
    let (block_size, n) = find_block_size(encryption_oracle);
    let first_block = encryption_oracle.encrypt(b"");
    let mut first_block = first_block[..block_size].to_owned();
    for i in 1.. {
        let padding = repeat('A' as u8).take(i).collect::<Vec<_>>();
        let block = encryption_oracle.encrypt(&padding);
        let block = &block[..block_size];
        if first_block == block {
            return block_size - i + 1;
        } else {
            first_block = block.to_owned();
        }
    }
    unreachable!()
}

fn find_prefix_len2(encryption_oracle: &EncryptionOracle) -> usize {
    let (block_size, _n) = find_block_size(encryption_oracle);
    let idx_mixed = find_mixed_block(encryption_oracle, block_size);
    let reference_block = encryption_oracle.encrypt(b"");
    let mut reference_block = get_block(&reference_block, idx_mixed, block_size).to_owned();
    let mut prefix_offset = None;
    for i in 1.. {
        let padding = repeat('A' as u8).take(i).collect::<Vec<_>>();
        let block = encryption_oracle.encrypt(&padding);
        let block = get_block(&block, idx_mixed, block_size);
        if reference_block == block {
            prefix_offset = Some((block_size + 1) - i);
            break;
        } else {
            reference_block = block.to_owned();
        }
    }
    idx_mixed * block_size + prefix_offset.unwrap()
}

fn find_mixed_block(encryption_oracle: &EncryptionOracle, block_size: usize) -> usize {
    let reference = encryption_oracle.encrypt(b"");
    let probe = encryption_oracle.encrypt(b"A");
    let index = zip(
        reference.chunks_exact(block_size),
        probe.chunks_exact(block_size),
    )
    .enumerate()
    .find_map(
        |(i, (reference, probe))| {
            if reference != probe {
                Some(i)
            } else {
                None
            }
        },
    );
    index.unwrap()
}

fn get_block(bytes: &[u8], i: usize, block_size: usize) -> &[u8] {
    assert!((i + 1) * block_size <= bytes.len());
    &bytes[i * block_size..(i + 1) * block_size]
}

fn create_dictionary_opt<'a>(
    decrypted_block: impl Iterator<Item = &'a u8>,
    block_size: usize,
) -> HashMap<Vec<u8>, u8> {
    let mut input = Vec::from_iter(decrypted_block.map(|b| *b));
    input.push(0);
    let mut dict = HashMap::new();
    for b in 0..=u8::MAX {
        assert!(input.len() % block_size == 0);
        *input.last_mut().unwrap() = b;
        let output = encryption_oracle(&input);
        let mut output_block = Vec::new();
        output_block.extend_from_slice(&output[..block_size]);
        dict.insert(output_block, b);
    }
    dict
}

fn dictionary3(block_size: usize, total_len: usize) {
    let mut decrypted_msg = Vec::new();
    let num_blocks = total_len / block_size;
    println!("num_blocks = {}, total_len = {}", num_blocks, total_len);
    let mut decrypted_block = repeat('A' as u8)
        .take(block_size - 1)
        .collect::<VecDeque<_>>();
    for block_idx in 0..num_blocks {
        for a_prefix in (0..block_size).rev() {
            let input = repeat('A' as u8).take(a_prefix).collect::<Vec<_>>();
            let dict = create_dictionary_opt(decrypted_block.iter(), block_size);
            let output = encryption_oracle(&input);
            // the dictionary attack can fail because padding values change between oracle calls
            let b = dict
                .get(get_block(&output, block_idx, block_size))
                .unwrap_or_else(|| {
                    println!(
                        "failed to decrypt byte = {} on block = {}\nblock = {:?}",
                        a_prefix,
                        block_idx,
                        get_block(&output, block_idx, block_size)
                    );
                    &('?' as u8)
                });
            decrypted_block.pop_front();
            decrypted_block.push_back(*b);
            decrypted_msg.push(*b);
        }
    }
    println!("{:?}", String::from_utf8(decrypted_msg.clone()).unwrap());
}

fn create_dictionary(
    decrypted_msg: &[u8],
    a_prefix: usize,
    block_idx: usize,
    block_size: usize,
) -> HashMap<Vec<u8>, u8> {
    //decrypted_msg can now be larger than block_size
    let mut input = repeat('A' as u8).take(a_prefix).collect::<Vec<_>>();
    input.extend_from_slice(decrypted_msg);
    //dummy value, we will modify it later
    input.push(0);
    let mut dict = HashMap::new();
    for b in 0..=u8::MAX {
        assert!(input.len() % block_size == 0);
        *input.last_mut().unwrap() = b;
        let output = encryption_oracle(&input);
        let mut output_block = Vec::new();
        output_block.extend_from_slice(get_block(&output, block_idx, block_size));
        dict.insert(output_block, b);
    }
    dict
}

fn dictionary2(block_size: usize, total_len: usize) {
    let mut decrypted_msg = Vec::new();
    let num_blocks = total_len / block_size;
    println!("num_blocks = {}, total_len = {}", num_blocks, total_len);
    for block_idx in 0..num_blocks {
        //let mut decrypted_block = Vec::new();
        for a_prefix in (0..block_size).rev() {
            let input = repeat('A' as u8).take(a_prefix).collect::<Vec<_>>();
            let dict = create_dictionary(&decrypted_msg, a_prefix, block_idx, block_size);
            let output = encryption_oracle(&input);
            //for k in dict.keys() {
            //    println!("{:?}", k);
            //}
            //println!("block {:?}", get_block(&output, block_idx, block_size));
            let b = dict
                .get(get_block(&output, block_idx, block_size))
                .unwrap_or_else(|| {
                    println!(
                        "failed to decrypt byte = {} on block = {}\ncurrent_msg = {}",
                        a_prefix,
                        block_idx,
                        String::from_utf8(decrypted_msg.clone()).unwrap()
                    );
                    &('?' as u8)
                });
            //let b = dict[get_block(&output, block_idx, block_size)];
            decrypted_msg.push(*b);
        }
        println!("{:?}", String::from_utf8(decrypted_msg.clone()).unwrap());
    }
}

//d...dd|AAA...Ax|
fn dictionary1(block_size: usize, total_len: usize) {
    let mut decrypted = Vec::new();
    for idx in (0..block_size).rev() {
        let input = repeat('A' as u8).take(idx).collect::<Vec<u8>>();
        let dict = create_dictionary(&decrypted, idx, 0, block_size);
        let output = encryption_oracle(&input);
        //println!("{:?}", &output[..block_size]);
        let b = dict[&output[..block_size]];
        decrypted.push(b);
    }
    println!("{:?}", String::from_utf8(decrypted).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    /*
    #[test]
    fn test_block_size() {
        let (block_size, n) = find_block_size();
        assert!(block_size == BLOCK_SIZE);
        println!("{}", block_size);
        //dictionary3(block_size, n);
    }
    #[test]
    fn test_find_prefix() {
        let p = find_prefix_len();
        assert!(5 <= p && p <= 10, "p = {}", p);
        println!("p = {}", p);
    }
    */

    #[test]
    fn test_find_prefix2() {
        for choosen_len in 1..20 {
            let mut prefix = vec![0u8; choosen_len];
            prefix 
                .iter_mut()
                .for_each(|b| *b = thread_rng().gen());
    
            let encryption_oracle = EncryptionOracle::new(&prefix);
            let p = find_prefix_len2(&encryption_oracle);
            assert!(p == choosen_len, "p = {}", p);
        }
    }


}
