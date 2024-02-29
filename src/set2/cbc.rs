use crate::set1::{
    aes_ecb,
    fixed_xor::{fixed_xor, fixed_xor_mut},
};
use openssl::symm::{encrypt, Cipher, Crypter, Mode};

const BLOCK_SIZE: usize = 16;

pub fn aes_ecb_encrpyt(
    plaintext: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let cipher = Cipher::aes_128_ecb(); // Change the cipher type if needed
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, None)?;
    encrypter.pad(false);

    let mut encrypted_data = vec![0; plaintext.len() + cipher.block_size()];
    let mut count = encrypter.update(plaintext, &mut encrypted_data)?;
    count += encrypter.finalize(&mut encrypted_data[count..])?;

    encrypted_data.truncate(count);
    Ok(encrypted_data)
}

fn aes_encrypt_block(
    key: &[u8],
    block: &[u8],
    out: &mut [u8],
) -> Result<(), openssl::error::ErrorStack> {
    let cipher = Cipher::aes_128_ecb(); // Change the cipher type if needed
    assert!(block.len() == cipher.block_size());
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, None)?;
    encrypter.pad(false);
    //let mut encrypted_data = vec![0; block.len() + cipher.block_size()];
    let mut count = encrypter.update(block, out)?;
    count += encrypter.finalize(&mut out[count..])?;
    assert!(count == block.len());
    Ok(())
}

fn aes_decrypt_block(
    key: &[u8],
    block: &[u8],
    out: &mut [u8],
) -> Result<(), openssl::error::ErrorStack> {
    let cipher = Cipher::aes_128_ecb(); // Change the cipher type if needed
    assert!(block.len() == cipher.block_size());
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, None)?;
    decrypter.pad(false);
    //let mut encrypted_data = vec![0; block.len() + cipher.block_size()];
    let mut count = decrypter.update(block, out)?;
    count += decrypter.finalize(&mut out[count..])?;
    assert!(count == block.len());
    Ok(())
}

pub fn aes_ecb_decrypt(
    ciphertext: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let cipher = Cipher::aes_128_ecb(); // Change the cipher type if needed
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, None)?;
    decrypter.pad(false);

    let mut decrypted_data = vec![0; ciphertext.len() + cipher.block_size()];
    let mut count = decrypter.update(ciphertext, &mut decrypted_data)?;
    count += decrypter.finalize(&mut decrypted_data[count..])?;

    decrypted_data.truncate(count);
    Ok(decrypted_data)
}

fn aes_cbc_encrpyt_naive(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut prev = iv;
    let mut result = Vec::new();
    assert!(BLOCK_SIZE == iv.len());
    for block in plaintext.chunks_exact(BLOCK_SIZE) {
        let xor = fixed_xor(block, prev);
        let cipher_block = aes_ecb_encrpyt(&xor, &key).unwrap();
        result.extend_from_slice(&cipher_block);
        prev = &result[result.len() - BLOCK_SIZE..];
    }
    result
}

pub fn aes_cbc_encrpyt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut prev = iv;
    let mut result = vec![0; plaintext.len() + BLOCK_SIZE];
    assert!(BLOCK_SIZE == iv.len());
    for (i, block) in plaintext.chunks_exact(BLOCK_SIZE).enumerate() {
        let xor = fixed_xor(block, prev);
        let current_result = &mut result[i * BLOCK_SIZE..];
        aes_encrypt_block(&key, &xor, current_result).unwrap();
        prev = &current_result[..BLOCK_SIZE];
    }
    result.truncate(result.len() - BLOCK_SIZE);
    result
}

pub fn aes_cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut prev = iv;
    let mut result = vec![0; ciphertext.len() + BLOCK_SIZE];
    assert!(BLOCK_SIZE == iv.len());
    for (i, block) in ciphertext.chunks_exact(BLOCK_SIZE).enumerate() {
        //assert!(result[i * BLOCK_SIZE] == 0);
        //let (_, result_block) = result.split_at_mut(i * BLOCK_SIZE);
        let current_result = &mut result[i * BLOCK_SIZE..];
        aes_decrypt_block(&key, &block, current_result).unwrap();
        fixed_xor_mut(&mut current_result[..BLOCK_SIZE], prev);
        prev = block;
    }
    result.truncate(result.len() - BLOCK_SIZE);
    result
}

#[cfg(test)]
mod tests {
    use crate::set1::break_repeating_key::read_file;

    use super::*;

    #[test]
    fn it_works() {
        let plain = b"BLOCK OF 16 SIZEBLOCK OF 16 SIZE";
        let key = b"YELLOW SUBMARINE";
        let iv = [0; 16];
        let e1 = aes_cbc_encrpyt(plain, key, &iv);
        let e2 = aes_cbc_encrpyt_naive(plain, key, &iv);
        assert!(e1 == e2);
    }

    #[test]
    fn it_works_file() {
        let cipher = read_file("10.txt");
        let key = b"YELLOW SUBMARINE";
        let iv = [0; 16];
        let d1 = aes_cbc_decrypt(&cipher, key, &iv);
        println!("{}", d1.iter().map(|&c| c as char).collect::<String>());
        let e1 = aes_cbc_encrpyt(&d1, key, &iv);
        assert!(e1 == cipher);
    }
}
