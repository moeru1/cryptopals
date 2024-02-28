use crate::set1::fixed_xor;
use openssl::symm::{Cipher, Crypter, Mode};

pub fn aes_ecb_decrypt(
    key: &[u8],
    ciphertext: &[u8],
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set1::break_repeating_key::read_file;
    use std::str;
    #[test]
    fn it_works() {
        let key = b"YELLOW SUBMARINE"; // 16-byte key for AES-128
        let ciphertext = read_file("7.txt");

        match aes_ecb_decrypt(key, &ciphertext) {
            Ok(plaintext) => {
                println!(
                    "Decrypted plaintext: {}",
                    str::from_utf8(&plaintext).unwrap()
                );
                // Convert plaintext to string if necessary
                // let plaintext_str = String::from_utf8_lossy(&plaintext);
                // println!("Decrypted plaintext: {}", plaintext_str);
            }
            Err(e) => println!("Error: {}", e),
        }
    }
}
