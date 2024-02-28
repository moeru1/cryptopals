use crate::set1::fixed_xor::*;
use crate::set1::single_byte_xor_cipher::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str;

use super::fixed_xor::hex_decode;

pub fn detect(file: &str) -> Vec<(f64, char, String)> {
    let file = File::open(file).unwrap();
    let reader = BufReader::new(file);
    let mut final_result = Vec::new();
    for line in reader.lines() {
        let line = line.unwrap();
        //println!("{:?}", line);
        let cipher = hex_decode(&line);
        //if !str::from_utf8(&cipher).is_ok() {
        //    continue;
        //}
        //let cipher_str = str::from_utf8(&cipher).unwrap();
        let evaluations = decrypt_single_xor(&cipher);
        let evaluations = evaluations.into_iter().take(2);
        final_result.extend(evaluations);
    }
    final_result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let filename = "4.txt";
        let mut res = detect(filename);
        res.sort_by(|(f1, _, _), (f2, _, _)| f1.partial_cmp(&f2).unwrap());
        let res = res.iter().take(5);
        res.for_each(|(val, ch, xor)| {
            println!(
                "({}, {}, {})",
                val,
                ch,
                //xor.replace(|c: char| !(c.is_ascii_alphanumeric() || c.is_ascii_whitespace()), "")
                xor
            )
        });
    }
}
