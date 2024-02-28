pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let cycle_key = key.iter().cycle();
    plaintext
        .iter()
        .zip(cycle_key)
        .map(|(b, k)| b ^ k)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set1::fixed_xor::*;
    #[test]
    fn it_works() {
        let text = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
        let key = "ICE";
        let enc = encrypt(text.as_bytes(), key.as_bytes());
        let enc = hex_encode(&enc);
        println!("{}", enc);
        assert!(enc == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    }
}
