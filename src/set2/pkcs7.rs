use std::iter::repeat;

pub fn pad(bytes: &mut Vec<u8>, target: usize) {
    let rest = target - bytes.len();
    let rest = u8::try_from(rest).unwrap();
    bytes.extend(repeat(rest).take(usize::from(rest)));
}

pub fn pad_to_multiple(bytes: &mut Vec<u8>, multiple: u8) {
    let pad = bytes.len() % usize::from(multiple);
    // the line above guarantees that pad is in u8 range
    let pad = u8::try_from(pad).unwrap();
    let pad = multiple - pad;
    bytes.extend(repeat(pad).take(usize::from(pad)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str;
    #[test]
    fn it_works() {
        let mut literal = Vec::from(b"YELLOW SUBMARINE");
        pad(&mut literal, 20);
        println!("{:?}", str::from_utf8(&literal).unwrap());
    }
}
