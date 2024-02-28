use std::borrow::Cow;
use std::char;
use std::fmt::{format, Write};
use std::io::{self, Write as IoWrite};
use std::str;

pub const fn probabilities_table() -> [f64; 256] {
    let mut probabilities = [0.; 256];
    probabilities[9] = 0.000057;
    probabilities[' ' as usize] = 0.171662;
    probabilities['!' as usize] = 0.000072;
    probabilities['"' as usize] = 0.002442;
    probabilities['#' as usize] = 0.000179;
    probabilities['$' as usize] = 0.000561;
    probabilities['%' as usize] = 0.000160;
    probabilities['&' as usize] = 0.000226;
    probabilities['\'' as usize] = 0.002447;
    probabilities['(' as usize] = 0.002178;
    probabilities[')' as usize] = 0.002233;
    probabilities['*' as usize] = 0.000628;
    probabilities['+' as usize] = 0.000215;
    probabilities[',' as usize] = 0.007384;
    probabilities['-' as usize] = 0.013734;
    probabilities['.' as usize] = 0.015124;
    probabilities['/' as usize] = 0.001549;
    probabilities['0' as usize] = 0.005516;
    probabilities['1' as usize] = 0.004594;
    probabilities['2' as usize] = 0.003322;
    probabilities['3' as usize] = 0.001847;
    probabilities['4' as usize] = 0.001348;
    probabilities['5' as usize] = 0.001663;
    probabilities['6' as usize] = 0.001153;
    probabilities['7' as usize] = 0.001030;
    probabilities['8' as usize] = 0.001054;
    probabilities['9' as usize] = 0.001024;
    probabilities[':' as usize] = 0.004354;
    probabilities[';' as usize] = 0.001214;
    probabilities['<' as usize] = 0.001225;
    probabilities['=' as usize] = 0.000227;
    probabilities['>' as usize] = 0.001242;
    probabilities['?' as usize] = 0.001474;
    probabilities['@' as usize] = 0.000073;
    probabilities['A' as usize] = 0.003132;
    probabilities['B' as usize] = 0.002163;
    probabilities['C' as usize] = 0.003906;
    probabilities['D' as usize] = 0.003151;
    probabilities['E' as usize] = 0.002673;
    probabilities['F' as usize] = 0.001416;
    probabilities['G' as usize] = 0.001876;
    probabilities['H' as usize] = 0.002321;
    probabilities['I' as usize] = 0.003211;
    probabilities['J' as usize] = 0.001726;
    probabilities['K' as usize] = 0.000687;
    probabilities['L' as usize] = 0.001884;
    probabilities['M' as usize] = 0.003529;
    probabilities['N' as usize] = 0.002085;
    probabilities['O' as usize] = 0.001842;
    probabilities['P' as usize] = 0.002614;
    probabilities['Q' as usize] = 0.000316;
    probabilities['R' as usize] = 0.002519;
    probabilities['S' as usize] = 0.004003;
    probabilities['T' as usize] = 0.003322;
    probabilities['U' as usize] = 0.000814;
    probabilities['V' as usize] = 0.000892;
    probabilities['W' as usize] = 0.002527;
    probabilities['X' as usize] = 0.000343;
    probabilities['Y' as usize] = 0.000304;
    probabilities['Z' as usize] = 0.000076;
    probabilities['[' as usize] = 0.000086;
    probabilities['\\' as usize] = 0.000016;
    probabilities[']' as usize] = 0.000088;
    probabilities['^' as usize] = 0.000003;
    probabilities['_' as usize] = 0.001159;
    probabilities['`' as usize] = 0.000009;
    probabilities['a' as usize] = 0.051880;
    probabilities['b' as usize] = 0.010195;
    probabilities['c' as usize] = 0.021129;
    probabilities['d' as usize] = 0.025071;
    probabilities['e' as usize] = 0.085771;
    probabilities['f' as usize] = 0.013725;
    probabilities['g' as usize] = 0.015597;
    probabilities['h' as usize] = 0.027444;
    probabilities['i' as usize] = 0.049019;
    probabilities['j' as usize] = 0.000867;
    probabilities['k' as usize] = 0.006753;
    probabilities['l' as usize] = 0.031750;
    probabilities['m' as usize] = 0.016437;
    probabilities['n' as usize] = 0.049701;
    probabilities['o' as usize] = 0.057701;
    probabilities['p' as usize] = 0.015482;
    probabilities['q' as usize] = 0.000747;
    probabilities['r' as usize] = 0.042586;
    probabilities['s' as usize] = 0.043686;
    probabilities['t' as usize] = 0.063700;
    probabilities['u' as usize] = 0.020999;
    probabilities['v' as usize] = 0.008462;
    probabilities['w' as usize] = 0.013034;
    probabilities['x' as usize] = 0.001950;
    probabilities['y' as usize] = 0.011330;
    probabilities['z' as usize] = 0.000596;
    probabilities['{' as usize] = 0.000026;
    probabilities['|' as usize] = 0.000007;
    probabilities['}' as usize] = 0.000026;
    probabilities['~' as usize] = 0.000003;
    //probabilities['ƒ' as usize] = 0.000000;
    //probabilities['•' as usize] = 0.006410;
    probabilities['·' as usize] = 0.000010;
    probabilities['ß' as usize] = 0.000000;
    probabilities['â' as usize] = 0.000000;
    probabilities['å' as usize] = 0.000000;
    probabilities['æ' as usize] = 0.000000;
    probabilities['í' as usize] = 0.000000;
    probabilities
}

fn chi_squared(observed: &[u32], probabilities: &[f64], n: usize) -> f64 {
    if n == 0 {
        return f64::MAX;
    }
    let expected = probabilities.iter().map(|p| p * n as f64);
    let chi_squared: f64 = observed
        .iter()
        .zip(expected)
        .map(|(&o, e)| {
            if e < 1e-7 {
                if o >= 1 {
                    (o * o * n as u32) as f64
                } else {
                    0.
                }
            } else {
                ((o as f64 - e) * (o as f64 - e)) / e
            }
        })
        .sum();
    chi_squared
}

pub fn xor_single(bytes: &[u8], x: u8) -> Vec<u8> {
    bytes.iter().map(|b| b ^ x).collect::<Vec<_>>()
}

pub fn decrypt_single_xor(bytes: &[u8]) -> Vec<(f64, char, String)> {
    static PROBABILITIES: [f64; 256] = probabilities_table();
    let mut evaluation = (0 as u8..127 as u8)
        .map(|x| {
            let xor = xor_single(bytes, x);
            let n = xor.len();
            let mut observed = [0; 256];
            for &byte in &xor {
                observed[byte as usize] += 1;
            }
            let chi_sq = chi_squared(&observed, &PROBABILITIES, n);
            let xor = xor.iter().map(|&c| c as char).collect();
            assert!(!chi_sq.is_nan(), "{}", xor);
            (chi_sq, char::from_u32(x as u32).unwrap(), xor)
        })
        .collect::<Vec<_>>();
    evaluation.sort_by(|(f1, _, _), (f2, _, _)| f1.partial_cmp(&f2).unwrap());
    evaluation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set1::fixed_xor::*;
    #[test]
    fn it_works() {
        let input =
            hex_decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let chi_sq = decrypt_single_xor(&input);
        chi_sq.iter().take(5).for_each(|c| println!("{:?}", c));
    }
}
