use crate::errors::Error;

pub fn compress(x: i16, d: usize, q: i16) -> i16 {
    let two_pow_d = 1i32 << d;

    let numerator = x as i32 * two_pow_d;
    let rounded = (numerator + (q as i32 / 2)) / q as i32;

    (rounded % two_pow_d) as i16
}

pub fn decompress(x: i16, d: usize, q: i16) -> i16 {
    let numerator = x as i32 * q as i32;

    let half_divisor = 1i32 << (d - 1);
    ((numerator + half_divisor) >> d) as i16
}

pub fn get_bit(bytes: &[u8], index: usize) -> i16 {
    let byte_index = index / 8;
    let bit_index = index % 8;
    ((bytes[byte_index] >> bit_index) & 1) as i16
}

/// Algorithm 3 (FIPS 203) : BitsToBytes(b)
/// Converts a bit array (of a length that is a multiple of eight) into an array of bytes.
///
/// Input : b in {0, 1}^(8*r)
/// Output : B in B^r
pub fn bits_to_bytes(bits: &[u8]) -> Result<Vec<u8>, Error> {
    if !bits.len().is_multiple_of(8) {
        return Err(Error::InvalidInputLength);
    }

    let mut bytes = vec![0u8; bits.len() / 8];
    for (i, &bit) in bits.iter().enumerate() {
        if bit == 1 {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }
    Ok(bytes)
}

/// Algorithm 4 (FIPS 203) : BytesToBits(B)
/// Performs the inverse of BitsToBytes, converting a byte array into a bit array
///
/// Input : B in B^r
/// Output : b in {0, 1}^(8*r)
pub fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);

    for byte in bytes {
        for i in 0..8 {
            bits.push((byte >> i) & 1);
        }
    }
    bits
}

/// Algorithm 5 (FIPS 203) : ByteEncode_d(F)
/// Encodes an array of d-bit integers into a byte array for 1 <= d <= 12
///
/// Input : integer array F in Z_m^N, where m = 2^d if d < 12, and m = Q if d = 12
/// Output : B in B^(32*d)
pub fn byte_encode(f: &[i16], d: usize) -> Result<Vec<u8>, Error> {
    let mut bits = vec![0u8; f.len() * d];
    for (i, coeff) in f.iter().enumerate() {
        for j in 0..d {
            bits[i * d + j] = ((coeff >> j) & 1) as u8;
        }
    }
    bits_to_bytes(&bits)
}

/// Algorithm 6 (FIPS 203) : ByteEncode_d(F)
/// Decodes a byte array into an array of d-bit integers for 1 <= d <= 12
///
/// Input : B in B^(32*d)
/// Output : integer array F in Z_m^N, where m = 2^d if d < 12, and m = Q if d = 12
pub fn byte_decode(bytes: &[u8], d: usize, q: i16) -> Vec<i16> {
    let m = match d {
        12 => q,
        _ => 1i16 << d,
    };

    let bits = bytes_to_bits(bytes);
    let n = bits.len() / d;
    let mut f = vec![0i16; n];

    for i in 0..n {
        for j in 0..d {
            f[i] = (f[i] as i32 + (bits[i * d + j] as i32) * (1 << j)).rem_euclid(m as i32) as i16;
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{KyberParams, PolyParams};
    use crate::polynomial::PolynomialNTT;

    #[test]
    fn basics() {
        let q = KyberParams::Q;
        assert_eq!(compress(1933, 11, q), 1189);
        assert_eq!(decompress(compress(1933, 11, q), 11, q), 1933);
        assert_eq!(decompress(2001, 11, q), 3253);
        assert_eq!(compress(decompress(2001, 11, q), 11, q), 2001);

        let bytes = b"salut tous le monde. Comment allez vous";
        assert_eq!(bits_to_bytes(&bytes_to_bits(bytes)).unwrap(), bytes);

        let b = vec![
            1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1,
            1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1,
            1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0,
            0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1,
            0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1,
            0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0,
            1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1,
            0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0,
            1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0,
            1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1,
            1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0,
        ];
        assert_eq!(bytes_to_bits(&bits_to_bytes(&b).unwrap()), b);

        let f =
            PolynomialNTT::<KyberParams>::sample_ntt(b"Salut de la part de moi meme le ka").coeffs;
        let f_rev = byte_decode(&byte_encode(&f, 12).unwrap(), 12, q);
        assert_eq!(&f, &f_rev.as_slice());
    }
}
