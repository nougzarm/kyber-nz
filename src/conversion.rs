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
pub fn bits_to_bytes(bits: &[u8], out: &mut [u8]) -> Result<(), Error> {
    if !bits.len().is_multiple_of(8) {
        return Err(Error::InvalidInputLength);
    }
    let output_length = bits.len() / 8;
    if out.len() != output_length {
        return Err(Error::InvalidInputLength);
    }

    for (i, &bit) in bits.iter().enumerate() {
        out[i / 8] |= (bit & 1) << (i % 8);
    }

    Ok(())
}

/// Algorithm 4 (FIPS 203) : BytesToBits(B)
/// Performs the inverse of BitsToBytes, converting a byte array into a bit array
///
/// Input : B in B^r
/// Output : b in {0, 1}^(8*r)
pub fn bytes_to_bits(bytes: &[u8], out: &mut [u8]) -> Result<(), Error> {
    if out.len() != bytes.len() * 8 {
        return Err(Error::InvalidInputLength);
    }

    for (byte_index, byte) in bytes.iter().enumerate() {
        for i in 0..8 {
            out[8 * byte_index + i] = (byte >> i) & 1;
        }
    }
    Ok(())
}

/// Algorithm 5 (FIPS 203) : ByteEncode_d(F)
/// Encodes an array of d-bit integers into a byte array for 1 <= d <= 12
///
/// Input : integer array F in Z_m^N, where m = 2^d if d < 12, and m = Q if d = 12
/// Output : B in B^(32*d)
pub fn byte_encode(f: &[i16], d: usize, out: &mut [u8]) -> Result<(), Error> {
    let mut bits = vec![0u8; f.len() * d];
    for (i, coeff) in f.iter().enumerate() {
        for j in 0..d {
            bits[i * d + j] = ((coeff >> j) & 1) as u8;
        }
    }

    bits_to_bytes(&bits, out)?;
    Ok(())
}

/// Algorithm 6 (FIPS 203) : ByteEncode_d(F)
/// Decodes a byte array into an array of d-bit integers for 1 <= d <= 12
///
/// Input : B in B^(32*d)
/// Output : integer array F in Z_m^N, where m = 2^d if d < 12, and m = Q if d = 12
pub fn byte_decode(bytes: &[u8], d: usize, q: i16, out: &mut [i16]) -> Result<(), Error> {
    let m = match d {
        12 => q,
        _ => 1i16 << d,
    };

    let mut bits = vec![0u8; bytes.len() * 8];
    bytes_to_bits(bytes, bits.as_mut_slice())?;
    let n = bits.len() / d;

    if out.len() != n {
        return Err(Error::InvalidInputLength);
    }

    for i in 0..n {
        out[i] = 0i16;
        for j in 0..d {
            out[i] =
                (out[i] as i32 + (bits[i * d + j] as i32) * (1 << j)).rem_euclid(m as i32) as i16;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{KyberParams, PolyParams};
    use crate::polynomial::PolynomialNTT;

    #[test]
    fn basics() -> Result<(), Error> {
        let q = KyberParams::Q;
        assert_eq!(compress(1933, 11, q), 1189);
        assert_eq!(decompress(compress(1933, 11, q), 11, q), 1933);
        assert_eq!(decompress(2001, 11, q), 3253);
        assert_eq!(compress(decompress(2001, 11, q), 11, q), 2001);

        let bytes = b"salut tous le monde. Comment allez vous";
        let rev_bytes = {
            let mut bits = [0u8; 39 * 8];
            bytes_to_bits(bytes, &mut bits)?;
            println!("{:?}", bits);
            let mut res = [0u8; 39];
            bits_to_bytes(bits.as_slice(), &mut res)?;
            res
        };
        assert_eq!(rev_bytes, *bytes);

        let b = [
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
        let rev_b = {
            let mut bytes = [0u8; 312 / 8];
            bits_to_bytes(&b, &mut bytes)?;
            let mut res = [0u8; 312];
            bytes_to_bits(&bytes, &mut res)?;
            res
        };
        assert_eq!(rev_b, b);

        let f =
            PolynomialNTT::<KyberParams>::sample_ntt(b"Salut de la part de moi meme le ka").coeffs;
        let f_rev = {
            let mut encode = [0u8; (256 * 12) / 8];
            byte_encode(&f, 12, &mut encode)?;
            let mut res = [0i16; 256];
            byte_decode(&encode, 12, q, &mut res)?;
            res
        };
        assert_eq!(f, f_rev);
        Ok(())
    }
}
