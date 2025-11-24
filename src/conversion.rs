use bitvec::prelude::*;

pub fn compress(x: i64, d: u32, q: i64) -> i64 {
    let two_pow_d = 1i64 << d;

    let numerator = x * two_pow_d;
    let rounded = (numerator + (q / 2)) / q;

    rounded % two_pow_d
}

pub fn decompress(x: i64, d: u32, q: i64) -> i64 {
    let two_pow_d = 1i64 << d;

    let numerator = x * q;

    let half_divisor = 1i64 << (d - 1);
    let rounded = (numerator + half_divisor) >> d;

    rounded
}

/// Algorithm 3 : BitsToBytes(b)
/// Converts a bit array (of a length that is a multiple of eight) into an array of bytes.
///
/// Input : b in {0, 1}^(8*r)
/// Output : B in B^r
pub fn BitsToBytes(bits: BitVec<u8, Lsb0>) -> Vec<u8> {
    bits.into_vec()
}

/// Algorithm 4 : BytesToBits(B)
/// Performs the inverse of BitsToBytes, converting a byte array into a bit array
///
/// Input : B in B^r
/// Output : b in {0, 1}^(8*r)
pub fn BytesToBits(bytes: &[u8]) -> BitVec<u8, Lsb0> {
    BitVec::<u8, Lsb0>::from_vec(bytes.to_vec())
}

/// Algorithm 5 : ByteEncode_d(F)
/// Encodes an array of d-bit integers into a byte array for 1 <= d <= 12
///
/// Input : integer array F in Z_m^N, where m = 2^d if d < 12, and m = Q if d = 12
/// Output : B in B^(32*d)
pub fn ByteEncode(F: &[i64], d: usize) -> Vec<u8> {
    let mut bits = bitvec![u8, Lsb0; 0; F.len() * d];
    for i in 0..F.len() {
        let a = F[i];
        for j in 0..d {
            let bit_is_set = ((a >> j) & 1) == 1;
            bits.set(i * d + j, bit_is_set);
        }
    }
    BitsToBytes(bits)
}

/// Algorithm 6 : ByteEncode_d(F)
/// Decodes a byte array into an array of d-bit integers for 1 <= d <= 12
///
/// Input : B in B^(32*d)
/// Output : integer array F in Z_m^N, where m = 2^d if d < 12, and m = Q if d = 12
pub fn ByteDecode<const N: usize, const Q: i64>(bytes: &[u8], d: usize) -> Vec<i64> {
    let m = match d {
        12 => Q,
        _ => 1i64 << d,
    };

    let mut f = vec![0i64; N];
    let bits = BytesToBits(bytes);
    for i in 0..N {
        for j in 0..d {
            f[i] = (f[i] + (bits[i * d + j] as i64) * (1 << j)).rem_euclid(m)
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
        assert_eq!(decompress(compress(1933, 11, q), 11, q), 1933);
        assert_eq!(compress(decompress(2001, 11, q), 11, q), 2001);

        let bytes = b"salut tous le monde. Comment allez vous";
        assert_eq!(BitsToBytes(BytesToBits(bytes)), bytes);

        let b = bitvec![u8, Lsb0;
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
            1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0
        ];
        assert_eq!(BytesToBits(&BitsToBytes(b.clone())), b);

        let f =
            PolynomialNTT::<KyberParams>::sample_ntt(b"Salut de la part de moi meme le ka").coeffs;
        let f_rev = ByteDecode::<256, 3329>(&ByteEncode(&f, 12), 12);
        assert_eq!(&f, &f_rev);
    }
}
