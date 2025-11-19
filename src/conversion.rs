use bitvec::prelude::*;

use crate::polynomial::mod_q;

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
pub fn BytesToBits(bytes: Vec<u8>) -> BitVec<u8, Lsb0> {
    BitVec::<u8, Lsb0>::from_vec(bytes)
}

/// Algorithm 5 : ByteEncode_d(F)
/// Encodes an array of d-bit integers into a byte array for 1 <= d <= 12
///
/// Input : integer array F in Z_m^N, where m = 2^d if d < 12, and m = Q if d = 12
/// Output : B in B^(32*d)
pub fn ByteEncode<const N: usize>(F: Vec<i64>, d: usize) -> Vec<u8> {
    let mut bits = BitVec::<u8, Lsb0>::with_capacity(N * d as usize);
    for i in 0..N {
        let mut a = F[i];
        for j in 0..d {
            let temp = a % 2;
            bits.set(i * d + j, temp == 1);
            a = (a - temp) / 2;
        }
    }
    BitsToBytes(bits)
}

/// Algorithm 6 : ByteEncode_d(F)
/// Decodes a byte array into an array of d-bit integers for 1 <= d <= 12
///
/// Input : B in B^(32*d)
/// Output : integer array F in Z_m^N, where m = 2^d if d < 12, and m = Q if d = 12
pub fn ByteDecode<const N: usize, const Q: i64>(bytes: Vec<u8>, d: usize) -> Vec<i64> {
    let m = match d {
        12 => Q,
        _ => 1i64 << d,
    };

    let mut f = vec![0i64; N];
    let bits = BytesToBits(bytes);
    for i in 0..N {
        for j in 0..d {
            f[i] = (f[i] + (bits[i * d + j] as i64) * (1 << j)) % m
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        let bytes = b"salut tous le monde. Comment allez vous".to_vec();
        assert_eq!(BitsToBytes(BytesToBits(bytes.clone())), bytes);

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
        assert_eq!(BytesToBits(BitsToBytes(b.clone())), b);
    }
}
