use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use std::{
    marker::PhantomData,
    ops::{Add, AddAssign, Index, IndexMut, Mul, Sub},
};

use crate::{constants::PolyParams, conversion::get_bit, errors::Error};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial<P: PolyParams> {
    pub coeffs: [i16; 256],
    _marker: std::marker::PhantomData<P>,
}

impl<P: PolyParams> From<[i16; 256]> for Polynomial<P> {
    fn from(value: [i16; 256]) -> Self {
        Polynomial::<P> {
            coeffs: value,
            _marker: PhantomData::<P>,
        }
    }
}

impl<P: PolyParams> From<i16> for Polynomial<P> {
    fn from(value: i16) -> Self {
        let mut coeffs = [0i16; 256];
        coeffs[0] = value;
        Polynomial::<P>::from(coeffs)
    }
}

impl<P: PolyParams> Polynomial<P> {
    pub fn new(coeffs: &[i16; 256]) -> Self {
        Polynomial::<P>::from(*coeffs)
    }

    pub fn from_slice(coeffs: &[i16]) -> Result<Self, Error> {
        if coeffs.len() != 256 {
            return Err(Error::InvalidInputLength);
        }
        let mut new_coeffs = [0i16; 256];
        new_coeffs.copy_from_slice(coeffs);
        Ok(Polynomial::<P>::from(new_coeffs))
    }

    /// Algorithm 8 (FIPS 203) : SimplePolyCBD_eta(B)
    ///
    /// Input : B in B^(64*eta)
    /// with eta in {2, 3}
    /// Output : f in Polynomial
    pub fn sample_poly_cbd(b: &[u8], eta: usize) -> Result<Self, Error> {
        if (eta != 2) && (eta != 3) {
            return Err(Error::InvalidEta);
        }

        let mut coeffs = [0i16; 256];
        for (i, coeff) in coeffs.iter_mut().enumerate() {
            let mut x = 0i16;
            for j in 0..eta {
                x += get_bit(b, 2 * i * eta + j);
            }
            let mut y = 0i16;
            for j in 0..eta {
                y += get_bit(b, 2 * i * eta + eta + j);
            }
            *coeff = (x - y).rem_euclid(P::Q);
        }
        Ok(Polynomial::<P>::from(coeffs))
    }

    /// Algorithm 9 (FIPS 203) : NTT(f)
    /// Computes the NTT representation f_ntt of the giver polynomial f in R_Q
    ///
    /// Input : Polynomial f in R_Q (Z_Q^N)
    /// Output : PolynomialNTT f_ntt in T_Q (Z_Q^N)
    pub fn to_ntt(&self) -> PolynomialNTT<P> {
        let mut coeffs = self.coeffs;
        let mut i = 1;
        let zetas = P::zetas();
        let mut len = 128;

        while len > 1 {
            for start in (0..P::N).step_by(2 * len) {
                let zeta = zetas[i];
                i += 1;
                for j in start..(start + len) {
                    let t = (zeta as i32 * coeffs[j + len] as i32).rem_euclid(P::Q as i32) as i16;
                    coeffs[j + len] = (coeffs[j] - t).rem_euclid(P::Q);
                    coeffs[j] = (coeffs[j] + t).rem_euclid(P::Q);
                }
            }
            len /= 2;
        }
        PolynomialNTT {
            coeffs,
            _marker: PhantomData::<P>,
        }
    }

    /// Algorithm 10 (FIPS 203) : NNT^-1(f_ntt)
    /// Computes the polynomial f in R_Q that corresponds to the given NTT representation f_ntt in T_Q
    ///
    /// Input : PolynomialNTT f_ntt in T_Q (Z_Q^N)
    /// Output : Polynomial f in R_Q (Z_Q^N)
    pub fn from_ntt(poly_ntt: &PolynomialNTT<P>) -> Self {
        let mut coeffs = poly_ntt.coeffs;
        let zetas = P::zetas();
        let mut i = 127;
        let mut len = 2;

        while len <= 128 {
            for start in (0..P::N).step_by(2 * len) {
                let zeta = zetas[i];
                i -= 1;
                for j in start..(start + len) {
                    let t = coeffs[j];
                    coeffs[j] = (t + coeffs[j + len]).rem_euclid(P::Q);
                    coeffs[j + len] =
                        (zeta as i32 * (coeffs[j + len] - t) as i32).rem_euclid(P::Q as i32) as i16;
                }
            }
            len *= 2;
        }

        for coeff in coeffs.iter_mut() {
            *coeff = (*coeff as i32 * P::N_INV as i32).rem_euclid(P::Q as i32) as i16;
        }

        Polynomial {
            coeffs,
            _marker: PhantomData::<P>,
        }
    }
}

impl<P: PolyParams> Add for &Polynomial<P> {
    type Output = Polynomial<P>;
    fn add(self, rhs: Self) -> Polynomial<P> {
        let mut new_coeffs = [0i16; 256];
        for (i, (a, b)) in self.coeffs.iter().zip(rhs.coeffs.iter()).enumerate() {
            new_coeffs[i] = (a + b).rem_euclid(P::Q);
        }
        Polynomial::<P> {
            coeffs: new_coeffs,
            _marker: PhantomData::<P>,
        }
    }
}

impl<P: PolyParams> AddAssign<&Polynomial<P>> for Polynomial<P> {
    fn add_assign(&mut self, rhs: &Polynomial<P>) {
        for (a, b) in self.coeffs.iter_mut().zip(rhs.coeffs.iter()) {
            *a = (*a + b).rem_euclid(P::Q);
        }
    }
}

impl<P: PolyParams> Sub for &Polynomial<P> {
    type Output = Polynomial<P>;
    fn sub(self, rhs: Self) -> Polynomial<P> {
        let mut new_coeffs = [0i16; 256];
        for (i, (a, b)) in self.coeffs.iter().zip(rhs.coeffs.iter()).enumerate() {
            new_coeffs[i] = (a - b).rem_euclid(P::Q);
        }
        Polynomial::<P> {
            coeffs: new_coeffs,
            _marker: PhantomData::<P>,
        }
    }
}

impl<P: PolyParams> Mul for &Polynomial<P> {
    type Output = Polynomial<P>;
    fn mul(self, rhs: Self) -> Self::Output {
        let mut new_coeffs = [0i16; 256];

        for i in 0..P::N {
            for j in 0..P::N {
                let pdt =
                    (self.coeffs[i] as i32 * rhs.coeffs[j] as i32).rem_euclid(P::Q as i32) as i16;

                let k = i + j;
                if k < P::N {
                    new_coeffs[k] = (new_coeffs[k] + pdt).rem_euclid(P::Q);
                } else {
                    let k_prime = k - P::N;
                    new_coeffs[k_prime] = (new_coeffs[k_prime] - pdt).rem_euclid(P::Q);
                }
            }
        }
        Polynomial::<P> {
            coeffs: new_coeffs,
            _marker: PhantomData::<P>,
        }
    }
}

impl<P: PolyParams> Index<usize> for Polynomial<P> {
    type Output = i16;
    fn index(&self, index: usize) -> &Self::Output {
        &self.coeffs[index]
    }
}

impl<P: PolyParams> IndexMut<usize> for Polynomial<P> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.coeffs[index]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolynomialNTT<P: PolyParams> {
    pub coeffs: [i16; 256],
    _marker: std::marker::PhantomData<P>,
}

impl<P: PolyParams> From<[i16; 256]> for PolynomialNTT<P> {
    fn from(value: [i16; 256]) -> Self {
        PolynomialNTT::<P> {
            coeffs: value,
            _marker: PhantomData::<P>,
        }
    }
}

impl<P: PolyParams> PolynomialNTT<P> {
    pub fn from_slice(coeffs: &[i16]) -> Result<Self, Error> {
        if coeffs.len() != 256 {
            return Err(Error::InvalidInputLength);
        }
        let mut new_coeffs = [0i16; 256];
        new_coeffs.copy_from_slice(coeffs);
        Ok(PolynomialNTT::<P>::from(new_coeffs))
    }

    /// Algorithm 7 : SampleNTT(B)
    ///
    /// Input : B in B^34
    /// Output : a in PolynomialNTT
    pub fn sample_ntt(bytes: &[u8; 34]) -> Self {
        let mut a = [0i16; 256];
        let mut hasher = Shake128::default();
        hasher.update(bytes);
        let mut reader = hasher.finalize_xof();
        let mut j = 0;
        while j < P::N {
            let mut c = [0u8; 3];
            reader.read(&mut c);
            let d1 = (c[0] as i16) + (P::N as i16) * (c[1] as i16 % 16);
            let d2 = (c[1] as i16 / 16) + 16 * (c[2] as i16);
            if d1 < P::Q {
                a[j] = d1;
                j += 1;
            }
            if (d2 < P::Q) && (j < P::N) {
                a[j] = d2;
                j += 1;
            }
        }
        PolynomialNTT::<P>::from(a)
    }
}

impl<P: PolyParams> Add for &PolynomialNTT<P> {
    type Output = PolynomialNTT<P>;
    fn add(self, rhs: Self) -> PolynomialNTT<P> {
        let mut new_coeffs = [0i16; 256];
        for (i, (a, b)) in self.coeffs.iter().zip(rhs.coeffs.iter()).enumerate() {
            new_coeffs[i] = (a + b).rem_euclid(P::Q);
        }
        PolynomialNTT::<P> {
            coeffs: new_coeffs,
            _marker: PhantomData::<P>,
        }
    }
}

impl<P: PolyParams> AddAssign<&PolynomialNTT<P>> for PolynomialNTT<P> {
    fn add_assign(&mut self, rhs: &PolynomialNTT<P>) {
        for (a, b) in self.coeffs.iter_mut().zip(rhs.coeffs.iter()) {
            *a = (*a + b).rem_euclid(P::Q);
        }
    }
}

impl<P: PolyParams> Mul for &PolynomialNTT<P> {
    type Output = PolynomialNTT<P>;
    fn mul(self, rhs: Self) -> Self::Output {
        let mut new_coeffs = [0i16; 256];

        let zetas = P::zetas();
        for i in 0..128 {
            let gamma = ((zetas[i] as i32 * zetas[i] as i32).rem_euclid(P::Q as i32)
                * P::ZETA as i32)
                .rem_euclid(P::Q as i32) as i16;
            new_coeffs[2 * i] = (self[2 * i] as i32 * rhs[2 * i] as i32
                + (self[2 * i + 1] as i32 * rhs[2 * i + 1] as i32).rem_euclid(P::Q as i32)
                    * gamma as i32)
                .rem_euclid(P::Q as i32) as i16;
            new_coeffs[2 * i + 1] = (self[2 * i] as i32 * rhs[2 * i + 1] as i32
                + self[2 * i + 1] as i32 * rhs[2 * i] as i32)
                .rem_euclid(P::Q as i32) as i16;
        }
        PolynomialNTT::<P> {
            coeffs: new_coeffs,
            _marker: PhantomData::<P>,
        }
    }
}

impl<P: PolyParams> Index<usize> for PolynomialNTT<P> {
    type Output = i16;
    fn index(&self, index: usize) -> &Self::Output {
        &self.coeffs[index]
    }
}

impl<P: PolyParams> IndexMut<usize> for PolynomialNTT<P> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.coeffs[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{constants::KyberParams, KyberPoly};

    #[test]
    fn basics() -> Result<(), Error> {
        let mut a_coeffs: Vec<i16> = vec![1, 0, 2, 3, 18, 32, 72, 21, 23, 1, 0, 9, 287, 23];
        a_coeffs.extend_from_slice(&[0i16; KyberParams::N - 14]);
        let a = KyberPoly::from_slice(&a_coeffs)?;
        assert_eq!(KyberPoly::from_ntt(&a.to_ntt()).coeffs, a.coeffs);

        let mut p1_coeffs: Vec<i16> = vec![1, 2, 4, 4, 3, 1, 6, 6, 4, 3];
        p1_coeffs.extend_from_slice(&[0i16; KyberParams::N - 10]);
        let mut p2_coeffs: Vec<i16> = vec![3, 4, 8, 10, 27, 273, 12, 982, 12, 42, 9];
        p2_coeffs.extend_from_slice(&[0i16; KyberParams::N - 11]);
        let p1 = KyberPoly::from_slice(&p1_coeffs)?;
        let p2 = KyberPoly::from_slice(&p2_coeffs)?;
        assert_eq!(
            KyberPoly::from_ntt(&(&p1.to_ntt() * &p2.to_ntt())).coeffs,
            (&p1 * &p2).coeffs
        );
        Ok(())
    }
}
