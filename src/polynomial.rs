use core::fmt;
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{
    marker::PhantomData,
    ops::{Add, AddAssign, Index, IndexMut, Mul, Sub},
};

use crate::{constants::PolyParams, conversion::bytes_to_bits};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial<P: PolyParams> {
    pub coeffs: [i32; 256],
    _marker: std::marker::PhantomData<P>,
}

impl<P: PolyParams> From<[i32; 256]> for Polynomial<P> {
    fn from(value: [i32; 256]) -> Self {
        Polynomial::<P> {
            coeffs: value,
            _marker: PhantomData::<P>,
        }
    }
}

impl<P: PolyParams> From<i32> for Polynomial<P> {
    fn from(value: i32) -> Self {
        let mut coeffs = [0i32; 256];
        coeffs[0] = value;
        Polynomial::<P>::from(coeffs)
    }
}

impl<P: PolyParams> Polynomial<P> {
    pub fn new(coeffs: &[i32; 256]) -> Self {
        Polynomial::<P>::from(*coeffs)
    }

    pub fn from_slice(coeffs: &[i32]) -> Self {
        if coeffs.len() != 256 {
            panic!("The polynomial must have exactly {} coefficients", 256);
        }
        let mut new_coeffs = [0i32; 256];
        new_coeffs.copy_from_slice(coeffs);
        Polynomial::<P>::from(new_coeffs)
    }

    /// Algorithm 8 (FIPS 203) : SimplePolyCBD_eta(B)
    ///
    /// Input : B in B^(64*eta)
    /// avec eta dans {2, 3}
    /// Output : f in Polynomial
    pub fn sample_poly_cbd(b: &[u8], eta: usize) -> Self {
        if (eta != 2) && (eta != 3) {
            panic!("Unauthorized value for eta")
        }

        if b.len() != 64 * eta {
            panic!("Unauthorized length for b")
        };

        let b_bits = bytes_to_bits(b);
        let mut coeffs = [0i32; 256];
        for i in 0..P::N {
            let mut x = 0i32;
            for j in 0..eta {
                x += b_bits[2 * i * eta + j] as i32;
            }
            let mut y = 0i32;
            for j in 0..eta {
                y += b_bits[2 * i * eta + eta + j] as i32;
            }
            coeffs[i] = (x - y).rem_euclid(P::Q);
        }
        Polynomial::<P>::from(coeffs)
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
                    let t = (zeta * coeffs[j + len]).rem_euclid(P::Q);
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
                    coeffs[j + len] = (zeta * (coeffs[j + len] - t)).rem_euclid(P::Q);
                }
            }
            len *= 2;
        }

        for coeff in coeffs.iter_mut() {
            *coeff = (*coeff * P::N_INV).rem_euclid(P::Q);
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
        let mut new_coeffs = [0i32; 256];
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
        let mut new_coeffs = [0i32; 256];
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
        let mut new_coeffs = [0i32; 256];

        for i in 0..P::N {
            for j in 0..P::N {
                let pdt = self.coeffs[i] * rhs.coeffs[j];

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

impl<P: PolyParams> fmt::Display for Polynomial<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut terms = Vec::new();
        for i in (0..P::N).rev() {
            let c = self.coeffs[i];
            if c == 0 {
                continue;
            }

            let mut term_str = String::new();

            if c != 1 || i == 0 {
                term_str.push_str(&c.to_string());
            }

            if i > 0 {
                if c != 1 {
                    term_str.push('*');
                }
                term_str.push('X');
                if i > 1 {
                    term_str.push_str(&format!("^{}", i));
                }
            }
            terms.push(term_str);
        }

        if terms.is_empty() {
            write!(f, "0")
        } else {
            write!(f, "{}", terms.join(" + "))
        }
    }
}

impl<P: PolyParams> Index<usize> for Polynomial<P> {
    type Output = i32;
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
    pub coeffs: [i32; 256],
    _marker: std::marker::PhantomData<P>,
}

impl<P: PolyParams> From<[i32; 256]> for PolynomialNTT<P> {
    fn from(value: [i32; 256]) -> Self {
        PolynomialNTT::<P> {
            coeffs: value,
            _marker: PhantomData::<P>,
        }
    }
}

impl<P: PolyParams> PolynomialNTT<P> {
    pub fn from_slice(coeffs: &[i32]) -> Self {
        if coeffs.len() != 256 {
            panic!("The polynomial must have exactly {} coefficients", 256);
        }
        let mut new_coeffs = [0i32; 256];
        new_coeffs.copy_from_slice(coeffs);
        PolynomialNTT::<P>::from(new_coeffs)
    }

    /// Algorithm 7 : SampleNTT(B)
    ///
    /// Input : B in B^34
    /// Output : a in PolynomialNTT
    pub fn sample_ntt(bytes: &[u8; 34]) -> Self {
        let mut a = [0i32; 256];
        let mut hasher = Shake128::default();
        hasher.update(bytes);
        let mut reader = hasher.finalize_xof();
        let mut j = 0;
        while j < P::N {
            let mut c = [0u8; 3];
            reader.read(&mut c);
            let d1 = (c[0] as i32) + (P::N as i32) * (c[1] as i32 % 16);
            let d2 = (c[1] as i32 / 16) + 16 * (c[2] as i32);
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
        let mut new_coeffs = [0i32; 256];
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
        let mut new_coeffs = [0i32; 256];

        let zetas = P::zetas();
        for i in 0..128 {
            let gamma = ((zetas[i] * zetas[i]).rem_euclid(P::Q) * P::ZETA).rem_euclid(P::Q);
            new_coeffs[2 * i] = (self[2 * i] * rhs[2 * i]
                + (self[2 * i + 1] * rhs[2 * i + 1]).rem_euclid(P::Q) * gamma)
                .rem_euclid(P::Q);
            new_coeffs[2 * i + 1] =
                (self[2 * i] * rhs[2 * i + 1] + self[2 * i + 1] * rhs[2 * i]).rem_euclid(P::Q);
        }
        PolynomialNTT::<P> {
            coeffs: new_coeffs,
            _marker: PhantomData::<P>,
        }
    }
}

impl<P: PolyParams> Index<usize> for PolynomialNTT<P> {
    type Output = i32;
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
    use crate::{constants::KyberParams, kyber::KyberPoly};

    #[test]
    fn basics() {
        let mut f = KyberPoly::from(0i32);
        let mut g = KyberPoly::from(1i32);
        (f[255], f[2]) = (6i32, 1i32);
        (g[19], g[3]) = (43i32, 92i32);
        println!("Polynomial f + g: {}", &f + &g);
        println!("Polynomial f * g: {}", &f * &g);

        let mut a_coeffs: Vec<i32> = vec![1, 0, 2, 3, 18, 32, 72, 21, 23, 1, 0, 9, 287, 23];
        a_coeffs.extend_from_slice(&[0i32; KyberParams::N - 14]);
        let a = KyberPoly::from_slice(&a_coeffs);
        assert_eq!(KyberPoly::from_ntt(&a.to_ntt()).coeffs, a.coeffs);

        let mut p1_coeffs: Vec<i32> = vec![1, 2, 4, 4, 3, 1, 6, 6, 4, 3];
        p1_coeffs.extend_from_slice(&[0i32; KyberParams::N - 10]);
        let mut p2_coeffs: Vec<i32> = vec![3, 4, 8, 10, 27, 273, 12, 982, 12, 42, 9];
        p2_coeffs.extend_from_slice(&[0i32; KyberParams::N - 11]);
        let p1 = KyberPoly::from_slice(&p1_coeffs);
        let p2 = KyberPoly::from_slice(&p2_coeffs);
        assert_eq!(
            KyberPoly::from_ntt(&(&p1.to_ntt() * &p2.to_ntt())).coeffs,
            (&p1 * &p2).coeffs
        );
    }
}
