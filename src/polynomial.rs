use core::fmt;
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{
    marker::PhantomData,
    ops::{Add, Index, IndexMut, Mul, RemAssign, Sub},
};

use crate::constants::PolyParams;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial<P: PolyParams> {
    pub coeffs: Vec<i64>,
    _marker: std::marker::PhantomData<P>,
}

impl<P: PolyParams> From<Vec<i64>> for Polynomial<P> {
    fn from(value: Vec<i64>) -> Self {
        Polynomial::<P> {
            coeffs: value,
            _marker: PhantomData::<P>,
        }
    }
}

impl<P: PolyParams> From<i64> for Polynomial<P> {
    fn from(value: i64) -> Self {
        let mut coeffs = vec![0i64; P::N];
        coeffs[0] = value;
        Polynomial::<P>::from(coeffs)
    }
}

impl<P: PolyParams> Polynomial<P> {
    pub fn new(coeffs: Vec<i64>) -> Self {
        if coeffs.len() != P::N {
            panic!("The polynomial must have exactly {} coefficients", P::N);
        }
        Polynomial::<P>::from(coeffs)
    }

    /// Algorithm 9 : NTT(f)
    /// Computes the NTT representation f_ntt of the giver polynomial f in R_Q
    ///
    /// Input : Polynomial f in R_Q (Z_Q^N)
    /// Output : PolynomialNTT f_ntt in T_Q (Z_Q^N)
    pub fn to_ntt(&self) -> PolynomialNTT<P> {
        let mut coeffs = self.coeffs.clone();
        let mut i = 1;
        let zetas = P::zetas().to_vec();
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
            len = len / 2;
        }
        PolynomialNTT {
            coeffs,
            _marker: PhantomData::<P>,
        }
    }

    /// Algorithm 10 : NNT^-1(f_ntt)
    /// Computes the polynomial f in R_Q that corresponds to the given NTT representation f_ntt in T_Q
    ///
    /// Input : PolynomialNTT f_ntt in T_Q (Z_Q^N)
    /// Output : Polynomial f in R_Q (Z_Q^N)
    pub fn from_ntt(poly_ntt: &PolynomialNTT<P>) -> Self {
        let mut coeffs = poly_ntt.coeffs.clone();
        let zetas = P::zetas().to_vec();
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
            len = len * 2;
        }

        for i in 0..(P::N) {
            coeffs[i] = (coeffs[i] * P::N_inv).rem_euclid(P::Q);
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
        let new_coeffs = self
            .coeffs
            .iter()
            .zip(rhs.coeffs.iter())
            .map(|(a, b)| (a + b).rem_euclid(P::Q))
            .collect();
        Polynomial::<P> {
            coeffs: new_coeffs,
            _marker: PhantomData::<P>,
        }
    }
}

impl<P: PolyParams> Sub for &Polynomial<P> {
    type Output = Polynomial<P>;
    fn sub(self, rhs: Self) -> Polynomial<P> {
        let new_coeffs = self
            .coeffs
            .iter()
            .zip(rhs.coeffs.iter())
            .map(|(a, b)| (a - b).rem_euclid(P::Q))
            .collect();
        Polynomial::<P> {
            coeffs: new_coeffs,
            _marker: PhantomData::<P>,
        }
    }
}

impl<P: PolyParams> Mul for &Polynomial<P> {
    type Output = Polynomial<P>;
    fn mul(self, rhs: Self) -> Self::Output {
        let mut new_coeffs = vec![0i64; P::N];

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
    type Output = i64;
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
    pub coeffs: Vec<i64>,
    _marker: std::marker::PhantomData<P>,
}

impl<P: PolyParams> From<Vec<i64>> for PolynomialNTT<P> {
    fn from(value: Vec<i64>) -> Self {
        PolynomialNTT::<P> {
            coeffs: value,
            _marker: PhantomData::<P>,
        }
    }
}

impl<P: PolyParams> PolynomialNTT<P> {
    pub fn SampleNTT(bytes: &[u8; 34]) -> Self {
        let mut a = vec![0i64; P::N];
        let mut hasher = Shake128::default();
        hasher.update(bytes);
        let mut reader = hasher.finalize_xof();
        let mut j = 0;
        while j < P::N {
            let mut C = [0u8; 3];
            reader.read(&mut C);
            let d1 = (C[0] as i64) + (P::N as i64) * (C[1] as i64 % 16);
            let d2 = (C[1] as i64 / 16) + 16 * (C[2] as i64);
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

impl<P: PolyParams> Mul for &PolynomialNTT<P> {
    type Output = PolynomialNTT<P>;
    fn mul(self, rhs: Self) -> Self::Output {
        let mut new_coeffs = vec![0i64; P::N];

        let zetas = P::zetas().to_vec();
        for i in 0..128 {
            let gamma = (zetas[i] * zetas[i] * P::ZETA).rem_euclid(P::Q);
            new_coeffs[2 * i] = (self[2 * i] * rhs[2 * i]
                + self[2 * i + 1] * rhs[2 * i + 1] * gamma)
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
    type Output = i64;
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
    use crate::constants::KyberParams;

    #[test]
    fn basics() {
        let mut f = Polynomial::<KyberParams>::from(0i64);
        let mut g = Polynomial::<KyberParams>::from(1i64);
        (f[255], f[2]) = (6i64, 1i64);
        (g[19], g[3]) = (43i64, 92i64);
        println!("Polynomial f + g: {}", &f + &g);
        println!("Polynomial f * g: {}", &f * &g);

        let mut a_coeffs: Vec<i64> = vec![1, 0, 2, 3];
        a_coeffs.extend_from_slice(&[0i64; KyberParams::N]);
        let a = Polynomial::<KyberParams>::from(a_coeffs);
        assert_eq!(
            Polynomial::<KyberParams>::from_ntt(&a.to_ntt()).coeffs,
            a.coeffs
        );
    }
}
