use core::fmt;
use std::{
    marker::PhantomData,
    ops::{Add, Index, IndexMut, Mul, Sub},
};

use crate::constants::PolyParams;

pub fn mod_q(x: i64, q: i64) -> i64 {
    ((x % q) + q) % q
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial<P: PolyParams> {
    coeffs: Vec<i64>,
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
}

impl<P: PolyParams> Add for &Polynomial<P> {
    type Output = Polynomial<P>;
    fn add(self, rhs: Self) -> Polynomial<P> {
        let new_coeffs = self
            .coeffs
            .iter()
            .zip(rhs.coeffs.iter())
            .map(|(a, b)| mod_q(a + b, P::Q))
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
            .map(|(a, b)| mod_q(a - b, P::Q))
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
                    new_coeffs[k] = mod_q(new_coeffs[k] + pdt, P::Q);
                } else {
                    let k_prime = k - P::N;
                    new_coeffs[k_prime] = mod_q(new_coeffs[k_prime] - pdt, P::Q);
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
    coeffs: Vec<i64>,
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
    pub fn SampleNTT(&[u8, 34]) -> Self {
        let mut a = vec![0i64; P::N];

        PolynomialNTT::<P>::from(a)
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
    }
}
