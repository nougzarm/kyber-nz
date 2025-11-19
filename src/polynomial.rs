use core::fmt;
use std::{
    marker::PhantomData,
    ops::{Add, Index, IndexMut, Mul, Sub},
};

pub fn mod_q(x: i64, q: i64) -> i64 {
    ((x % q) + q) % q
}

pub trait PolyParams {
    const N: usize;
    const Q: i64;

    fn zetas() -> &'static [i64];
}

struct KyberParams;
impl PolyParams for KyberParams {
    const N: usize = 256;
    const Q: i64 = 3329;

    fn zetas() -> &'static [i64] {
        &[
            1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746,
            296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974,
            821, 289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33,
            1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474,
            3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233,
            756, 2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437,
            2388, 733, 2337, 268, 641, 1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319,
            2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722,
            1212, 1874, 1029, 2110, 2935, 885, 2154,
        ]
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
