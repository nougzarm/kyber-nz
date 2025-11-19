use std::{marker::PhantomData, ops::Add};

pub trait PolyParams {
    const N: usize;
    const Q: i64;
    
    fn zetas() -> &'static [i64];
}

pub struct Polynomial<P: PolyParams> {
    coeffs: Vec<i64>,
    _marker: std::marker::PhantomData<P>
}

impl<P: PolyParams> From<Vec<i64>> for Polynomial<P>{
    fn from(value: Vec<i64>) -> Self {
        Polynomial::<P> { coeffs: value, _marker: PhantomData::<P> }
    }
}

impl<P: PolyParams> Add for &Polynomial<P> {
    type Output = Polynomial<P>;
    fn add(self, other: Self) -> Polynomial<P> {
        let new_coeffs = self.coeffs.iter()
            .zip(other.coeffs.iter())
            .map(|(a, b)| (a + b)) // à replacer par mod q
            .collect();
        Polynomial::<P> { coeffs: new_coeffs, _marker: PhantomData::<P> }
    }
}