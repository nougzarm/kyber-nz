use std::marker::PhantomData;

use crate::constants::PolyParams;
use crate::conversion::{ByteDecode, ByteEncode, compress, decompress};
use crate::hash::{g, prf};
use crate::polynomial::{Polynomial, PolynomialNTT};

pub struct K_PKE<P: PolyParams> {
    k: usize,
    eta_1: usize,
    eta_2: usize,
    d_u: usize,
    d_v: usize,
    _marker: std::marker::PhantomData<P>,
}

impl<P: PolyParams> K_PKE<P> {
    pub fn new(k: usize, eta_1: usize, eta_2: usize, d_u: usize, d_v: usize) -> Self {
        K_PKE::<P> {
            k,
            eta_1,
            eta_2,
            d_u,
            d_v,
            _marker: PhantomData::<P>,
        }
    }

    /// Algorithm 13 : K-PKE.KeyGen(d)
    ///
    /// Input : randomness d in B^32
    /// Output : (ek, dk) pair of encryption-decryption keys
    /// with : ek in B^(384*k + 32), and dk in B^(384*k)
    pub fn key_gen(&self, d: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let mut d_tmp = d.to_vec();
        d_tmp.extend_from_slice(&[self.k as u8]);
        let (rho, gamma) = g(&d_tmp);

        let mut n_var = 0usize;

        let a_ntt: Vec<Vec<PolynomialNTT<P>>> = vec![];
        for i in 0..self.k {
            let mut tmp_line = vec![];
            for j in 0..self.k {
                let mut input = [0u8; 34];
                input[0..32].copy_from_slice(&rho);
                input[32] = j as u8;
                input[33] = i as u8;
                tmp_line.push(PolynomialNTT::<P>::sample_ntt(&input));
            }
        }

        let mut s: Vec<Polynomial<P>> = vec![];
        for _i in 0..self.k {
            s.push(Polynomial::<P>::sample_poly_cbd(
                &prf(self.eta_1, &gamma, &[n_var as u8]),
                self.eta_1,
            ));
            n_var += 1;
        }

        let mut e: Vec<Polynomial<P>> = vec![];
        for _i in 0..self.k {
            e.push(Polynomial::<P>::sample_poly_cbd(
                &prf(self.eta_1, &gamma, &[n_var as u8]),
                self.eta_1,
            ));
            n_var += 1;
        }

        let s_ntt: Vec<PolynomialNTT<P>> = s.iter().map(|poly| poly.to_ntt()).collect();
        let e_ntt: Vec<PolynomialNTT<P>> = e.iter().map(|poly| poly.to_ntt()).collect();

        let mut t_ntt: Vec<PolynomialNTT<P>> = Vec::with_capacity(self.k);
        for i in 0..self.k {
            let mut pol_temp = PolynomialNTT::<P>::from(vec![0i64; P::N]);

            for j in 0..self.k {
                let product = &a_ntt[i][j] * &s_ntt[j];
                pol_temp = &pol_temp + &product;
            }

            let t_i = &pol_temp + &e_ntt[i];
            t_ntt.push(t_i);
        }

        const CONST_D: usize = 12;

        let mut ek = Vec::new();
        for poly in &t_ntt {
            ek.extend(ByteEncode(&poly.coeffs, CONST_D));
        }
        ek.extend_from_slice(&rho);

        let mut dk = Vec::new();
        for poly in &s_ntt {
            dk.extend(ByteEncode(&poly.coeffs, CONST_D));
        }

        (ek, dk)
    }

    /// Algorithm 14 : K-PKE.Encrypt(ek, m, r)
    ///
    /// Input : encryption key ek in B^(384*k + 32)
    /// Input : message m in B^32
    /// Input : randomness r in B^32
    /// Output : ciphertext c in B^(32 * (d_u * k + d_v))
    pub fn encrypt(&self, ek: &[u8], m: &[u8], r: &[u8; 32]) -> Vec<u8> {
        let mut n_var = 0usize;
        let mut t_ntt = Vec::with_capacity(self.k);
        for i in 0..self.k {
            let chunk = &ek[384 * i..384 * (i + 1)];
            let coeffs = ByteDecode(chunk, 12, P::Q);
            t_ntt.push(PolynomialNTT::<P>::from(coeffs));
        }
        let rho = &ek[384 * self.k..];

        let mut a_ntt = Vec::with_capacity(self.k);
        for i in 0..self.k {
            let mut temp_line = Vec::with_capacity(self.k);
            for j in 0..self.k {
                let mut input = [0u8; 34];
                input[0..32].copy_from_slice(rho);
                input[32] = j as u8;
                input[33] = i as u8;
                temp_line.push(PolynomialNTT::<P>::sample_ntt(&input));
            }
            a_ntt.push(temp_line);
        }

        let mut y = Vec::with_capacity(self.k);
        for _i in 0..self.k {
            y.push(Polynomial::<P>::sample_poly_cbd(
                &prf(self.eta_1, r, &[n_var as u8]),
                self.eta_1,
            ));
            n_var += 1;
        }

        let mut e_1 = Vec::with_capacity(self.k);
        for _i in 0..self.k {
            e_1.push(Polynomial::<P>::sample_poly_cbd(
                &prf(self.eta_2, r, &[n_var as u8]),
                self.eta_2,
            ));
            n_var += 1;
        }

        let e_2 = Polynomial::<P>::sample_poly_cbd(&prf(self.eta_2, r, &[n_var as u8]), self.eta_2);
        let y_ntt: Vec<PolynomialNTT<P>> = y.iter().map(|p| p.to_ntt()).collect();

        let mut u = Vec::with_capacity(self.k);
        for i in 0..self.k {
            let mut pol_tmp = PolynomialNTT::<P>::from(vec![0i64; P::N]);
            for j in 0..self.k {
                let product = &a_ntt[j][i] * &y_ntt[j];
                pol_tmp = &pol_tmp + &product;
            }
            u.push(&Polynomial::<P>::from_ntt(&pol_tmp) + &e_1[i]);
        }

        let m_bits = ByteDecode(m, 1, P::Q);
        let mu_coeffs: Vec<i64> = m_bits.into_iter().map(|b| decompress(b, 1, P::Q)).collect();
        let mu = Polynomial::<P>::from(mu_coeffs);

        let mut v_ntt_tmp = PolynomialNTT::<P>::from(vec![0i64; P::N]);
        for i in 0..self.k {
            v_ntt_tmp = &v_ntt_tmp + &(&t_ntt[i] * &y_ntt[i]);
        }
        let v = &(&Polynomial::<P>::from_ntt(&v_ntt_tmp) + &e_2) + &mu;

        let mut c1 = Vec::new();
        for poly in &u {
            let compressed: Vec<i64> = poly
                .coeffs
                .iter()
                .map(|&c| compress(c, self.d_u, P::Q))
                .collect();
            c1.extend(ByteEncode(&compressed, self.d_u as usize));
        }

        let compressed_v: Vec<i64> = v
            .coeffs
            .iter()
            .map(|&c| compress(c, self.d_v, P::Q))
            .collect();
        let c2 = ByteEncode(&compressed_v, self.d_v as usize);

        c1.extend_from_slice(&c2);
        c1
    }

    /// Algorithm 15 : K-PKE.Decrypt(dk, c)
    ///
    /// Input : decryption key dk in B^(384*k)
    /// Input : ciphertext c in B^(32 * (d_u*k + d_v))
    /// Output : message m in B^32
    pub fn decrypt(&self, dk: &[u8], c: &[u8]) -> Vec<u8> {
        let c_1 = &c[0..32 * self.d_u * self.k];
        let c_2 = &c[32 * self.d_u * self.k..];

        let mut u_prime = Vec::with_capacity(self.k);
        for i in 0..self.k {
            let decode = ByteDecode(
                &c_1[32 * self.d_u * i..32 * self.d_u * (i + 1)],
                self.d_u,
                P::Q,
            );
            let coeffs: Vec<i64> = decode
                .into_iter()
                .map(|val| decompress(val, self.d_u, P::Q))
                .collect();
            u_prime.push(Polynomial::<P>::from(coeffs));
        }

        let decoded_v = ByteDecode(c_2, self.d_v, P::Q);
        let v_coeffs: Vec<i64> = decoded_v
            .into_iter()
            .map(|val| decompress(val, self.d_v, P::Q))
            .collect();
        let v_prime = Polynomial::<P>::from(v_coeffs);

        let mut s_ntt = Vec::with_capacity(self.k);
        for i in 0..self.k {
            let chunk = &dk[384 * i..384 * (i + 1)];
            let coeffs = ByteDecode(chunk, 12, P::Q);
            s_ntt.push(PolynomialNTT::<P>::from(coeffs));
        }

        let mut pdt_tmp = PolynomialNTT::<P>::from(vec![0i64; P::N]);
        for i in 0..self.k {
            pdt_tmp = &pdt_tmp + &(&s_ntt[i] * &u_prime[i].to_ntt());
        }
        let w = &v_prime - &Polynomial::<P>::from_ntt(&pdt_tmp);

        let compressed_w: Vec<i64> = w
            .coeffs
            .iter()
            .map(|&coeff| compress(coeff, 1, P::Q))
            .collect();

        let m = ByteEncode(&compressed_w, 1);
        m
    }
}
