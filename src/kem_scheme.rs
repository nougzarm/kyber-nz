use rand::rngs::OsRng;
use rand::RngCore;

use crate::{constants::PolyParams, pke_scheme::K_PKE};
use crate::hash::{g, h, j};

pub struct ML_KEM<P: PolyParams>(pub K_PKE<P>);

impl<P: PolyParams> ML_KEM<P> {
    pub fn new(k: usize, eta_1: usize, eta_2: usize, d_u: usize, d_v: usize) -> Self {
        ML_KEM(K_PKE::<P>::new(k, eta_1, eta_2, d_u, d_v))
    }

    /// Algorithm 16 : ML-KEM.KeyGen_internal(d, z)
    /// Uses randomness to generate an encapsulation key and a corresponding decapsulation key.
    /// 
    /// Input : randomness d in B^32
    /// Input : randomness z in B^32
    /// Output : encapsulation key ek in B^(384*k + 32)
    /// Output : decapsulation key dk in B^(768*k + 96)
    pub fn key_gen_internal(&self, d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let (ek_pke, mut dk) = self.0.key_gen(d);
        dk.extend_from_slice(&ek_pke);
        dk.extend_from_slice(&h(&ek_pke));
        dk.extend_from_slice(z);

        (ek_pke, dk)
    }

    /// Algorithm 17 : ML-KEM.Encaps_internal(ek, m)
    /// Uses the encapsulation key and randomness to generate a key and an associated ciphertext.
    /// 
    /// Input : encapsulation key ek in B^(384*k + 32)
    /// Input : randomness m in B^32
    /// Output : shared secret key K in B^32
    /// Output : ciphertext c in B^(32 * (d_u*k + d_v))
    pub fn encaps_internal(&self, ek: &[u8], m: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let mut g_seed = m.to_vec();
        g_seed.extend_from_slice(&h(ek));
        let (k, r) = g(&g_seed);
        let c = self.0.encrypt(ek, m, &r);

        (k.to_vec(), c)
    }

    /// Algorithm 18 : ML-KEM.Decaps_internal(dk, c)
    /// Uses the decapsulation key to produce a shared secret key from a ciphertext.
    /// 
    /// Input : decapsulation key dk in B^(768*k + 96)
    /// Input : ciphertext c in B^(32 * (d_u*k + d_v))
    /// Output : shared secret key K in B^32
    pub fn decaps_internal(&self, dk: &[u8], c: &[u8]) -> Vec<u8> {
        let dk_pke = &dk[0 .. 384 * self.0.k];
        let ek_pke = &dk[384 * self.0.k .. 768 * self.0.k + 32];
        let h = &dk[768 * self.0.k + 32 .. 768 * self.0.k + 64];
        let z = &dk[768 * self.0.k + 64 ..];
        let m_prime = self.0.decrypt(dk_pke, c);

        let mut g_hash = vec![];
        g_hash.extend_from_slice(&m_prime);
        g_hash.extend_from_slice(&h);
        let (mut K_prime, r_prime) = g(&g_hash);

        let mut j_hash = vec![];
        j_hash.extend_from_slice(z);
        j_hash.extend_from_slice(c);
        let k_bar = j(&j_hash);

        let m_prime_slice: [u8; 32] = m_prime.as_slice().try_into().expect("");
        let c_prime = self.0.encrypt(ek_pke, &m_prime_slice, &r_prime);

        if c != c_prime {
            K_prime = k_bar;
        };

        K_prime.to_vec()
    }

    /// Algorithm 19 : ML-KEM.KeyGen()
    /// Generates an encapsulation key and a corresponding decapsulation key.
    /// 
    /// Output : encapsulation key ek in B^(384*k + 32)
    /// Output : decapsulation key dk in B^(768*k + 96)
    pub fn key_gen(&self) -> (Vec<u8>, Vec<u8>) {
        let mut d = [0u8; 32];
        OsRng.fill_bytes(&mut d);

        let mut z = [0u8; 32];
        OsRng.fill_bytes(&mut z);

        self.key_gen_internal(&d, &z)
    }

    /// Algorithm 20 : ML-KEM.Encaps(ek)
    /// Uses the encapsulation key to generate a shared secret key and an associated ciphertext
    /// 
    /// Input : encapsulation key ek in B^(384*k + 32)
    /// Output : shared secret key K in B^32
    /// Output : ciphertext c in B^(32 * (d_u*k + d_v))
    pub fn encaps(&self, ek: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut m = [0u8; 32];
        OsRng.fill_bytes(&mut m);

        self.encaps_internal(ek, &m)
    }

    /// Algorithm 21 : ML-KEM.Decaps(dk, c)
    /// Uses the decapsulation key to produce a shared secret key from a ciphertext.
    /// 
    /// Input : decapsulation key dk in B^(768*k + 96)
    /// Input : ciphertext c in B^(32 * (d_u*k + d_v))
    /// Output : shared secret key K in B^32
    pub fn decaps(&self, dk: &[u8], c: &[u8]) -> Vec<u8> {
        self.decaps_internal(dk, c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::KyberParams;

    #[test]
    fn basics() {
        let (k, eta_1, eta_2, d_u, d_v) = (3, 2, 2, 10, 4);
        let kem_scheme = ML_KEM::<KyberParams>::new(k, eta_1, eta_2, d_u, d_v);

        let d = h(b"randomness d");
        let z = j(b"randomness z");
        let (ek, dk) = kem_scheme.key_gen_internal(&d, &z);

        let seed = h(b"seed permettant l encapsulation");
        let (k, c) = kem_scheme.encaps_internal(&ek, &seed);

        let k_decaps = kem_scheme.decaps_internal(&dk, &c);
        assert_eq!(k_decaps, k);

        let (ek, dk) = kem_scheme.key_gen();

        let (k, c) = kem_scheme.encaps(&ek);

        let k_decaps = kem_scheme.decaps(&dk, &c);
        assert_eq!(k_decaps, k);
    }
}