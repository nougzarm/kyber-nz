use core::array;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::constants::PolyParams;
use crate::conversion::{byte_decode, byte_encode, compress, decompress};
use crate::errors::Error;
use crate::hash::{prf, G};
use crate::params::SecurityLevel;
use crate::polynomial::{Polynomial, PolynomialNTT};
use crate::traits::PkeScheme;

pub struct KPke<const K: usize, S: SecurityLevel, P: PolyParams> {
    _marker: std::marker::PhantomData<(S, P)>,
}

impl<const K: usize, S: SecurityLevel, P: PolyParams> KPke<K, S, P> {
    pub fn new() -> Self {
        KPke::<K, S, P> {
            _marker: std::marker::PhantomData::<(S, P)>,
        }
    }
}

impl<const K: usize, S: SecurityLevel, P: PolyParams> Default for KPke<K, S, P> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PkeDecryptKey<const K: usize>(pub [[u8; 384]; K]);

pub struct PkeEncryptKey<const K: usize>(pub [[u8; 384]; K], pub [u8; 32]);

impl<const K: usize, S: SecurityLevel, P: PolyParams> PkeScheme for KPke<K, S, P> {
    type DecryptKey = PkeDecryptKey<K>;
    type EncryptKey = PkeEncryptKey<K>;

    /// Algorithm 13 (FIPS 203) : K-PKE.KeyGen(d)
    ///
    /// Input : randomness d in B^32
    /// Output : (ek, dk) pair of encryption-decryption keys
    /// with : ek in B^(384*k + 32), and dk in B^(384*k)
    fn key_gen(&self, d: &[u8; 32]) -> Result<(Self::EncryptKey, Self::DecryptKey), Error> {
        let mut d_ext = [0u8; 33];
        d_ext[0..32].copy_from_slice(d);
        d_ext[32] = K as u8;

        let (rho, gamma) = G::evaluate(&d_ext);

        let mut n_var = 0u8;

        let mut a_ntt: Vec<PolynomialNTT<P>> = Vec::with_capacity(K * K);
        for i in 0..K {
            for j in 0..K {
                let mut input = [0u8; 34];
                input[0..32].copy_from_slice(&rho);
                input[32] = j as u8;
                input[33] = i as u8;
                a_ntt.push(PolynomialNTT::<P>::sample_ntt(&input));
            }
        }

        let s_ntt: [PolynomialNTT<P>; K] = array::from_fn(|_| {
            let tmp =
                Polynomial::<P>::sample_poly_cbd(&prf(S::ETA1, &gamma, &[n_var]).unwrap(), S::ETA1)
                    .unwrap();
            n_var += 1;
            tmp.to_ntt()
        });

        let e_ntt: [PolynomialNTT<P>; K] = array::from_fn(|_| {
            let tmp =
                Polynomial::<P>::sample_poly_cbd(&prf(S::ETA1, &gamma, &[n_var]).unwrap(), S::ETA1)
                    .unwrap();
            n_var += 1;
            tmp.to_ntt()
        });

        let t_ntt: [PolynomialNTT<P>; K] = array::from_fn(|i| {
            let mut pol_temp = PolynomialNTT::<P>::from([0i16; 256]);

            for (j, poly) in s_ntt.iter().enumerate() {
                let product = &a_ntt[i * K + j] * poly;
                pol_temp += &product;
            }
            &pol_temp + &e_ntt[i]
        });

        const CONST_D: usize = 12;

        let mut ek_content = [[0u8; 384]; K];

        for (i, poly) in t_ntt.iter().enumerate() {
            let mut encoded = [0u8; 384];
            byte_encode(&poly.coeffs, CONST_D, &mut encoded)?;
            ek_content[i] = encoded;
        }

        let mut dk_content = [[0u8; 384]; K];
        for (i, poly) in s_ntt.iter().enumerate() {
            let mut encoded = [0u8; 384];
            byte_encode(&poly.coeffs, CONST_D, &mut encoded)?;
            dk_content[i] = encoded;
        }

        Ok((
            PkeEncryptKey::<K>(ek_content, rho),
            PkeDecryptKey::<K>(dk_content),
        ))
    }

    /// Algorithm 14 (FIPS 203) : K-PKE.Encrypt(ek, m, r)
    ///
    /// Input : encryption key ek in B^(384*k + 32)
    /// Input : message m in B^32
    /// Input : randomness r in B^32
    /// Output : ciphertext c in B^(32 * (d_u * k + d_v))
    fn encrypt(&self, ek: &Self::EncryptKey, m: &[u8; 32], r: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let mut n_var = 0usize;
        let mut t_ntt = Vec::with_capacity(K * K);
        for i in 0..K {
            let chunk = &ek.0[i];
            let coeffs = {
                let mut res = [0i16; 256];
                byte_decode(chunk, 12, P::Q, &mut res)?;
                res
            };
            t_ntt.push(PolynomialNTT::<P>::from_slice(coeffs.as_slice())?);
        }
        let rho = &ek.1;

        let mut a_ntt = Vec::with_capacity(K * K);
        for i in 0..K {
            for j in 0..K {
                let mut input = [0u8; 34];
                input[0..32].copy_from_slice(rho);
                input[32] = j as u8;
                input[33] = i as u8;
                a_ntt.push(PolynomialNTT::<P>::sample_ntt(&input));
            }
        }

        let y_ntt: [PolynomialNTT<P>; K] = array::from_fn(|_| {
            let tmp = Polynomial::<P>::sample_poly_cbd(
                &prf(S::ETA1, r, &[n_var as u8]).unwrap(),
                S::ETA1,
            )
            .unwrap();
            n_var += 1;
            tmp.to_ntt()
        });

        let e_1: [Polynomial<P>; K] = array::from_fn(|_| {
            let tmp = Polynomial::<P>::sample_poly_cbd(
                &prf(S::ETA2, r, &[n_var as u8]).unwrap(),
                S::ETA2,
            )
            .unwrap();
            n_var += 1;
            tmp
        });

        let e_2 = Polynomial::<P>::sample_poly_cbd(&prf(S::ETA2, r, &[n_var as u8])?, S::ETA2)?;

        let u: [Polynomial<P>; K] = array::from_fn(|i| {
            let mut tmp = PolynomialNTT::<P>::from([0i16; 256]);
            for j in 0..K {
                let product = &a_ntt[j * K + i] * &y_ntt[j];
                tmp += &product;
            }
            &Polynomial::<P>::from_ntt(&tmp) + &e_1[i]
        });

        let m_bits = {
            let mut result = [0i16; 256];
            byte_decode(m, 1, P::Q, &mut result)?;
            result
        };

        let mu = {
            let mut coeffs = [0i16; 256];
            for (i, &b) in m_bits.iter().enumerate() {
                coeffs[i] = decompress(b, 1, P::Q);
            }
            Polynomial::<P>::from_slice(&coeffs)?
        };

        let v = {
            let mut tmp = PolynomialNTT::<P>::from([0i16; 256]);
            for i in 0..K {
                tmp += &(&t_ntt[i] * &y_ntt[i]);
            }
            &(&Polynomial::<P>::from_ntt(&tmp) + &e_2) + &mu
        };

        let mut c1 = Vec::new();
        for poly in &u {
            let compressed: Vec<i16> = poly
                .coeffs
                .iter()
                .map(|&c| compress(c, S::DU, P::Q))
                .collect();
            let compressed_encode = {
                let mut result = vec![0u8; 32 * S::DU];
                byte_encode(&compressed, S::DU, &mut result)?;
                result
            };
            c1.extend(compressed_encode);
        }

        let compressed_v: Vec<i16> = v.coeffs.iter().map(|&c| compress(c, S::DV, P::Q)).collect();
        let c2 = {
            let mut result = vec![0u8; 32 * S::DV];
            byte_encode(&compressed_v, S::DV, &mut result)?;
            result
        };

        c1.extend_from_slice(&c2);
        Ok(c1)
    }

    /// Algorithm 15 (FIPS 203) : K-PKE.Decrypt(dk, c)
    ///
    /// Input : decryption key dk in B^(384*k)
    /// Input : ciphertext c in B^(32 * (d_u*k + d_v))
    /// Output : message m in B^32
    fn decrypt(&self, dk: &Self::DecryptKey, c: &[u8]) -> Result<[u8; 32], Error> {
        let c_1 = &c[0..32 * S::DU * K];
        let c_2 = &c[32 * S::DU * K..];

        let mut u_prime = Vec::with_capacity(K);
        for i in 0..K {
            let decode = {
                let mut result = [0i16; 256];
                byte_decode(
                    &c_1[32 * S::DU * i..32 * S::DU * (i + 1)],
                    S::DU,
                    P::Q,
                    &mut result,
                )?;
                result
            };
            let coeffs: Vec<i16> = decode
                .into_iter()
                .map(|val| decompress(val, S::DU, P::Q))
                .collect();
            u_prime.push(Polynomial::<P>::from_slice(coeffs.as_slice())?);
        }

        let decoded_v = {
            let mut result = [0i16; 256];
            byte_decode(c_2, S::DV, P::Q, &mut result)?;
            result
        };
        let v_coeffs: Vec<i16> = decoded_v
            .into_iter()
            .map(|val| decompress(val, S::DV, P::Q))
            .collect();
        let v_prime = Polynomial::<P>::from_slice(v_coeffs.as_slice())?;

        let mut s_ntt = Vec::with_capacity(K);
        for i in 0..K {
            let chunk = &dk.0[i];
            let coeffs = {
                let mut result = [0i16; 256];
                byte_decode(chunk, 12, P::Q, &mut result)?;
                result
            };
            s_ntt.push(PolynomialNTT::<P>::from_slice(coeffs.as_slice())?);
        }

        let w = {
            let mut tmp = PolynomialNTT::<P>::from([0i16; 256]);
            for i in 0..K {
                tmp += &(&s_ntt[i] * &u_prime[i].to_ntt());
            }
            &v_prime - &Polynomial::<P>::from_ntt(&tmp)
        };

        let compressed_w: Vec<i16> = w
            .coeffs
            .iter()
            .map(|&coeff| compress(coeff, 1, P::Q))
            .collect();

        let mut result = [0u8; 32];
        byte_encode(compressed_w.as_slice(), 1, &mut result)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::KyberParams;

    struct SecurityL;
    impl SecurityLevel for SecurityL {
        const ETA1: usize = 2;
        const ETA2: usize = 2;
        const DU: usize = 10;
        const DV: usize = 4;
    }

    #[test]
    fn basics() -> Result<(), Error> {
        let pke_scheme = KPke::<3, SecurityL, KyberParams>::new();

        let seed = b"Salut de la part de moi meme lee";
        let (ek, dk) = pke_scheme.key_gen(seed)?;

        let message = b"Ce message est tres confidentiel";
        let ciphertext = pke_scheme.encrypt(&ek, message, seed)?;
        assert_eq!(ciphertext, hex::decode("012ac1758bc94772b397ca25074f4a215bdf198f247b7c752570718c8cb343026ab5d3d2f3d077b027eadb4f48e5f03b2e6269a526404b2da74b3f37fece1d855839434f9d9248bae4d368cf641ec582de41d5844123b0154e9ec72e1bf945c65e3b3b07fd838c1b2f810f1ba7b6edc8ff2f8c30cdc5bb962a9cf003763442388ff329714fff31d74614572c3d29106a58400e8c0192fe956a48f80b0d9ae0702b5ab92e3fa21b08185418acd32f7e95f451e5577138bf88c04e792544f325dacff933cb44bca9ed3c947d4b1af6bed402dd9abefdd752cf835924c1497f3fb0e8a5fc0af2e4256120f0eeac759194661a6e3fdb21f7b2dd69bc35cecc827fa63639dab275a2979b52db602a7bb82bbaeb00ff77e0f2a0c9eb62cc67eb374cf930b59afa48b1bffcb4ec35c9050a5b3f3ee1e7602eec383095b3405a5c2a9a34a1bd65349706ace75e4e5700661a49097bc395e3529cea3dad0a60360166fd6c39a3e4448b7b9a019810ae1f2788ea4e59c70fc3a86402bce1de829b300c765fc04fb868ddbfe18415742d87d9c61b04dbb25212a4d0f94cef95b1a0ae14802d7a2ed594c72744fd8edb3b5042bb097e6b3ee2453ea11f8ec3c605de358ab9e20d030c709963084da663a0d9960fe219f565ddd28de3cf55700ca52fefacaeff1eb4a33acd0e03451f7426cd366d2bc2ec15908fe8df228d18eb895cb02bc58881dc7d0257212e8a0629ce9e7dfbc1d6e5674ad03ecb856896effefdf4a2e04b8d2751588d50202e6561c557058bc4987f91e992039a8c113a0ee0526b8bdfe3794988e7def3d274db03bb44b6641cc1796ebdfac2168d40aa2bbee9676d8f7526883579f3244c80ba7c052adeaa25e897621c2e723738ab1d3d357be714f1c1098185e46df87152ab4036da585f5c6c8afe971d9ffefa49bd446e4c625e9e9455c79d7f8f744c4e6baccb8cb85dfbb06f10348ee605eb6764623175fcfd90ceb9c62e5969618bf4663650798d96acd35c5840ba5eb9cf01b61f62677648e4f4087589be566edc9df121f686665b1eb56ab265807125abba488df00d174d6f01aa9b5c70b83ae18cfced6aad04eebfb41831d65b4169cd36f0d6a18888d1244eba5b659a2be54f70ee2d3c4a6431b83f63b676dc636169b8d3f3aa8ac3b285339fd657087745a70324a35904c501f9a60d3d89463e063ea9757c381b33bf1aa3ec6acfef970e54a1369e5d123e357f4b28dedaf0775fe24014414a83a6b603cd2d0e51aab08238b11f7edc685697328adf7fce4bf05e20de54b4843f163060dc2848685338584a90660d52fdf9f482f49669fee04bdd9a0c4296de160cf2405e249844de8ba1ba815bc6ad86146a8798ea723f00601e77f1455872be02cabf47dde765913ed904b34eb00efee1d7bc3181b4dddb3441b12d5660803a50658a2bb567ccf50af9ef7e07903902265f43d57270374a30d89bc964ec5a076cc8276c4788e289957fb0efa5a7d5ea688ff56c55e91488c4b79bc3177fcf2c469b7c9b")
                .unwrap());

        let mess_decrypt = pke_scheme.decrypt(&dk, &ciphertext)?;
        assert_eq!(mess_decrypt, *message);
        Ok(())
    }
}
