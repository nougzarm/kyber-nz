use rand::RngCore;
use rand::rngs::OsRng;
use sha3::digest::Update;
use sha3::{Digest, Sha3_256, Sha3_512};
use subtle::{ConditionallySelectable, ConstantTimeEq};

use crate::hash::{g, j};
use crate::pke_scheme::{PkeDecryptKey, PkeEncryptKey};
use crate::traits::KemScheme;
use crate::{constants::PolyParams, pke_scheme::KPke, traits::PkeScheme};

pub struct MlKem<const K: usize, P: PolyParams>(pub KPke<K, P>);

impl<const K: usize, P: PolyParams> MlKem<K, P> {
    pub fn new(eta_1: usize, eta_2: usize, d_u: usize, d_v: usize) -> Self {
        MlKem(KPke::<K, P>::new(eta_1, eta_2, d_u, d_v))
    }
}

pub struct KemDecapsKey<const K: usize>(pub [[u8; 384]; K], pub [[u8; 384]; K], pub [u8; 96]);

impl<const K: usize> KemDecapsKey<K> {
    pub fn len() -> usize {
        768 * K + 96
    }
}

pub struct KemEncapsKey<const K: usize>(pub [[u8; 384]; K], pub [u8; 32]);

impl<const K: usize> KemEncapsKey<K> {
    pub fn len() -> usize {
        384 * K + 32
    }
}

impl<const K: usize, P: PolyParams> KemScheme for MlKem<K, P> {
    type DecapsKey = KemDecapsKey<K>;
    type EncapsKey = KemEncapsKey<K>;

    /// Algorithm 16 (FIPS 203) : ML-KEM.KeyGen_internal(d, z)
    /// Uses randomness to generate an encapsulation key and a corresponding decapsulation key.
    ///
    /// Input : randomness d in B^32
    /// Input : randomness z in B^32
    /// Output : encapsulation key ek in B^(384*k + 32)
    /// Output : decapsulation key dk in B^(768*k + 96)
    fn key_gen_internal(&self, d: &[u8; 32], z: &[u8; 32]) -> (Self::EncapsKey, Self::DecapsKey) {
        let (pke_encrypt_key, pke_decrypt_key) = self.0.key_gen(d);
        let mut decaps_2_content = [0u8; 96];
        decaps_2_content[..32].copy_from_slice(&pke_encrypt_key.1);

        // h function from hash.rs
        let mut hasher = Sha3_256::new();
        for slice in &pke_encrypt_key.0 {
            Update::update(&mut hasher, slice);
        }
        Update::update(&mut hasher, &pke_encrypt_key.1);
        let h_res: [u8; 32] = hasher.finalize().into();

        decaps_2_content[32..64].copy_from_slice(&h_res);
        decaps_2_content[64..].copy_from_slice(z);

        let decaps_key = KemDecapsKey::<K>(pke_decrypt_key.0, pke_encrypt_key.0, decaps_2_content);
        let encaps_key = KemEncapsKey::<K>(pke_encrypt_key.0, pke_encrypt_key.1);

        (encaps_key, decaps_key)
    }

    /// Algorithm 17 (FIPS 203) : ML-KEM.Encaps_internal(ek, m)
    /// Uses the encapsulation key and randomness to generate a key and an associated ciphertext.
    ///
    /// Input : encapsulation key ek in B^(384*k + 32)
    /// Input : randomness m in B^32
    /// Output : shared secret key K in B^32
    /// Output : ciphertext c in B^(32 * (d_u*k + d_v))
    fn encaps_internal(&self, ek: &Self::EncapsKey, m: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        // g function from hash.rs
        let mut g_hasher = Sha3_512::new();
        Update::update(&mut g_hasher, m);

        // h function from hash.rs
        let mut h_hasher = Sha3_256::new();
        for slice in &ek.0 {
            Update::update(&mut h_hasher, slice);
        }
        Update::update(&mut h_hasher, &ek.1);
        let h_res: [u8; 32] = h_hasher.finalize().into();

        Update::update(&mut g_hasher, &h_res);

        let result = g_hasher.finalize();

        let mut k = [0u8; 32];
        let mut r = [0u8; 32];
        k.copy_from_slice(&result[0..32]);
        r.copy_from_slice(&result[32..64]);

        let c = self.0.encrypt(&PkeEncryptKey::<K>(ek.0, ek.1), m, &r);

        (k.to_vec(), c)
    }

    /// Algorithm 18 (FIPS 203) : ML-KEM.Decaps_internal(dk, c)
    /// Uses the decapsulation key to produce a shared secret key from a ciphertext.
    ///
    /// Input : decapsulation key dk in B^(768*k + 96)
    /// Input : ciphertext c in B^(32 * (d_u*k + d_v))
    /// Output : shared secret key K in B^32
    fn decaps_internal(&self, dk: &Self::DecapsKey, c: &[u8]) -> Vec<u8> {
        let dk_pke = PkeDecryptKey(dk.0);

        let mut ek_pke_1 = [0u8; 32];
        ek_pke_1.copy_from_slice(&dk.2[..32]);
        let ek_pke = PkeEncryptKey(dk.1, ek_pke_1);

        let m_prime = self.0.decrypt(&dk_pke, c);

        let mut g_hash = vec![];
        g_hash.extend_from_slice(&m_prime);
        g_hash.extend_from_slice(&dk.2[32..64]);
        let (mut k_prime, r_prime) = g(&g_hash);

        let mut j_hash = vec![];
        j_hash.extend_from_slice(&dk.2[64..96]);
        j_hash.extend_from_slice(c);
        let k_bar = j(&j_hash);

        let m_prime_slice: [u8; 32] = m_prime.as_slice().try_into().expect("");
        let c_prime = self.0.encrypt(&ek_pke, &m_prime_slice, &r_prime);

        let cond = !(c.ct_eq(&c_prime));

        for (dst, src) in k_prime.iter_mut().zip(k_bar.iter()) {
            dst.conditional_assign(src, cond);
        }

        k_prime.to_vec()
    }

    /// Algorithm 19 (FIPS 203) : ML-KEM.KeyGen()
    /// Generates an encapsulation key and a corresponding decapsulation key.
    ///
    /// Output : encapsulation key ek in B^(384*k + 32)
    /// Output : decapsulation key dk in B^(768*k + 96)
    fn key_gen(&self) -> (Self::EncapsKey, Self::DecapsKey) {
        let mut d = [0u8; 32];
        OsRng.fill_bytes(&mut d);

        let mut z = [0u8; 32];
        OsRng.fill_bytes(&mut z);

        self.key_gen_internal(&d, &z)
    }

    /// Algorithm 20 (FIPS 203) : ML-KEM.Encaps(ek)
    /// Uses the encapsulation key to generate a shared secret key and an associated ciphertext
    ///
    /// Input : encapsulation key ek in B^(384*k + 32)
    /// Output : shared secret key K in B^32
    /// Output : ciphertext c in B^(32 * (d_u*k + d_v))
    fn encaps(&self, ek: &Self::EncapsKey) -> (Vec<u8>, Vec<u8>) {
        let mut m = [0u8; 32];
        OsRng.fill_bytes(&mut m);

        self.encaps_internal(ek, &m)
    }

    /// Algorithm 21 (FIPS 203) : ML-KEM.Decaps(dk, c)
    /// Uses the decapsulation key to produce a shared secret key from a ciphertext.
    ///
    /// Input : decapsulation key dk in B^(768*k + 96)
    /// Input : ciphertext c in B^(32 * (d_u*k + d_v))
    /// Output : shared secret key K in B^32
    fn decaps(&self, dk: &Self::DecapsKey, c: &[u8]) -> Vec<u8> {
        self.decaps_internal(dk, c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{constants::KyberParams, hash::h};

    #[test]
    fn basics() {
        let (_k, eta_1, eta_2, d_u, d_v) = (3, 2, 2, 10, 4);
        let kem_scheme = MlKem::<3, KyberParams>::new(eta_1, eta_2, d_u, d_v);

        let d = h(b"randomness d");
        let z = j(b"randomness z");
        let (ek, dk) = kem_scheme.key_gen_internal(&d, &z);

        let seed = h(b"seed permettant l encapsulation");
        let (k, c) = kem_scheme.encaps_internal(&ek, &seed);
        assert_eq!(c, hex::decode("aaaae490a2820e03d5252fb685d64e3bbcaf7e5119c39c5e96168297cb21cc291acfa96f7443b0fe25176f87cc722a742d917a7c13a189e9c97a326a398486cc11bc3301b70c38d93b98d4bc53761e847166a6f9bc0eac3b1f648404f9ff20feb92dfa68dc6e5ae697d9f853c5a4c486bbc9344665fcb6319872f2ca021042712cf412f0c622f93be7cdbed75654a8826ecd5734a843f331ee9e10306b2e287cf81c9621434020db2a55182ea543c14d28274375a76f7764ff09517d32b2dc0d97ae908136aa054111b23e948b038ade262fbdd78e3e84243582d8a9a836109ab9b0ad4b8eb2468ae9750437903d8fecee33c6b0a986d34fcda3b3e8926d39f3b19c0dc03b7a066d92b5b756495b6bd6ec472235b757d20a50b7733c2a03cb516f378e0b4a5b48daf4a324e21d93ce65221261734a5978d8ff5870e06fb61de7ea04acb1bf20cbd7a6de9627f5707685640389fb89c98695314eac05231ac04d8ae92cc99f05405b692bd9d1d0a411285668f4e422143a7ddfc544d13446f0caae9e1387a1f91f19d08cc2be7c6eb31337f8680e87d11d4768dd97dd517eafcde4641b588e729b9e5928372868cf9ce443dd45b142b6f79383041b2676e0b9dab5166f9f7101d824dad711b6fb2d8d7e370038da229d545a82a7cf705fcd223273d29bf47ff49b2fb1f37a9d7463fe61ad4d91dbb5ba5a89c6a4c8ed0d2e69aa866d2ed5f056f72d3caf6ab1e13fdf1da78fe26c84844c3b52c758bf79d855e32734b58e742f795920d71a87c1f9204d60d1c9b3800a64035cd5a5de6f6de8774103ec18080296cafe747a9384ce0fe1faad8c0d256fe2311df570fb4f539fc8d8bfd645371e91808aada68c48263b4d74cf071f7a1564c06d0e17f4855c26f8387cf45b42ade887110c63f29817cf7c0a155a3e2259592943685a2f5c0c59aa8001f07148b076e4ca8abc73e70b028f5431da1fc12a0e066f0674ee05f697c2b415bf132a90be4b3f66ffad9186bc7990593f970e590edf553180d66abb7ab0f940e75bac02df54b51177857bd5317ad27f7a3420e5affe5527c9710de6f28049f4700ceca2a23c7eefb4195812684b5bdc31bc85eb330a8948388d90db3ab677b7f54d7fbc418e98fce6f2f811143d952986e9cef0adc12e7a00e345b210f68de2513c83e21757b9a29b614e30c932c538df1ff2c9342fa8af49164d97338d489f06f807f7edd84d2b8f51d283a237ef595be4a7b0e9d60d9fcdb0d20a63d1f924133618e8c393344c6edb1d9f68c3f710dfbfaf00b93ee5ff4a3ac2ef439126ae370f357fb4e44f43178e9bd6893113e8f7bdbf08afcb751d1e2b07d2d9e6cc1924a7277956ca226416b64f6357a3eb0b1ef8164f6d03d96c34f7cbc72a3aae4f2ffae05f93a18d3c79e2674b3a19045457905b340af018092a19d2360dcf40d24fd7e9a89a80ae802a3a278714bc72793e58f4af84890f6fd9cc4f5a844c9ba65463289592e95d6e4a5998b6626229d0d753f6d22cc5686650ce454f9b10")
                .unwrap());

        let k_decaps = kem_scheme.decaps_internal(&dk, &c);
        assert_eq!(k_decaps, k);

        let (ek, dk) = kem_scheme.key_gen();

        let (k, c) = kem_scheme.encaps(&ek);

        let k_decaps = kem_scheme.decaps(&dk, &c);
        assert_eq!(k_decaps, k);
    }
}
