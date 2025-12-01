use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake256};

use crate::errors::Error;

/// Matches the definition in (4.2) and in (4.3)
/// PRF : {2, 3} x B^32 x B -> B^(64*eta)
pub fn prf(eta: usize, s: &[u8; 32], b: &[u8; 1]) -> Result<Vec<u8>, Error> {
    if eta != 2 && eta != 3 {
        return Err(Error::InvalidEta);
    }

    let mut hasher = Shake256::default();
    hasher.update(s);
    hasher.update(b);

    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; 64 * eta];
    reader.read(&mut output);

    Ok(output)
}

/// Matches the definition in (4.4 FIPS 203)
/// H : B* -> B^32
pub fn h(s: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Update::update(&mut hasher, s);

    hasher.finalize().into()
}

/// Matches the definition in (4.4 FIPS 203)
/// J : B* -> B^32
pub fn j(s: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(s);

    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; 32];
    reader.read(&mut output);

    output
}

/// Matches the definition in (4.5 FIPS 203)
/// G : B* -> B^32 x B^32
pub fn g(c: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Sha3_512::new();
    Update::update(&mut hasher, c);
    let result = hasher.finalize();

    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&result[0..32]);
    b.copy_from_slice(&result[32..64]);

    (a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        let seed_s = b"qjdhfyritoprlkdjfkrjfbdnzyhdjrtr";
        let nonce_b = b"a";

        let prf_result = prf(2, seed_s, nonce_b).unwrap();
        assert_eq!(prf_result, hex::decode("eedb2631fdc3c6748dc567534e90eb016d087e6c088f3de6f815e854e6a78daf4181a01d80f26c1f9d2816f95e2427b8e261cc45dc2a98f96a81db2235b0f4d02c4a6b2ad94e3444dc921fc0ed378bca86a9eec7179c45be3f6b9809a4770012e7cd143872e45b7bf8f34e6819102d5a55f32a1f9d105a8b3dfe25af75d76f93").unwrap());

        let h_result = h(seed_s);
        assert_eq!(
            h_result.to_vec(),
            hex::decode("af791f788a6048e5f16b9ee9ef12add7a3fcdf2d615f79960c588bdc9824178f")
                .unwrap()
        );

        let j_result = j(seed_s);
        assert_eq!(
            j_result.to_vec(),
            hex::decode("1ffbe9a12ca007f5e869838bd0ba33284554800575b87b1023bbfe41a7332b7a")
                .unwrap()
        );

        let (g_a, g_b) = g(seed_s);
        assert_eq!(
            (g_a.to_vec(), g_b.to_vec()),
            (
                hex::decode("132f6750e8aafeee8cff75bafdf1cae43307ac23878d5403990b33664bdec268")
                    .unwrap(),
                hex::decode("73fe4185b09c291388961a4420b40a44705538502490b755b27e88d723f85192")
                    .unwrap()
            )
        );
    }
}
