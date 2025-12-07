use hex;
use kyber_rs::constants::KyberParams;
use kyber_rs::kem_scheme::{KemDecapsKey, KemEncapsKey, MlKem};
use kyber_rs::params::{Kyber1024Params, Kyber512Params, Kyber768Params, SecurityLevel};
use kyber_rs::traits::KemScheme;
use rand::rngs::OsRng;

fn run_kem_test<const K: usize, S: SecurityLevel>(test_name: &str) {
    println!("\n--- Running the test : {} ---", test_name);

    let kem = MlKem::<K, S, KyberParams>::new();

    let (ek, dk) = kem.key_gen(&mut OsRng);
    println!(
        "  Generated keys (ek: {} bytes, dk: {} bytes)",
        KemEncapsKey::<K>::len(),
        KemDecapsKey::<K>::len()
    );

    let (k_encaps, c) = kem.encaps(&ek, &mut OsRng);
    println!("  Encapsulated key (K) : {}", hex::encode(&k_encaps.0));
    println!("  Ciphertext generated (c) : {} bytes", c.len());

    let k_decaps = kem.decaps(&dk, &c);
    println!("  Decapsulated key (K') : {}", hex::encode(&k_decaps.0));

    assert_eq!(
        k_encaps.0, k_decaps.0,
        "TEST {} FAILED: Keys do not match !",
        test_name
    );
    println!("  ✅ SUCCESS : {}", test_name);
}

#[test]
fn test_ml_kem_512() {
    run_kem_test::<2, Kyber512Params>("ML-KEM-512");
}

#[test]
fn test_ml_kem_768() {
    run_kem_test::<3, Kyber768Params>("ML-KEM-768");
}

#[test]
fn test_ml_kem_1024() {
    run_kem_test::<4, Kyber1024Params>("ML-KEM-1024");
}
