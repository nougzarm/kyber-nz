use hex;
use pqc_rs::constants::KyberParams;
use pqc_rs::kyber::kem_scheme::MlKem;

fn run_kem_test(k: usize, eta_1: usize, eta_2: usize, du: usize, dv: usize, test_name: &str) {
    println!("\n--- Running the test : {} ---", test_name);

    let kem = MlKem::<KyberParams>::new(k, eta_1, eta_2, du, dv);

    let (ek, dk) = kem.key_gen();
    println!(
        "  Generated keys (ek: {} bytes, dk: {} bytes)",
        ek.len(),
        dk.len()
    );

    let (k_encaps, c) = kem.encaps(&ek);
    println!("  Encapsulated key (K) : {}", hex::encode(&k_encaps));
    println!("  Ciphertext generated (c) : {} bytes", c.len());

    let k_decaps = kem.decaps(&dk, &c);
    println!("  Decapsulated key (K') : {}", hex::encode(&k_decaps));

    assert_eq!(
        k_encaps, k_decaps,
        "TEST {} FAILED: Keys do not match !",
        test_name
    );
    println!("  ✅ SUCCESS : {}", test_name);
}

#[test]
fn test_ml_kem_512() {
    run_kem_test(2, 3, 2, 10, 4, "ML-KEM-512");
}

#[test]
fn test_ml_kem_768() {
    run_kem_test(3, 2, 2, 10, 4, "ML-KEM-768");
}

#[test]
fn test_ml_kem_1024() {
    run_kem_test(4, 2, 2, 11, 5, "ML-KEM-1024");
}
