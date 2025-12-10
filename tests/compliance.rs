use kyber_nz::constants::{KyberParams, PolyParams};
use kyber_nz::kem_scheme::{KemDecapsKey, KemEncapsKey, MlKem};
use kyber_nz::params::{Kyber1024Params, Kyber512Params, Kyber768Params, SecurityLevel};
use kyber_nz::traits::KemScheme;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

fn flatten_encaps_key<const K: usize>(key: &KemEncapsKey<K>) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in &key.0 {
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&key.1);
    out
}

fn flatten_decaps_key<const K: usize>(key: &KemDecapsKey<K>) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in &key.0 {
        out.extend_from_slice(chunk);
    }
    for chunk in &key.1 {
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&key.2);
    out
}

#[derive(Default, Debug)]
struct TestCase {
    count: Option<usize>,
    d: Option<Vec<u8>>,
    z: Option<Vec<u8>>,
    msg: Option<Vec<u8>>,
    pk: Option<Vec<u8>>,
    sk: Option<Vec<u8>>,
    ct: Option<Vec<u8>>,
    ss: Option<Vec<u8>>,
}

impl TestCase {
    fn is_complete(&self) -> bool {
        self.d.is_some()
            && self.z.is_some()
            && self.msg.is_some()
            && self.pk.is_some()
            && self.sk.is_some()
            && self.ct.is_some()
            && self.ss.is_some()
    }
}

fn process_kat_file<const K: usize, S, P>(filename: &str)
where
    S: SecurityLevel,
    P: PolyParams,
{
    let filepath = format!("tests/test_vectors/{}", filename);
    let path = Path::new(&filepath);

    if !path.exists() {
        eprintln!(
            "⚠️  WARNING: File '{}' not found. Test ignored.",
            filename
        );
        return;
    }

    println!("Testing compliance using {}...", filename);
    let file = File::open(path).expect("Unable to open the file");
    let reader = BufReader::new(file);

    let kem = MlKem::<K, S, P>::new();
    let mut current_case = TestCase::default();

    for line_res in reader.lines() {
        let line = line_res.expect("Line reading error");
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, '=').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            continue;
        }

        let key = parts[0];
        let value_hex = parts[1];

        let value_bytes = if key != "count" && key != "seed" {
            Some(hex::decode(value_hex).unwrap_or_else(|_| panic!("Hex invalid line: {}", line)))
        } else {
            None
        };

        match key {
            "count" => {
                current_case = TestCase::default();
                current_case.count = Some(value_hex.parse().unwrap());
            }
            "d" => current_case.d = value_bytes,
            "z" => current_case.z = value_bytes,
            "msg" => current_case.msg = value_bytes,
            "pk" => current_case.pk = value_bytes,
            "sk" => current_case.sk = value_bytes,
            "ct" => current_case.ct = value_bytes,
            "ss" => current_case.ss = value_bytes,
            _ => {}
        }

        if current_case.is_complete() {
            run_single_test(&kem, &current_case);
            current_case = TestCase::default();
        }
    }
}

fn run_single_test<const K: usize, S, P>(kem: &MlKem<K, S, P>, case: &TestCase)
where
    S: SecurityLevel,
    P: PolyParams,
{
    let count = case.count.unwrap();
    let d: [u8; 32] = case.d.clone().unwrap().try_into().unwrap();
    let z: [u8; 32] = case.z.clone().unwrap().try_into().unwrap();
    let m: [u8; 32] = case.msg.clone().unwrap().try_into().unwrap();

    // 1. KeyGen
    let (ek, dk) = kem.key_gen_internal(&d, &z).unwrap();

    let ek_flat = flatten_encaps_key(&ek);
    let dk_flat = flatten_decaps_key(&dk);

    assert_eq!(
        &ek_flat,
        case.pk.as_ref().unwrap(),
        "❌ [Count {}] PK mismatch",
        count
    );
    assert_eq!(
        &dk_flat,
        case.sk.as_ref().unwrap(),
        "❌ [Count {}] SK mismatch",
        count
    );

    // 2. Encaps
    let (ss_bob, ct) = kem.encaps_internal(&ek, &m).unwrap();
    assert_eq!(
        &ct,
        case.ct.as_ref().unwrap(),
        "❌ [Count {}] CT mismatch",
        count
    );
    assert_eq!(
        &ss_bob.0.to_vec(),
        case.ss.as_ref().unwrap(),
        "❌ [Count {}] SS (Bob) mismatch",
        count
    );

    // 3. Decaps
    let ss_alice = kem.decaps_internal(&dk, &ct).unwrap();
    assert_eq!(
        &ss_alice.0.to_vec(),
        case.ss.as_ref().unwrap(),
        "❌ [Count {}] SS (Alice) mismatch",
        count
    );
}

#[test]
fn test_kat_mlkem_512() {
    process_kat_file::<2, Kyber512Params, KyberParams>("kat_MLKEM_512.rsp");
}

#[test]
fn test_kat_mlkem_768() {
    process_kat_file::<3, Kyber768Params, KyberParams>("kat_MLKEM_768.rsp");
}

#[test]
fn test_kat_mlkem_1024() {
    process_kat_file::<4, Kyber1024Params, KyberParams>("kat_MLKEM_1024.rsp");
}
