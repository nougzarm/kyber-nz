pub trait SecurityLevel {
    const ETA1: usize;
    const ETA2: usize;
    const DU: usize;
    const DV: usize;
}

pub struct Kyber512;
pub struct Kyber768;
pub struct Kyber1024;

impl SecurityLevel for Kyber512 {
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
}

impl SecurityLevel for Kyber768 {
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
}
impl SecurityLevel for Kyber1024 {
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
}
