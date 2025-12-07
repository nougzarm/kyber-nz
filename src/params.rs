pub trait SecurityLevel {
    const ETA1: usize;
    const ETA2: usize;
    const DU: usize;
    const DV: usize;
}

pub struct Kyber512Params;
pub struct Kyber768Params;
pub struct Kyber1024Params;

impl SecurityLevel for Kyber512Params {
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
}

impl SecurityLevel for Kyber768Params {
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
}
impl SecurityLevel for Kyber1024Params {
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
}
