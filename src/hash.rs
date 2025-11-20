use sha3::{Shake128, digest::{Update, ExtendableOutput}};

pub trait XOF {
    fn new() -> Self;

    fn absorb(&mut self, bytes: Vec<u8>);

    fn squeeze(&mut self, length: usize) -> Vec<u8>;
}

pub struct SHAKE128 (Shake128);

impl XOF for SHAKE128 {
    fn new() -> Self {
        SHAKE128(Shake128::default())
    }

    fn absorb(&mut self, bytes: Vec<u8>) {
        self.0.update(&bytes);
    }

    fn squeeze(&mut self, length: usize) -> Vec<u8> {
        let mut output = vec![0u8; length];
        self.0.clone().finalize_xof_into(&mut output);
        output
    }
}