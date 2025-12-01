pub trait PkeScheme {
    type DecryptKey;
    type EncryptKey;

    fn key_gen(&self, d: &[u8; 32]) -> (Self::EncryptKey, Self::DecryptKey);

    fn encrypt(&self, ek: &Self::EncryptKey, m: &[u8; 32], r: &[u8; 32]) -> Vec<u8>;

    fn decrypt(&self, dk: &Self::DecryptKey, c: &[u8]) -> Vec<u8>;
}

pub trait KemScheme {
    type DecapsKey;
    type EncapsKey;

    fn key_gen_internal(&self, d: &[u8; 32], z: &[u8; 32]) -> (Self::EncapsKey, Self::DecapsKey);

    fn key_gen(&self) -> (Self::EncapsKey, Self::DecapsKey);

    fn encaps_internal(&self, ek: &Self::EncapsKey, m: &[u8; 32]) -> (Vec<u8>, Vec<u8>);

    fn encaps(&self, ek: &Self::EncapsKey) -> (Vec<u8>, Vec<u8>);

    fn decaps_internal(&self, dk: &Self::DecapsKey, c: &[u8]) -> Vec<u8>;

    fn decaps(&self, dk: &Self::DecapsKey, c: &[u8]) -> Vec<u8>;
}
