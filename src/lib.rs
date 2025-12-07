use crate::params::{Kyber1024Params, Kyber512Params, Kyber768Params};
use crate::{constants::KyberParams, kem_scheme::MlKem, polynomial::Polynomial};

pub mod constants;
pub mod conversion;
pub mod errors;
pub mod hash;
pub mod kem_scheme;
pub mod params;
pub mod pke_scheme;
pub mod polynomial;
pub mod traits;

pub type KyberPoly = Polynomial<KyberParams>;

pub type Kyber512 = MlKem<2, Kyber512Params, KyberParams>;
pub type Kyber768 = MlKem<3, Kyber768Params, KyberParams>;
pub type Kyber1024 = MlKem<4, Kyber1024Params, KyberParams>;
