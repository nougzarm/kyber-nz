//! # kyber-nz (ML-KEM / FIPS 203)
//!
//! A **pure Rust**, **secure**, and **robust** implementation of the **FIPS 203** (Module-Lattice-Based Key-Encapsulation Mechanism) standard,
//! formerly known as **CRYSTALS-Kyber**.
//!
//! This library strives for excellence in security (resistance to side-channel attacks)
//! and reliability (strict error handling).
//!
//! ## 🛡️ Security & Robustness
//!
//! * **Constant Time**: All sensitive operations (especially decapsulation and hash comparison)
//!   are performed in constant time using the [`subtle`] crate to prevent Timing Attacks.
//! * **Memory Clearing**: Structures containing secrets (`KemDecapsKey`, `KemSharedSecret`) implement
//!   the [`zeroize::Zeroize`] and [`zeroize::ZeroizeOnDrop`] traits. They are automatically wiped from RAM
//!   when they go out of scope.
//! * **Determinism**: Key generation and encapsulation functions accept an external random number generator
//!   (implementing [`rand_core::RngCore`]), allowing for deterministic tests (Known Answer Tests).
//!
//! ## 🚀 Quick Start (ML-KEM-768)
//!
//! ```rust
//! use kyber_nz::Kyber768; // Alias for ML-KEM-768
//! use kyber_nz::traits::KemScheme;
//! use rand::rngs::OsRng;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Initialization
//! let kem = Kyber768::new();
//!
//! // 2. Key Generation (Alice)
//! let (ek, dk) = kem.key_gen(&mut OsRng);
//!
//! // 3. Encapsulation (Bob)
//! let (shared_secret_bob, ciphertext) = kem.encaps(&ek, &mut OsRng);
//!
//! // 4. Decapsulation (Alice)
//! let shared_secret_alice = kem.decaps(&dk, &ciphertext);
//!
//! // The secrets are identical
//! assert_eq!(shared_secret_bob.0, shared_secret_alice.0);
//! # Ok(())
//! # }
//! ```
//!
//! ## 📦 Architecture
//!
//! The library is structured in a modular way:
//!
//! - [`kem_scheme`]: Implementation of the Key Encapsulation Mechanism (ML-KEM).
//! - [`pke_scheme`]: Implementation of the underlying Public Key Encryption (K-PKE).
//! - [`polynomial`]: Polynomial arithmetic on the ring $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$.
//! - [`params`]: Definition of security parameters via the [`params::SecurityLevel`] trait.

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

/// Type alias for a polynomial in the ring R_q with Kyber parameters.
pub type KyberPoly = Polynomial<KyberParams>;

/// Alias for **ML-KEM-512**.
pub type Kyber512 = MlKem<2, Kyber512Params, KyberParams>;

/// Alias for **ML-KEM-768**.
pub type Kyber768 = MlKem<3, Kyber768Params, KyberParams>;

/// Alias for **ML-KEM-1024**.
pub type Kyber1024 = MlKem<4, Kyber1024Params, KyberParams>;
