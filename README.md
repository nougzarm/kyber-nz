# pqc-rs: ML-KEM (FIPS 203) in Rust

**pqc-rs** is a pure Rust implementation of the **FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism)** standard, formerly known as **CRYSTALS-Kyber**.

This project aims to provide a readable, modular, and compliant implementation of the NIST specifications for post-quantum cryptography.

## 📦 Features

* **FIPS 203 Compliance**: Faithfully implements the algorithms specified in the official standard.
* **Full Security Level Support**:
    * ML-KEM-512
    * ML-KEM-768
    * ML-KEM-1024
* **Pure Rust**: No C dependencies, ensuring memory safety and portability.
* **Integer Arithmetic**: No floating-point operations, guaranteeing reproducibility across all architectures.
* **Modular Architecture**: Clear separation between arithmetic layers (`polynomial`), encryption (`pke`), and encapsulation (`kem`).

## 🚀 Installation

Add the dependency to your `Cargo.toml` file:

```toml
[dependencies]
pqc-rs = { path = "." } # If local
# or via git once hosted
# pqc-rs = { git = "[https://github.com/nougzarm/pqc-rs](https://github.com/nougzarm/pqc-rs)" }