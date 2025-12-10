# kyber-nz: ML-KEM (FIPS 203) in Rust

**kyber-nz** is a pure Rust implementation of the **FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism)** standard, formerly known as **CRYSTALS-Kyber**.

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

## ⚡ Performance

This crate relies on [`criterion`](https://github.com/bheisler/criterion.rs) for accurate, statistically driven benchmarking.

The following results were measured on a **Apple MacBook Air M4** using a single core. The implementation is **Pure Rust** (no handwritten assembly), focusing on portability and safety while maintaining competitive speed.

| Parameter Set   | KeyGen   | Encaps   | Decaps   |
|-----------------|----------|----------|----------|
| **ML-KEM-512**  | 55.3 µs  | 47.7 µs  | 59.0 µs  |
| **ML-KEM-768**  | 85.3 µs  | 70.4 µs  | 87.3 µs  |
| **ML-KEM-1024** | 120.2 µs | 98.8 µs  | 121.4 µs |

To run the benchmarks yourself:

```bash
cargo bench
```

## 🚀 Installation

Add the dependency to your `Cargo.toml` file:

```toml
[dependencies]
kyber-nz = "0.1.0"
# or via git once hosted
# kyber-nz = { git = "[https://github.com/nougzarm/kyber-nz](https://github.com/nougzarm/kyber-nz)" }