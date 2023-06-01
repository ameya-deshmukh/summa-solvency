//! # Summa Solvency
//!
//! This crate contains the circuit implementation for a zk proof of solvency protocol.
//! The tooling being used to generate the zkSNARKs is [Halo2 PSE Fork](https://github.com/privacy-scaling-explorations/halo2).

/// This module contains the zk circuit subcomponents aka chips.
pub mod chips;

/// This module contains the zk circuit implementations with a full prover and verifier. A circuit can be viewed as an assembly of chips.
pub mod circuits;

/// This module contains the utils to build the merkle sum tree data structure. No zk proof in here.
pub mod merkle_sum_tree;
