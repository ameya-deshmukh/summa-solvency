/// This module contains a wrapper for the poseidon hash chip
pub mod hash;
/// Parameters for using rate 4 Poseidon with the BN256 curve.
/// Patterned after [halo2_gadgets::poseidon::primitives]
pub mod rate4_params;
/// Contains the specification for specific poseidon hashers with different rates based on the bn256 curve.
/// Patterned after [halo2_gadgets::poseidon::primitives::P128Pow5T3]
pub mod spec;
