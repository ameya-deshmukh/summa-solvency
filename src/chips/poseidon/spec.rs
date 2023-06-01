use crate::chips::poseidon::rate4_params;
use halo2_gadgets::poseidon::primitives::*;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::bn256::Fr as Fp;

#[derive(Debug, Clone, Copy)]

/// Specification for a Poseidon Hasher with width 5, rate 4, and 4 inputs based on the bn256 curve.
pub struct MySpec;

pub(crate) type Mds<Fp, const T: usize> = [[Fp; T]; T];

impl Spec<Fp, 5, 4> for MySpec {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        60
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        unimplemented!()
    }

    fn constants() -> (Vec<[Fp; 5]>, Mds<Fp, 5>, Mds<Fp, 5>) {
        (
            rate4_params::ROUND_CONSTANTS[..].to_vec(),
            rate4_params::MDS,
            rate4_params::MDS_INV,
        )
    }
}
