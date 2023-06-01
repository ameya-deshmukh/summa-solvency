use halo2_gadgets::poseidon::{primitives::*, Hash, Pow5Chip, Pow5Config};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::{circuit::*, plonk::*};
use std::marker::PhantomData;

#[derive(Debug, Clone)]

/// Defines the configuration of the PoseidonConfig.
/// It is a wrapper around the Pow5Config from [halo2_gadgets::poseidon::Pow5Config].
/// It is parametrized by the width, rate, and number of inputs for the Poseidon hash function.
/// For example, in the case of a Poseidon Hasher with 4 inputs. WIDTH = 5, RATE = 4, L = 4.
pub struct PoseidonConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
    pow5_config: Pow5Config<Fp, WIDTH, RATE>,
}

#[derive(Debug, Clone)]

/// Implementation of the PoseidonChip that defines the constraints for the PoseidonChip and the witness assignement functions
pub struct PoseidonChip<
    S: Spec<Fp, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    config: PoseidonConfig<WIDTH, RATE, L>,
    _marker: PhantomData<S>,
}

impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize>
    PoseidonChip<S, WIDTH, RATE, L>
{
    pub fn construct(config: PoseidonConfig<WIDTH, RATE, L>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    /// Wrapper for configuring the Pow5Chip from [halo2_gadgets::poseidon::Pow5Chip]
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        hash_inputs: Vec<Column<Advice>>,
    ) -> PoseidonConfig<WIDTH, RATE, L> {
        let partial_sbox = meta.advice_column();
        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        for i in 0..WIDTH {
            meta.enable_equality(hash_inputs[i]);
        }
        meta.enable_constant(rc_b[0]);

        let pow5_config = Pow5Chip::configure::<S>(
            meta,
            hash_inputs.try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        PoseidonConfig { pow5_config }
    }

    /// Assigns the `input_cells` as input to the hashing function of the `pow_5_chip` and returns the output cell
    pub fn hash(
        &self,
        mut layouter: impl Layouter<Fp>,
        input_cells: [AssignedCell<Fp, Fp>; L],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let pow5_chip = Pow5Chip::construct(self.config.pow5_config.clone());

        // initialize the hasher
        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            pow5_chip,
            layouter.namespace(|| "hasher"),
        )?;
        hasher.hash(layouter.namespace(|| "hash"), input_cells)
    }
}
