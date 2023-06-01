use crate::chips::poseidon::hash::{PoseidonChip, PoseidonConfig};
use crate::chips::poseidon::spec::MySpec;
use gadgets::less_than::{LtChip, LtConfig, LtInstruction};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};

const WIDTH: usize = 5;
const RATE: usize = 4;
const L: usize = 4;

/// Defines the configuration of the MerkleSumTreeChip.
/// Note that it makes use of configs from two external gadgets: PoseidonConfig and LtConfig
#[derive(Debug, Clone)]
pub struct MerkleSumTreeConfig {
    pub advice: [Column<Advice>; 5],
    /// When toggled, constrains that a value in the current row in column e is binary.
    pub bool_selector: Selector,
    /// When toggled, constrains the correct swapping between two consecutive row according to a binary index.
    pub swap_selector: Selector,
    /// When toggled, constrains `b` + `d` = `e` at the current rotation.
    pub sum_selector: Selector,
    /// When toggled, constraints that `c` = `is_lt`.
    pub lt_selector: Selector,
    pub instance: Column<Instance>,
    pub poseidon_config: PoseidonConfig<WIDTH, RATE, L>,
    pub lt_config: LtConfig<Fp, 8>,
}

/// Implementation of the MerkleSumTreeChip.
/// Defines the constraints for the MerkleSumTreeChip and the witness assignement functions

#[derive(Debug, Clone)]
pub struct MerkleSumTreeChip {
    config: MerkleSumTreeConfig,
}

impl MerkleSumTreeChip {
    pub fn construct(config: MerkleSumTreeConfig) -> Self {
        Self { config }
    }

    ///
    /// Defines and return the configuration for the chip. It enforces the following constraints:
    /// - `bool constraint` -> Enforces that e.cur() is either a 0 or 1. `s * e * (1 - e) = 0`
    /// - `swap constraint` -> Enforces that `l1.next()=c.cur(), l2.next()=d.cur(), r1.next()=a.cur(), and r2.next()=b.cur()` if e is 0. Otherwise, `l1.next()=a.cur(), l2.next()=b.cur(), r1.next()=c.cur(), and r2.next()=d.cur()`.
    /// - `sum constraint` -> Enforces that `b.cur() + d.cur() = e.cur()`
    /// - `lt constraint` -> Enforces that `c.cur() = is_lt` from LtChip
    ///
    /// Furthermore:
    /// - initiates the poseidon chip passing in the first #WIDTH advice columns
    /// - initiates the lt chip passing a.cur() as lhs and b.cur() as rhs
    ///

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advice: [Column<Advice>; 5],
        instance: Column<Instance>,
    ) -> MerkleSumTreeConfig {
        let col_a = advice[0];
        let col_b = advice[1];
        let col_c = advice[2];
        let col_d = advice[3];
        let col_e = advice[4];

        // create selectors
        let bool_selector = meta.selector();
        let swap_selector = meta.selector();
        let sum_selector = meta.selector();
        let lt_selector = meta.selector();

        // enable equality for leaf_hash copy constraint with instance column (col_a)
        // enable equality for balance_hash copy constraint with instance column (col_b)
        // enable equality for copying left_hash, left_balance, right_hash, right_balance into poseidon_chip (col_a, col_b, col_c, col_d)
        // enable equality for computed_sum copy constraint with instance column (col_e)
        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);
        meta.enable_equality(col_d);
        meta.enable_equality(col_e);
        meta.enable_equality(instance);

        meta.create_gate("bool constraint", |meta| {
            let s = meta.query_selector(bool_selector);
            let e = meta.query_advice(col_e, Rotation::cur());
            vec![s * e.clone() * (Expression::Constant(Fp::from(1)) - e)]
        });

        meta.create_gate("swap constraint", |meta| {
            let s = meta.query_selector(swap_selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            let d = meta.query_advice(col_d, Rotation::cur());
            let e = meta.query_advice(col_e, Rotation::cur());
            let l1 = meta.query_advice(col_a, Rotation::next());
            let l2 = meta.query_advice(col_b, Rotation::next());
            let r1 = meta.query_advice(col_c, Rotation::next());
            let r2 = meta.query_advice(col_d, Rotation::next());

            vec![
                s.clone() * e.clone() * ((l1 - a) - (c - r1)),
                s * e * ((l2 - b) - (d - r2)),
            ]
        });

        meta.create_gate("sum constraint", |meta| {
            let s = meta.query_selector(sum_selector);
            let left_balance = meta.query_advice(col_b, Rotation::cur());
            let right_balance = meta.query_advice(col_d, Rotation::cur());
            let computed_sum = meta.query_advice(col_e, Rotation::cur());
            vec![s * (left_balance + right_balance - computed_sum)]
        });

        let hash_inputs = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();

        let poseidon_config = PoseidonChip::<MySpec, WIDTH, RATE, L>::configure(meta, hash_inputs);

        let lt_config = LtChip::configure(
            meta,
            |meta| meta.query_selector(lt_selector),
            |meta| meta.query_advice(col_a, Rotation::cur()),
            |meta| meta.query_advice(col_b, Rotation::cur()),
        );

        let config = MerkleSumTreeConfig {
            advice: [col_a, col_b, col_c, col_d, col_e],
            bool_selector,
            swap_selector,
            sum_selector,
            lt_selector,
            instance,
            poseidon_config,
            lt_config,
        };

        meta.create_gate("lt constraint", |meta| {
            let q_enable = meta.query_selector(lt_selector);

            let check = meta.query_advice(col_c, Rotation::cur());

            vec![q_enable * (config.lt_config.is_lt(meta, None) - check)]
        });

        config
    }

    /// Witness assignment function that assigns the leaf hash and balance related to your entry to the execution trace
    /// - leaf_hash -> a, 0
    /// - leaf_balance -> b, 0
    pub fn assing_leaf_hash_and_balance(
        &self,
        mut layouter: impl Layouter<Fp>,
        leaf_hash: Fp,
        leaf_balance: Fp,
    ) -> Result<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>), Error> {
        let (leaf_hash_cell, leaf_balance_cell) = layouter.assign_region(
            || "assign leaf hash",
            |mut region| {
                let l = region.assign_advice(
                    || "leaf hash",
                    self.config.advice[0],
                    0,
                    || Value::known(leaf_hash),
                )?;

                let r = region.assign_advice(
                    || "leaf balance",
                    self.config.advice[1],
                    0,
                    || Value::known(leaf_balance),
                )?;

                Ok((l, r))
            },
        )?;

        Ok((leaf_hash_cell, leaf_balance_cell))
    }

    /// Witness assignment function that assigns the witness for a merkle prove level.
    /// It takes the hash and balance from the previous level and the sibling element hash and balance to perform an hashing level
    /// - At row 0 ->  `prev_hash, rev_balance, element_hash, element_balance`
    /// - At row 1 ->  `hash_left, balance_left, hash_right, balance_right` by swapping the elements according to the binary index.
    /// - Performs the hashing  `computed_hash = (hash_left, balance_left, hash_right, balance_right)`
    /// - Calculates the sum    `computed_sum = balance_left + balance_right`
    ///
    pub fn merkle_prove_layer(
        &self,
        mut layouter: impl Layouter<Fp>,
        prev_hash: &AssignedCell<Fp, Fp>,
        prev_balance: &AssignedCell<Fp, Fp>,
        element_hash: Fp,
        element_balance: Fp,
        index: Fp,
    ) -> Result<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>), Error> {
        let (left_hash, left_balance, right_hash, right_balance, computed_sum_cell) = layouter
            .assign_region(
                || "merkle prove layer",
                |mut region| {
                    // Row 0
                    self.config.bool_selector.enable(&mut region, 0)?;
                    self.config.swap_selector.enable(&mut region, 0)?;
                    let l1 = prev_hash.copy_advice(
                        || "copy hash cell from previous level",
                        &mut region,
                        self.config.advice[0],
                        0,
                    )?;
                    let l2 = prev_balance.copy_advice(
                        || "copy balance cell from previous level",
                        &mut region,
                        self.config.advice[1],
                        0,
                    )?;
                    let r1 = region.assign_advice(
                        || "assign element_hash",
                        self.config.advice[2],
                        0,
                        || Value::known(element_hash),
                    )?;
                    let r2 = region.assign_advice(
                        || "assign balance",
                        self.config.advice[3],
                        0,
                        || Value::known(element_balance),
                    )?;
                    let index = region.assign_advice(
                        || "assign index",
                        self.config.advice[4],
                        0,
                        || Value::known(index),
                    )?;

                    let mut l1_val = l1.value().map(|x| x.to_owned());
                    let mut l2_val = l2.value().map(|x| x.to_owned());
                    let mut r1_val = r1.value().map(|x| x.to_owned());
                    let mut r2_val = r2.value().map(|x| x.to_owned());

                    // Row 1
                    self.config.sum_selector.enable(&mut region, 1)?;

                    // if index is 0 return (l1, l2, r1, r2) else return (r1, r2, l1, l2)
                    index.value().map(|x| x.to_owned()).map(|x| {
                        (l1_val, l2_val, r1_val, r2_val) = if x == Fp::zero() {
                            (l1_val, l2_val, r1_val, r2_val)
                        } else {
                            (r1_val, r2_val, l1_val, l2_val)
                        };
                    });

                    // We need to perform the assignment of the row below according to the index
                    let left_hash = region.assign_advice(
                        || "assign left hash to be hashed",
                        self.config.advice[0],
                        1,
                        || l1_val,
                    )?;

                    let left_balance = region.assign_advice(
                        || "assign left balance to be hashed",
                        self.config.advice[1],
                        1,
                        || l2_val,
                    )?;

                    let right_hash = region.assign_advice(
                        || "assign right hash to be hashed",
                        self.config.advice[2],
                        1,
                        || r1_val,
                    )?;

                    let right_balance = region.assign_advice(
                        || "assign right balance to be hashed",
                        self.config.advice[3],
                        1,
                        || r2_val,
                    )?;

                    let computed_sum = left_balance
                        .value()
                        .zip(right_balance.value())
                        .map(|(a, b)| *a + b);

                    // Now we can assign the sum result to the computed_sum cell.
                    let computed_sum_cell = region.assign_advice(
                        || "assign sum of left and right balance",
                        self.config.advice[4],
                        1,
                        || computed_sum,
                    )?;

                    Ok((
                        left_hash,
                        left_balance,
                        right_hash,
                        right_balance,
                        computed_sum_cell,
                    ))
                },
            )?;

        // instantiate the poseidon_chip
        let poseidon_chip =
            PoseidonChip::<MySpec, WIDTH, RATE, L>::construct(self.config.poseidon_config.clone());

        // The hash function inside the poseidon_chip performs the following action
        // 1. Copy the left and right cells from the previous row
        // 2. Perform the hash function and assign the digest to the current row
        // 3. Constrain the digest to be equal to the hash of the left and right values
        let computed_hash = poseidon_chip.hash(
            layouter.namespace(|| "hash four child nodes"),
            [left_hash, left_balance, right_hash, right_balance],
        )?;

        Ok((computed_hash, computed_sum_cell))
    }

    /// Witness assignment function that assigns the witness to enforce that the computed sum is less than the total assets
    /// It takes the prev_computed_sum_cell as input and enforces that this cell is less than the total assets (passed as input to the instance column)
    pub fn enforce_less_than(
        &self,
        mut layouter: impl Layouter<Fp>,
        prev_computed_sum_cell: &AssignedCell<Fp, Fp>,
    ) -> Result<(), Error> {
        let chip = LtChip::construct(self.config.lt_config);

        chip.load(&mut layouter)?;

        layouter.assign_region(
            || "enforce sum to be less than total assets",
            |mut region| {
                // copy the computed sum to the cell in the first column
                let computed_sum_cell = prev_computed_sum_cell.copy_advice(
                    || "copy computed sum",
                    &mut region,
                    self.config.advice[0],
                    0,
                )?;

                // copy the total assets from instance column to the cell in the second column
                let total_assets_cell = region.assign_advice_from_instance(
                    || "copy total assets",
                    self.config.instance,
                    3,
                    self.config.advice[1],
                    0,
                )?;

                // set check to be equal to 1
                region.assign_advice(
                    || "check",
                    self.config.advice[2],
                    0,
                    || Value::known(Fp::from(1)),
                )?;

                // enable lt seletor
                self.config.lt_selector.enable(&mut region, 0)?;

                total_assets_cell
                    .value()
                    .zip(computed_sum_cell.value())
                    .map(|(total_assets, computed_sum)| {
                        if let Err(e) = chip.assign(
                            &mut region,
                            0,
                            computed_sum.to_owned(),
                            total_assets.to_owned(),
                        ) {
                            println!("Error: {:?}", e);
                        };
                    });

                Ok(())
            },
        )?;

        Ok(())
    }

    /// Function that enforce the copy constrain between an advise cell and a cell from the instance column
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        cell: &AssignedCell<Fp, Fp>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}
