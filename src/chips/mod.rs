/// This module contains a chip that implements all the contraints to verify: a) inclusion of an entry inside a merkle sum tree, b) the total balance of the tree is less than a given amount
pub mod merkle_sum_tree;
/// This module contains an easy-to-use implementation of the Poseidon Hash in the form of a Halo2 Chip. While the Poseidon Hash function is already implemented in halo2_gadgets, there is no wrapper chip that makes it easy to use in other circuits
pub mod poseidon;
