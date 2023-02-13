use ark_ff::PrimeField;
use ark_r1cs_std::{boolean::AllocatedBit, prelude::*, uint64::UInt64};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;

use crate::building_blocks::crh::CRHforMerkleTreeGadget;
use crate::building_blocks::mt::merkle_sparse_tree::*;

/// Gadgets for one Merkle tree path
#[derive(Debug)]
pub struct MerkleSparseTreePathVar<P, HVar, ConstraintF>
where
    P: MerkleSparseTreeConfig,
    HVar: CRHforMerkleTreeGadget<P::H, ConstraintF>,
    ConstraintF: PrimeField,
{
    path: Vec<(HVar::OutputVar, HVar::OutputVar)>,
}

/// Gadgets for two Merkle tree paths
#[derive(Debug)]
pub struct MerkleSparseTreeTwoPathsVar<P, HVar, ConstraintF>
where
    P: MerkleSparseTreeConfig,
    HVar: CRHforMerkleTreeGadget<P::H, ConstraintF>,
    ConstraintF: PrimeField,
{
    old_path: Vec<(HVar::OutputVar, HVar::OutputVar)>,
    new_path: Vec<(HVar::OutputVar, HVar::OutputVar)>,
}

impl<P, CRHVar, ConstraintF> MerkleSparseTreePathVar<P, CRHVar, ConstraintF>
where
    P: MerkleSparseTreeConfig,
    ConstraintF: PrimeField,
    CRHVar: CRHforMerkleTreeGadget<P::H, ConstraintF>,
{
    /// check a lookup proof (does not enforce index consistency)
    pub fn check_membership(
        &self,
        cs: ConstraintSystemRef<ConstraintF>,
        parameters: &<P::H as CRHforMerkleTree>::Parameters,
        root: &CRHVar::OutputVar,
        leaf: impl ToBytesGadget<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.conditionally_check_membership(cs, parameters, root, leaf, &Boolean::Constant(true))
    }

    /// conditionally check a lookup proof (does not enforce index consistency)
    pub fn conditionally_check_membership(
        &self,
        cs: ConstraintSystemRef<ConstraintF>,
        parameters: &<P::H as CRHforMerkleTree>::Parameters,
        root: &CRHVar::OutputVar,
        leaf: impl ToBytesGadget<ConstraintF>,
        should_enforce: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        assert_eq!(self.path.len(), (P::HEIGHT - 1) as usize);
        // Check that the hash of the given leaf matches the leaf hash in the membership
        // proof.
        let leaf_bits = leaf.to_bytes()?;
        let leaf_hash = CRHVar::hash_bytes(parameters, &leaf_bits)?;

        // Check if leaf is one of the bottom-most siblings.
        let leaf_is_left = Boolean::Is(AllocatedBit::new_witness(
            ark_relations::ns!(cs, "leaf_is_left"),
            || Ok(leaf_hash.value()? == self.path[0].0.value()?),
        )?);

        leaf_hash.conditional_enforce_equal(
            &CRHVar::OutputVar::conditionally_select(
                &leaf_is_left,
                &self.path[0].0,
                &self.path[0].1,
            )?,
            should_enforce,
        )?;

        // Check levels between leaf level and root.
        let mut previous_hash = leaf_hash;
        for (left_hash, right_hash) in self.path.iter() {
            // Check if the previous_hash matches the correct current hash.
            let previous_is_left = Boolean::Is(AllocatedBit::new_witness(
                ark_relations::ns!(cs, "previous_is_left"),
                || Ok(previous_hash.value()? == left_hash.value()?),
            )?);

            previous_hash.conditional_enforce_equal(
                &CRHVar::OutputVar::conditionally_select(&previous_is_left, left_hash, right_hash)?,
                should_enforce,
            )?;

            previous_hash = hash_inner_node_gadget::<P::H, CRHVar, ConstraintF>(
                parameters, left_hash, right_hash,
            )?;
        }

        root.conditional_enforce_equal(&previous_hash, should_enforce)
    }

    /// check a lookup proof (with index)
    pub fn check_membership_with_index(
        &self,
        parameters: &<P::H as CRHforMerkleTree>::Parameters,
        root: &CRHVar::OutputVar,
        leaf: impl ToBytesGadget<ConstraintF>,
        index: &UInt64<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.conditionally_check_membership_with_index(
            parameters,
            root,
            leaf,
            index,
            &Boolean::Constant(true),
        )
    }

    /// conditionally check a lookup proof (with index)
    pub fn conditionally_check_membership_with_index(
        &self,
        parameters: &<P::H as CRHforMerkleTree>::Parameters,
        root: &CRHVar::OutputVar,
        leaf: impl ToBytesGadget<ConstraintF>,
        index: &UInt64<ConstraintF>,
        should_enforce: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        assert_eq!(self.path.len(), (P::HEIGHT - 1) as usize);
        // Check that the hash of the given leaf matches the leaf hash in the membership
        // proof.
        let leaf_bits = leaf.to_bytes()?;
        let leaf_hash = CRHVar::hash_bytes(parameters, &leaf_bits)?;

        // Check levels between leaf level and root.
        let mut previous_hash = leaf_hash;
        let index_bits = index.to_bits_le();
        for (i, (left_hash, right_hash)) in self.path.iter().enumerate() {
            // Check if the previous_hash matches the correct current hash.
            let previous_is_left = index_bits[i].not();

            previous_hash.conditional_enforce_equal(
                &CRHVar::OutputVar::conditionally_select(&previous_is_left, left_hash, right_hash)?,
                should_enforce,
            )?;

            previous_hash = hash_inner_node_gadget::<P::H, CRHVar, ConstraintF>(
                parameters, left_hash, right_hash,
            )?;
        }

        root.conditional_enforce_equal(&previous_hash, should_enforce)
    }
}

impl<P, CRHVar, ConstraintF> MerkleSparseTreeTwoPathsVar<P, CRHVar, ConstraintF>
where
    P: MerkleSparseTreeConfig,
    ConstraintF: PrimeField,
    CRHVar: CRHforMerkleTreeGadget<P::H, ConstraintF>,
{
    /// check a modifying proof
    pub fn check_update(
        &self,
        parameters: &<P::H as CRHforMerkleTree>::Parameters,
        old_root: &CRHVar::OutputVar,
        new_root: &CRHVar::OutputVar,
        new_leaf: impl ToBytesGadget<ConstraintF>,
        index: &UInt64<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.conditionally_check_update(
            parameters,
            old_root,
            new_root,
            new_leaf,
            index,
            &Boolean::Constant(true),
        )
    }

    /// conditionally check a modifying proof
    pub fn conditionally_check_update(
        &self,
        parameters: &<P::H as CRHforMerkleTree>::Parameters,
        old_root: &CRHVar::OutputVar,
        new_root: &CRHVar::OutputVar,
        new_leaf: impl ToBytesGadget<ConstraintF>,
        index: &UInt64<ConstraintF>,
        should_enforce: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        assert_eq!(self.old_path.len(), (P::HEIGHT - 1) as usize);
        assert_eq!(self.new_path.len(), (P::HEIGHT - 1) as usize);
        // Check that the hash of the given leaf matches the leaf hash in the membership
        // proof.
        let new_leaf_bits = new_leaf.to_bytes()?;
        let new_leaf_hash = CRHVar::hash_bytes(parameters, &new_leaf_bits)?;

        // Check levels between leaf level and root of the new tree.
        let mut previous_hash = new_leaf_hash;
        let index_bits = index.to_bits_le();
        for (i, (left_hash, right_hash)) in self.new_path.iter().enumerate() {
            // Check if the previous_hash matches the correct current hash.
            let previous_is_left = index_bits[i].not();

            previous_hash.conditional_enforce_equal(
                &CRHVar::OutputVar::conditionally_select(&previous_is_left, left_hash, right_hash)?,
                should_enforce,
            )?;

            previous_hash = hash_inner_node_gadget::<P::H, CRHVar, ConstraintF>(
                parameters, left_hash, right_hash,
            )?;
        }

        new_root.conditional_enforce_equal(&previous_hash, should_enforce)?;

        let mut old_path_iter = self.old_path.iter();
        let old_path_first_entry = old_path_iter.next().unwrap();

        previous_hash = hash_inner_node_gadget::<P::H, CRHVar, ConstraintF>(
            parameters,
            &old_path_first_entry.0,
            &old_path_first_entry.1,
        )?;

        let mut current_loc = 1;
        loop {
            let pair = old_path_iter.next();

            match pair {
                Some((left_hash, right_hash)) => {
                    // Check if the previous_hash matches the correct current hash.
                    let previous_is_left = index_bits[current_loc].not();

                    previous_hash.conditional_enforce_equal(
                        &CRHVar::OutputVar::conditionally_select(
                            &previous_is_left,
                            left_hash,
                            right_hash,
                        )?,
                        should_enforce,
                    )?;

                    previous_hash = hash_inner_node_gadget::<P::H, CRHVar, ConstraintF>(
                        parameters, left_hash, right_hash,
                    )?;
                }
                None => break,
            }
            current_loc += 1;
        }

        old_path_iter = self.old_path.iter();
        for (i, (left_hash, right_hash)) in self.new_path.iter().enumerate() {
            // Check if the previous_hash matches the correct current hash.
            let previous_is_left = index_bits[i].not();
            let previous_is_right = previous_is_left.not();

            let old_path_corresponding_entry = old_path_iter.next().unwrap();

            right_hash
                .conditional_enforce_equal(&old_path_corresponding_entry.1, &previous_is_left)?;

            left_hash
                .conditional_enforce_equal(&old_path_corresponding_entry.0, &previous_is_right)?;
        }

        old_root.conditional_enforce_equal(&previous_hash, should_enforce)
    }
}

pub(crate) fn hash_inner_node_gadget<H, HG, ConstraintF>(
    parameters: &H::Parameters,
    left_child: &HG::OutputVar,
    right_child: &HG::OutputVar,
) -> Result<HG::OutputVar, SynthesisError>
where
    ConstraintF: PrimeField,
    H: CRHforMerkleTree,
    HG: CRHforMerkleTreeGadget<H, ConstraintF>,
{
    HG::two_to_one_compress(parameters, left_child, right_child)
}

impl<P, HVar, ConstraintF> AllocVar<MerkleSparseTreePath<P>, ConstraintF>
    for MerkleSparseTreePathVar<P, HVar, ConstraintF>
where
    P: MerkleSparseTreeConfig,
    HVar: CRHforMerkleTreeGadget<P::H, ConstraintF>,
    ConstraintF: PrimeField,
{
    fn new_variable<T: Borrow<MerkleSparseTreePath<P>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let mut path = Vec::new();
        for (l, r) in f()?.borrow().path.iter() {
            let l_hash =
                HVar::OutputVar::new_variable(ark_relations::ns!(cs, "l_child"), || Ok(*l), mode)?;
            let r_hash =
                HVar::OutputVar::new_variable(ark_relations::ns!(cs, "r_child"), || Ok(*r), mode)?;
            path.push((l_hash, r_hash));
        }
        Ok(MerkleSparseTreePathVar { path })
    }
}

impl<P, HVar, ConstraintF> AllocVar<MerkleSparseTreeTwoPaths<P>, ConstraintF>
    for MerkleSparseTreeTwoPathsVar<P, HVar, ConstraintF>
where
    P: MerkleSparseTreeConfig,
    HVar: CRHforMerkleTreeGadget<P::H, ConstraintF>,
    ConstraintF: PrimeField,
{
    fn new_variable<T: Borrow<MerkleSparseTreeTwoPaths<P>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let mut old_path = Vec::new();

        let t = f()?;
        let paths = t.borrow();
        for (l, r) in paths.old_path.path.iter() {
            let l_hash = HVar::OutputVar::new_variable(
                ark_relations::ns!(cs, "old_path_l_child"),
                || Ok(*l),
                mode,
            )?;
            let r_hash = HVar::OutputVar::new_variable(
                ark_relations::ns!(cs, "old_path_r_child"),
                || Ok(*r),
                mode,
            )?;
            old_path.push((l_hash, r_hash));
        }
        let mut new_path = Vec::new();
        for (l, r) in paths.new_path.path.iter() {
            let l_hash = HVar::OutputVar::new_variable(
                ark_relations::ns!(cs, "new_path_l_child"),
                || Ok(*l),
                mode,
            )?;
            let r_hash = HVar::OutputVar::new_variable(
                ark_relations::ns!(cs, "new_path_r_child"),
                || Ok(*r),
                mode,
            )?;
            new_path.push((l_hash, r_hash));
        }
        Ok(MerkleSparseTreeTwoPathsVar { old_path, new_path })
    }
}

#[cfg(test)]
mod test {
    use ark_ed_on_mnt4_298::EdwardsParameters;
    use ark_ed_on_mnt4_298::Fq;
    use ark_relations::r1cs::ConstraintSystem;
    use rand_chacha::ChaChaRng;

    use super::*;
    use crate::building_blocks::crh::bowe_hopwood::{
        BoweHopwoodCRHforMerkleTree, BoweHopwoodCRHforMerkleTreeGadget,
    };

    type H = BoweHopwoodCRHforMerkleTree<ChaChaRng, EdwardsParameters>;
    type HG = BoweHopwoodCRHforMerkleTreeGadget<ChaChaRng, EdwardsParameters>;

    #[derive(Debug)]
    struct JubJubMerkleTreeParams;

    impl MerkleSparseTreeConfig for JubJubMerkleTreeParams {
        const HEIGHT: u64 = 32;
        type H = H;
    }

    type JubJubMerkleTree = MerkleSparseTree<JubJubMerkleTreeParams>;

    fn generate_merkle_tree(leaves: &BTreeMap<u64, [u8; 30]>, use_bad_root: bool) {
        let mut rng = ark_std::test_rng();

        let crh_parameters = H::setup(&mut rng).unwrap();
        let tree = JubJubMerkleTree::new(crh_parameters.clone(), leaves).unwrap();
        let root = tree.root();
        let mut satisfied = true;
        for (i, leaf) in leaves.iter() {
            let cs_sys = ConstraintSystem::<Fq>::new();
            let cs = ConstraintSystemRef::new(cs_sys);
            let proof = tree.generate_proof(*i, &leaf).unwrap();
            assert!(proof.verify(&crh_parameters, &root, &leaf).unwrap());

            // Allocate Merkle Tree Root
            let root = <HG as CRHforMerkleTreeGadget<H, _>>::OutputVar::new_witness(
                ark_relations::ns!(cs, "new_digest"),
                || {
                    if use_bad_root {
                        Ok(<H as CRHforMerkleTree>::Output::default())
                    } else {
                        Ok(root)
                    }
                },
            )
            .unwrap();

            let constraints_from_digest = cs.num_constraints();
            println!("constraints from digest: {constraints_from_digest}");

            // Allocate Parameters for CRH
            let constraints_from_parameters = cs.num_constraints() - constraints_from_digest;
            println!("constraints from parameters: {constraints_from_parameters}");

            // Allocate Leaf
            let leaf_g = UInt8::constant_vec(leaf);
            let index_g = UInt64::constant(*i);

            let constraints_from_leaf =
                cs.num_constraints() - constraints_from_parameters - constraints_from_digest;
            println!("constraints from leaf: {constraints_from_leaf}");

            // Allocate Merkle Tree Path
            let cw = MerkleSparseTreePathVar::<_, HG, _>::new_witness(
                ark_relations::ns!(cs, "new_witness"),
                || Ok(proof),
            )
            .unwrap();

            let constraints_from_path = cs.num_constraints()
                - constraints_from_parameters
                - constraints_from_digest
                - constraints_from_leaf;
            println!("constraints from path: {constraints_from_path}");
            let leaf_g: &[UInt8<Fq>] = leaf_g.as_slice();
            cw.check_membership(
                ark_relations::ns!(cs, "check_membership").cs(),
                &crh_parameters,
                &root,
                &leaf_g,
            )
            .unwrap();
            cw.check_membership_with_index(&crh_parameters, &root, &leaf_g, &index_g)
                .unwrap();
            if !cs.is_satisfied().unwrap() {
                satisfied = false;
                println!(
                    "Unsatisfied constraint: {}",
                    cs.which_is_unsatisfied().unwrap().unwrap()
                );
            }
            let setup_constraints = constraints_from_leaf
                + constraints_from_digest
                + constraints_from_parameters
                + constraints_from_path;
            println!(
                "number of constraints: {}",
                cs.num_constraints() - setup_constraints
            );
        }

        assert!(satisfied);
    }

    #[test]
    fn good_root_membership_test() {
        let mut leaves: BTreeMap<u64, [u8; 30]> = BTreeMap::new();
        for i in 0..10u8 {
            let input = [i; 30];
            leaves.insert(i as u64, input);
        }
        generate_merkle_tree(&leaves, false);
    }

    #[should_panic]
    #[test]
    fn bad_root_membership_test() {
        let mut leaves: BTreeMap<u64, [u8; 30]> = BTreeMap::new();
        for i in 0..10u8 {
            let input = [i; 30];
            leaves.insert(i as u64, input);
        }
        generate_merkle_tree(&leaves, true);
    }

    fn generate_merkle_tree_and_test_update(
        old_leaves: &BTreeMap<u64, [u8; 2]>,
        new_leaves: &BTreeMap<u64, [u8; 2]>,
    ) {
        let mut rng = ark_std::test_rng();

        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut tree = JubJubMerkleTree::new(crh_parameters.clone(), old_leaves).unwrap();
        let mut satisfied = true;
        for (i, new_leaf) in new_leaves.iter() {
            let cs_sys = ConstraintSystem::<Fq>::new();
            let cs = ConstraintSystemRef::new(cs_sys);

            let old_root = tree.root.unwrap();
            let update_proof = tree.update_and_prove(*i, &new_leaf).unwrap();
            let new_leaf_membership_proof = tree.generate_proof(*i, &new_leaf).unwrap();
            let new_root = tree.root.unwrap();

            assert!(update_proof
                .verify(&crh_parameters, &old_root, &new_root, &new_leaf, *i)
                .unwrap());
            assert!(new_leaf_membership_proof
                .verify_with_index(&crh_parameters, &new_root, &new_leaf, *i)
                .unwrap());

            // Allocate Merkle Tree Root
            let old_root_gadget = <HG as CRHforMerkleTreeGadget<H, _>>::OutputVar::new_witness(
                ark_relations::ns!(cs, "old_digest"),
                || Ok(old_root),
            )
            .unwrap();
            let new_root_gadget = <HG as CRHforMerkleTreeGadget<H, _>>::OutputVar::new_witness(
                ark_relations::ns!(cs, "new_digest"),
                || Ok(new_root),
            )
            .unwrap();

            let constraints_from_digests = cs.num_constraints();
            println!("constraints from digests: {constraints_from_digests}");

            // Allocate Parameters for CRH
            let constraints_from_parameters = cs.num_constraints() - constraints_from_digests;
            println!("constraints from parameters: {constraints_from_parameters}");

            // Allocate Leaf
            let leaf_g = UInt8::constant_vec(new_leaf);
            let index_g = UInt64::constant(*i);

            let constraints_from_leaf =
                cs.num_constraints() - constraints_from_parameters - constraints_from_digests;
            println!("constraints from leaf: {constraints_from_leaf}");

            // Allocate Merkle Tree Path
            let update_proof_cw = MerkleSparseTreeTwoPathsVar::<_, HG, _>::new_witness(
                ark_relations::ns!(cs, "new_witness_update"),
                || Ok(update_proof),
            )
            .unwrap();

            let constraints_from_two_paths = cs.num_constraints()
                - constraints_from_parameters
                - constraints_from_digests
                - constraints_from_leaf;
            println!("constraints from two paths: {constraints_from_two_paths}");

            let new_leaf_membership_proof_cw = MerkleSparseTreePathVar::<_, HG, _>::new_witness(
                ark_relations::ns!(cs, "new_witness_new_membership"),
                || Ok(new_leaf_membership_proof),
            )
            .unwrap();

            let constraints_from_path = cs.num_constraints()
                - constraints_from_parameters
                - constraints_from_digests
                - constraints_from_leaf
                - constraints_from_two_paths;
            println!("constraints from path: {constraints_from_path}");

            let leaf_g: &[UInt8<Fq>] = leaf_g.as_slice();
            update_proof_cw
                .check_update(
                    &crh_parameters,
                    &old_root_gadget,
                    &new_root_gadget,
                    &leaf_g,
                    &index_g,
                )
                .unwrap();
            new_leaf_membership_proof_cw
                .check_membership_with_index(&crh_parameters, &new_root_gadget, &leaf_g, &index_g)
                .unwrap();
            if !cs.is_satisfied().unwrap() {
                satisfied = false;
                println!(
                    "Unsatisfied constraint: {}",
                    cs.which_is_unsatisfied().unwrap().unwrap()
                );
            }
            let setup_constraints = constraints_from_leaf
                + constraints_from_digests
                + constraints_from_parameters
                + constraints_from_two_paths
                + constraints_from_path;
            println!(
                "number of constraints: {}",
                cs.num_constraints() - setup_constraints
            );
        }

        assert!(satisfied);
    }

    #[test]
    fn good_root_update_test() {
        let mut old_leaves: BTreeMap<u64, [u8; 2]> = BTreeMap::new();
        for i in 0..4u8 {
            let input = [i; 2];
            old_leaves.insert(i as u64, input);
        }
        let mut new_leaves: BTreeMap<u64, [u8; 2]> = BTreeMap::new();
        for i in 0..8u8 {
            let input = [i + 1; 2];
            new_leaves.insert(i as u64, input);
        }
        generate_merkle_tree_and_test_update(&old_leaves, &new_leaves);
    }
}
