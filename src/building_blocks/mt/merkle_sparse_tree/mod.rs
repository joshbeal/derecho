use ark_ff::ToBytes;
use ark_serialize::{CanonicalSerialize, SerializationError};
use ark_std::collections::{BTreeMap, BTreeSet};
use ark_std::io::Cursor;
use ark_std::{fmt::Debug, format};
use ark_std::{
    io::{Result as IoResult, Write},
    string::ToString,
    vec::Vec,
};

use crate::building_blocks::crh::CRHforMerkleTree;
use crate::Error;

/// constraints for the Merkle sparse tree
pub mod constraints;

/// configuration of a Merkle tree
pub trait MerkleSparseTreeConfig: Debug {
    /// Tree height
    const HEIGHT: u64;
    /// The CRH
    type H: CRHforMerkleTree;
}

/// Stores the hashes of a particular path (in order) from leaf to root.
/// Our path `is_left_child()` if the boolean in `path` is true.
#[derive(CanonicalSerialize, Derivative)]
#[derivative(
    Clone(bound = "P: MerkleSparseTreeConfig"),
    Debug(bound = "P: MerkleSparseTreeConfig, <P::H as CRHforMerkleTree>::Output: Debug")
)]
pub struct MerkleSparseTreePath<P: MerkleSparseTreeConfig> {
    pub(crate) path: Vec<(
        <P::H as CRHforMerkleTree>::Output,
        <P::H as CRHforMerkleTree>::Output,
    )>,
}

#[derive(CanonicalSerialize, Derivative)]
#[derivative(Debug(bound = "P: MerkleSparseTreeConfig"))]
/// A modifying proof, consisting of two Merkle tree paths
pub struct MerkleSparseTreeTwoPaths<P: MerkleSparseTreeConfig> {
    pub(crate) old_path: MerkleSparseTreePath<P>,
    pub(crate) new_path: MerkleSparseTreePath<P>,
}

/// public parameters of the Merkle sparse tree
pub type MerkleSparseTreeParams<P> =
    <<P as MerkleSparseTreeConfig>::H as CRHforMerkleTree>::Parameters;
/// digest of the Merkle sparse tree
pub type MerkleSparseTreeDigest<P> = <<P as MerkleSparseTreeConfig>::H as CRHforMerkleTree>::Output;

impl<P: MerkleSparseTreeConfig> Default for MerkleSparseTreePath<P> {
    fn default() -> Self {
        let mut path = Vec::with_capacity(P::HEIGHT as usize);
        for _i in 1..P::HEIGHT as usize {
            path.push((
                <P::H as CRHforMerkleTree>::Output::default(),
                <P::H as CRHforMerkleTree>::Output::default(),
            ));
        }
        Self { path }
    }
}

impl<P: MerkleSparseTreeConfig> ToBytes for MerkleSparseTreePath<P> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        for p in &self.path {
            p.0.write(&mut writer)?;
            p.1.write(&mut writer)?;
        }
        Ok(())
    }
}

impl<P: MerkleSparseTreeConfig> Default for MerkleSparseTreeTwoPaths<P> {
    fn default() -> Self {
        let old_path: MerkleSparseTreePath<P> = MerkleSparseTreePath::default();
        let new_path: MerkleSparseTreePath<P> = MerkleSparseTreePath::default();
        Self { old_path, new_path }
    }
}

impl<P: MerkleSparseTreeConfig> ToBytes for MerkleSparseTreeTwoPaths<P> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.old_path.write(&mut writer)?;
        self.new_path.write(&mut writer)?;
        Ok(())
    }
}

impl<P: MerkleSparseTreeConfig> Clone for MerkleSparseTreeTwoPaths<P> {
    fn clone(&self) -> Self {
        MerkleSparseTreeTwoPaths {
            old_path: self.old_path.clone(),
            new_path: self.new_path.clone(),
        }
    }
}

impl<P: MerkleSparseTreeConfig> MerkleSparseTreePath<P> {
    /// verify the lookup proof, just checking the membership
    pub fn verify<L: ToBytes>(
        &self,
        parameters: &<P::H as CRHforMerkleTree>::Parameters,
        root_hash: &<P::H as CRHforMerkleTree>::Output,
        leaf: &L,
    ) -> Result<bool, Error> {
        if self.path.len() != (P::HEIGHT - 1) as usize {
            return Ok(false);
        }
        // Check that the given leaf matches the leaf in the membership proof.
        if !self.path.is_empty() {
            let claimed_leaf_hash = hash_leaf::<P::H, L>(parameters, leaf)?;

            if claimed_leaf_hash != self.path[0].0 && claimed_leaf_hash != self.path[0].1 {
                return Ok(false);
            }

            let mut prev = claimed_leaf_hash;
            // Check levels between leaf level and root.
            for (left_hash, right_hash) in &self.path {
                // Check if the previous hash matches the correct current hash.
                if &prev != left_hash && &prev != right_hash {
                    return Ok(false);
                }
                prev = hash_inner_node::<P::H>(parameters, left_hash, right_hash)?;
            }

            if root_hash != &prev {
                return Ok(false);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// verify the lookup proof, given the location
    pub fn verify_with_index<L: ToBytes>(
        &self,
        parameters: &<P::H as CRHforMerkleTree>::Parameters,
        root_hash: &<P::H as CRHforMerkleTree>::Output,
        leaf: &L,
        index: u64,
    ) -> Result<bool, Error> {
        if self.path.len() != (P::HEIGHT - 1) as usize {
            return Ok(false);
        }
        // Check that the given leaf matches the leaf in the membership proof.
        let last_level_index: u64 = (1u64 << (P::HEIGHT - 1)) - 1;
        let tree_index: u64 = last_level_index + index;

        let mut index_from_path: u64 = last_level_index;
        let mut index_offset: u64 = 1;

        if !self.path.is_empty() {
            let claimed_leaf_hash = hash_leaf::<P::H, L>(parameters, leaf)?;

            if tree_index % 2 == 1 {
                if claimed_leaf_hash != self.path[0].0 {
                    return Ok(false);
                }
            } else if claimed_leaf_hash != self.path[0].1 {
                return Ok(false);
            }

            let mut prev = claimed_leaf_hash;
            let mut prev_index = tree_index;
            // Check levels between leaf level and root.
            for (left_hash, right_hash) in &self.path {
                // Check if the previous hash matches the correct current hash.
                if prev_index % 2 == 1 {
                    if &prev != left_hash {
                        return Ok(false);
                    }
                } else {
                    if &prev != right_hash {
                        return Ok(false);
                    }
                    index_from_path += index_offset;
                }
                index_offset *= 2;
                prev_index = (prev_index - 1) / 2;
                prev = hash_inner_node::<P::H>(parameters, left_hash, right_hash)?;
            }

            if root_hash != &prev {
                return Ok(false);
            }

            if index_from_path != tree_index {
                return Ok(false);
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl<P: MerkleSparseTreeConfig> MerkleSparseTreeTwoPaths<P> {
    /// verify the modifying proof
    pub fn verify<L: ToBytes>(
        &self,
        parameters: &<P::H as CRHforMerkleTree>::Parameters,
        old_root_hash: &<P::H as CRHforMerkleTree>::Output,
        new_root_hash: &<P::H as CRHforMerkleTree>::Output,
        leaf: &L,
        index: u64,
    ) -> Result<bool, Error> {
        if self.old_path.path.len() != (P::HEIGHT - 1) as usize
            || self.new_path.path.len() != (P::HEIGHT - 1) as usize
        {
            return Ok(false);
        }
        // Check that the given leaf matches the leaf in the membership proof.
        let last_level_index: u64 = (1u64 << (P::HEIGHT - 1)) - 1;
        let tree_index: u64 = last_level_index + index;

        let mut index_from_path: u64 = last_level_index;
        let mut index_offset: u64 = 1;

        if !self.old_path.path.is_empty() && !self.new_path.path.is_empty() {
            // Check the new path first
            let claimed_leaf_hash = hash_leaf::<P::H, L>(parameters, leaf)?;

            if tree_index % 2 == 1 {
                if claimed_leaf_hash != self.new_path.path[0].0 {
                    return Ok(false);
                }
            } else if claimed_leaf_hash != self.new_path.path[0].1 {
                return Ok(false);
            }

            let mut prev = claimed_leaf_hash;
            let mut prev_index = tree_index;

            // Check levels between leaf level and root.
            for (left_hash, right_hash) in &self.new_path.path {
                // Check if the previous hash matches the correct current hash.
                if prev_index % 2 == 1 {
                    if &prev != left_hash {
                        return Ok(false);
                    }
                } else {
                    if &prev != right_hash {
                        return Ok(false);
                    }
                    index_from_path += index_offset;
                }
                index_offset *= 2;
                prev_index = (prev_index - 1) / 2;
                prev = hash_inner_node::<P::H>(parameters, left_hash, right_hash)?;
            }

            if new_root_hash != &prev {
                return Ok(false);
            }

            if index_from_path != tree_index {
                return Ok(false);
            }

            if tree_index % 2 == 1 {
                prev = self.old_path.path[0].0;
            } else {
                prev = self.old_path.path[0].1;
            }

            prev_index = tree_index;
            let mut new_path_iter = self.new_path.path.iter();
            for (left_hash, right_hash) in &self.old_path.path {
                // Check if the previous hash matches the correct current hash.
                if prev_index % 2 == 1 {
                    if &prev != left_hash {
                        return Ok(false);
                    }
                } else if &prev != right_hash {
                    return Ok(false);
                }

                let new_path_corresponding_entry = new_path_iter.next();

                // Check the co-path is unchanged
                match new_path_corresponding_entry {
                    Some(x) => {
                        if prev_index % 2 == 1 {
                            if *right_hash != x.1 {
                                return Ok(false);
                            }
                        } else if *left_hash != x.0 {
                            return Ok(false);
                        }
                    }
                    None => return Ok(false),
                }

                prev_index = (prev_index - 1) / 2;
                prev = hash_inner_node::<P::H>(parameters, left_hash, right_hash)?;
            }

            if old_root_hash != &prev {
                return Ok(false);
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Merkle sparse tree
pub struct MerkleSparseTree<P: MerkleSparseTreeConfig> {
    /// data of the tree
    pub tree: BTreeMap<u64, <P::H as CRHforMerkleTree>::Output>,
    parameters: <P::H as CRHforMerkleTree>::Parameters,
    root: Option<<P::H as CRHforMerkleTree>::Output>,
    empty_hashes: Vec<<P::H as CRHforMerkleTree>::Output>,
}

impl<P: MerkleSparseTreeConfig> MerkleSparseTree<P> {
    /// tree height
    pub const HEIGHT: u64 = P::HEIGHT;

    /// obtain an empty tree
    pub fn blank<L: Default + ToBytes>(parameters: <P::H as CRHforMerkleTree>::Parameters) -> Self {
        let empty_hashes = gen_empty_hashes::<P, L>(&parameters, L::default()).unwrap();

        MerkleSparseTree {
            tree: BTreeMap::new(),
            parameters,
            root: Some(empty_hashes[(P::HEIGHT - 1) as usize]),
            empty_hashes,
        }
    }

    /// initialize a tree (with optional data)
    /// optional data doesn't work with store history
    pub fn new<L: Default + ToBytes>(
        parameters: <P::H as CRHforMerkleTree>::Parameters,
        leaves: &BTreeMap<u64, L>,
    ) -> Result<Self, Error> {
        let last_level_size = leaves.len().next_power_of_two();
        let tree_size = 2 * last_level_size - 1;
        let tree_height = tree_height(tree_size as u64);
        assert!(tree_height <= Self::HEIGHT);

        // Initialize the merkle tree.
        let mut tree: BTreeMap<u64, <P::H as CRHforMerkleTree>::Output> = BTreeMap::new();
        let empty_hashes = gen_empty_hashes::<P, L>(&parameters, L::default())?;

        // Compute and store the hash values for each leaf.
        let last_level_index: u64 = (1u64 << (Self::HEIGHT - 1)) - 1;
        for (i, leaf) in leaves.iter() {
            tree.insert(
                last_level_index + *i,
                hash_leaf::<P::H, _>(&parameters, leaf)?,
            );
        }

        let mut middle_nodes: BTreeSet<u64> = BTreeSet::new();
        for i in leaves.keys() {
            middle_nodes.insert(parent(last_level_index + *i).unwrap());
        }

        // Compute the hash values for every node in parts of the tree.
        for level in 0..Self::HEIGHT {
            // Iterate over the current level.
            for current_index in &middle_nodes {
                let left_index = left_child(*current_index);
                let right_index = right_child(*current_index);

                let mut left_hash = empty_hashes[level as usize];
                let mut right_hash = empty_hashes[level as usize];

                if tree.contains_key(&left_index) {
                    match tree.get(&left_index) {
                        Some(x) => left_hash = *x,
                        _ => return Err(MerkleSparseTreeError::IncorrectTreeStructure.into()),
                    }
                }

                if tree.contains_key(&right_index) {
                    match tree.get(&right_index) {
                        Some(x) => right_hash = *x,
                        _ => return Err(MerkleSparseTreeError::IncorrectTreeStructure.into()),
                    }
                }

                // Compute Hash(left || right).
                tree.insert(
                    *current_index,
                    hash_inner_node::<P::H>(&parameters, &left_hash, &right_hash)?,
                );
            }

            let tmp_middle_nodes = middle_nodes.clone();
            middle_nodes.clear();
            for i in tmp_middle_nodes {
                if !is_root(i) {
                    middle_nodes.insert(parent(i).unwrap());
                }
            }
        }

        let root_hash = match tree.get(&0) {
            Some(x) => *x,
            _ => return Err(MerkleSparseTreeError::IncorrectTreeStructure.into()),
        };

        Ok(MerkleSparseTree {
            tree,
            parameters,
            root: Some(root_hash),
            empty_hashes,
        })
    }

    #[inline]
    /// obtain the root hash
    pub fn root(&self) -> <P::H as CRHforMerkleTree>::Output {
        self.root.unwrap()
    }

    #[inline]
    /// obtain the empty leaf hash
    pub fn empty_leaf(&self) -> <P::H as CRHforMerkleTree>::Output {
        self.empty_hashes[0]
    }

    /// generate a membership proof (does not check the data point)
    pub fn generate_membership_proof(&self, index: u64) -> Result<MerkleSparseTreePath<P>, Error> {
        let mut path = Vec::new();

        let tree_height = Self::HEIGHT;
        let tree_index = convert_index_to_last_level(index, tree_height);

        // Iterate from the leaf up to the root, storing all intermediate hash values.
        let mut current_node = tree_index;
        let mut empty_hashes_iter = self.empty_hashes.iter();
        while !is_root(current_node) {
            let sibling_node = sibling(current_node).unwrap();

            let mut current_hash = *empty_hashes_iter.next().unwrap();
            let mut sibling_hash = current_hash;

            if self.tree.contains_key(&current_node) {
                match self.tree.get(&current_node) {
                    Some(x) => current_hash = *x,
                    _ => return Err(MerkleSparseTreeError::IncorrectTreeStructure.into()),
                }
            }

            if self.tree.contains_key(&sibling_node) {
                match self.tree.get(&sibling_node) {
                    Some(x) => sibling_hash = *x,
                    _ => return Err(MerkleSparseTreeError::IncorrectTreeStructure.into()),
                }
            }

            if is_left_child(current_node) {
                path.push((current_hash, sibling_hash));
            } else {
                path.push((sibling_hash, current_hash));
            }
            current_node = parent(current_node).unwrap();
        }

        if path.len() != (Self::HEIGHT - 1) as usize {
            Err(MerkleSparseTreeError::IncorrectPathLength(path.len()).into())
        } else {
            Ok(MerkleSparseTreePath { path })
        }
    }

    /// generate a lookup proof
    pub fn generate_proof<L: ToBytes>(
        &self,
        index: u64,
        leaf: &L,
    ) -> Result<MerkleSparseTreePath<P>, Error> {
        let leaf_hash = hash_leaf::<P::H, _>(&self.parameters, leaf)?;
        let tree_height = Self::HEIGHT;
        let tree_index = convert_index_to_last_level(index, tree_height);

        // Check that the given index corresponds to the correct leaf.
        if let Some(x) = self.tree.get(&tree_index) {
            if leaf_hash != *x {
                return Err(MerkleSparseTreeError::IncorrectTreeStructure.into());
            }
        }

        self.generate_membership_proof(index)
    }

    /// update the tree and provide a modifying proof
    pub fn update_and_prove<L: ToBytes>(
        &mut self,
        index: u64,
        new_leaf: &L,
    ) -> Result<MerkleSparseTreeTwoPaths<P>, Error> {
        let old_path = self.generate_membership_proof(index)?;

        let new_leaf_hash = hash_leaf::<P::H, _>(&self.parameters, new_leaf)?;

        let tree_height = Self::HEIGHT;
        let tree_index = convert_index_to_last_level(index, tree_height);

        // Update the leaf and update the parents
        self.tree.insert(tree_index, new_leaf_hash);

        // Iterate from the leaf up to the root, storing all intermediate hash values.
        let mut current_node = tree_index;
        current_node = parent(current_node).unwrap();

        let mut empty_hashes_iter = self.empty_hashes.iter();
        loop {
            let left_node = left_child(current_node);
            let right_node = right_child(current_node);

            let mut left_hash = *empty_hashes_iter.next().unwrap();
            let mut right_hash = left_hash;

            if self.tree.contains_key(&left_node) {
                match self.tree.get(&left_node) {
                    Some(x) => left_hash = *x,
                    _ => return Err(MerkleSparseTreeError::IncorrectTreeStructure.into()),
                }
            }

            if self.tree.contains_key(&right_node) {
                match self.tree.get(&right_node) {
                    Some(x) => right_hash = *x,
                    _ => return Err(MerkleSparseTreeError::IncorrectTreeStructure.into()),
                }
            }

            self.tree.insert(
                current_node,
                hash_inner_node::<P::H>(&self.parameters, &left_hash, &right_hash)?,
            );

            if is_root(current_node) {
                break;
            }

            current_node = parent(current_node).unwrap();
        }

        match self.tree.get(&0) {
            Some(x) => self.root = Some(*x),
            None => return Err(MerkleSparseTreeError::IncorrectTreeStructure.into()),
        }

        let new_path = self.generate_proof(index, new_leaf)?;

        Ok(MerkleSparseTreeTwoPaths { old_path, new_path })
    }

    /// check if the tree is structurally valid
    pub fn validate(&self) -> Result<bool, Error> {
        /* Finding the leaf nodes */
        let last_level_index: u64 = (1u64 << (Self::HEIGHT - 1)) - 1;
        let mut middle_nodes: BTreeSet<u64> = BTreeSet::new();

        for key in self.tree.keys() {
            if *key >= last_level_index && !is_root(*key) {
                middle_nodes.insert(parent(*key).unwrap());
            }
        }

        for level in 0..Self::HEIGHT {
            for current_index in &middle_nodes {
                let left_index = left_child(*current_index);
                let right_index = right_child(*current_index);

                let mut left_hash = self.empty_hashes[level as usize];
                let mut right_hash = self.empty_hashes[level as usize];

                if self.tree.contains_key(&left_index) {
                    match self.tree.get(&left_index) {
                        Some(x) => left_hash = *x,
                        _ => {
                            return Ok(false);
                        }
                    }
                }

                if self.tree.contains_key(&right_index) {
                    match self.tree.get(&right_index) {
                        Some(x) => right_hash = *x,
                        _ => {
                            return Ok(false);
                        }
                    }
                }

                let hash = hash_inner_node::<P::H>(&self.parameters, &left_hash, &right_hash)?;

                match self.tree.get(current_index) {
                    Some(x) => {
                        if *x != hash {
                            return Ok(false);
                        }
                    }
                    _ => {
                        return Ok(false);
                    }
                }
            }

            let tmp_middle_nodes = middle_nodes.clone();
            middle_nodes.clear();
            for i in tmp_middle_nodes {
                if !is_root(i) {
                    middle_nodes.insert(parent(i).unwrap());
                }
            }
        }

        Ok(true)
    }
}

/// error for Merkle sparse tree
#[derive(Debug)]
pub enum MerkleSparseTreeError {
    /// the path's length does not work for this tree
    IncorrectPathLength(usize),
    /// tree structure is incorrect, some nodes are missing
    IncorrectTreeStructure,
}

impl core::fmt::Display for MerkleSparseTreeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            MerkleSparseTreeError::IncorrectPathLength(len) => {
                format!("incorrect path length: {len}")
            }
            MerkleSparseTreeError::IncorrectTreeStructure => "incorrect tree structure".to_string(),
        };
        write!(f, "{msg}")
    }
}

impl ark_std::error::Error for MerkleSparseTreeError {}

/// Returns the log2 value of the given number.
#[inline]
fn log2(number: u64) -> u64 {
    ark_std::log2(number as usize) as u64
}

/// Returns the height of the tree, given the size of the tree.
#[inline]
fn tree_height(tree_size: u64) -> u64 {
    log2(tree_size)
}

/// Returns true iff the index represents the root.
#[inline]
fn is_root(index: u64) -> bool {
    index == 0
}

/// Returns the index of the left child, given an index.
#[inline]
fn left_child(index: u64) -> u64 {
    2 * index + 1
}

/// Returns the index of the right child, given an index.
#[inline]
fn right_child(index: u64) -> u64 {
    2 * index + 2
}

/// Returns the index of the sibling, given an index.
#[inline]
fn sibling(index: u64) -> Option<u64> {
    if index == 0 {
        None
    } else if is_left_child(index) {
        Some(index + 1)
    } else {
        Some(index - 1)
    }
}

/// Returns true iff the given index represents a left child.
#[inline]
fn is_left_child(index: u64) -> bool {
    index % 2 == 1
}

/// Returns the index of the parent, given an index.
#[inline]
fn parent(index: u64) -> Option<u64> {
    if index > 0 {
        Some((index - 1) >> 1)
    } else {
        None
    }
}

#[inline]
fn convert_index_to_last_level(index: u64, tree_height: u64) -> u64 {
    index + (1 << (tree_height - 1)) - 1
}

/// Returns the output hash, given a left and right hash value.
pub(crate) fn hash_inner_node<H: CRHforMerkleTree>(
    parameters: &H::Parameters,
    left: &H::Output,
    right: &H::Output,
) -> Result<H::Output, Error> {
    H::two_to_one_compress(parameters, left, right)
}

/// Returns the hash of a leaf.
fn hash_leaf<H: CRHforMerkleTree, L: ToBytes>(
    parameters: &H::Parameters,
    leaf: &L,
) -> Result<H::Output, Error> {
    let mut writer = Cursor::new(Vec::<u8>::new());
    leaf.write(&mut writer)?;

    H::hash_bytes(parameters, &writer.into_inner())
}

fn hash_empty<H: CRHforMerkleTree, L: ToBytes>(
    parameters: &H::Parameters,
    empty_leaf: L,
) -> Result<H::Output, Error> {
    let mut writer = Cursor::new(Vec::<u8>::new());
    empty_leaf.write(&mut writer)?;

    H::hash_bytes(parameters, &writer.into_inner())
}

fn gen_empty_hashes<P: MerkleSparseTreeConfig, L: ToBytes>(
    parameters: &<P::H as CRHforMerkleTree>::Parameters,
    empty_leaf: L,
) -> Result<Vec<<P::H as CRHforMerkleTree>::Output>, Error> {
    let mut empty_hashes = Vec::with_capacity(P::HEIGHT as usize);

    let mut empty_hash = hash_empty::<P::H, L>(parameters, empty_leaf)?;
    empty_hashes.push(empty_hash);

    for _ in 1..=P::HEIGHT {
        empty_hash = hash_inner_node::<P::H>(parameters, &empty_hash, &empty_hash)?;
        empty_hashes.push(empty_hash);
    }

    Ok(empty_hashes)
}

#[cfg(test)]
mod test {
    use ark_ed_on_mnt4_298::EdwardsParameters;
    use ark_ed_on_mnt4_298::Fq as Fr;
    use ark_ff::{ToBytes, Zero};
    use ark_std::collections::BTreeMap;
    use rand_chacha::ChaChaRng;

    use crate::building_blocks::crh::bowe_hopwood::BoweHopwoodCRHforMerkleTree;
    use crate::building_blocks::mt::merkle_sparse_tree::*;

    type H = BoweHopwoodCRHforMerkleTree<ChaChaRng, EdwardsParameters>;

    #[derive(Debug)]
    struct JubJubMerkleTreeParams;

    impl MerkleSparseTreeConfig for JubJubMerkleTreeParams {
        const HEIGHT: u64 = 32;
        type H = H;
    }
    type JubJubMerkleTree = MerkleSparseTree<JubJubMerkleTreeParams>;

    fn generate_merkle_tree_and_test_membership<L: Default + ToBytes + Clone + Eq>(
        leaves: &BTreeMap<u64, L>,
    ) {
        let mut rng = ark_std::test_rng();

        let crh_parameters = H::setup(&mut rng).unwrap();
        let tree = JubJubMerkleTree::new(crh_parameters.clone(), leaves).unwrap();
        let root = tree.root();
        for (i, leaf) in leaves.iter() {
            let proof = tree.generate_proof(*i, &leaf).unwrap();
            assert!(proof.verify(&crh_parameters, &root, &leaf).unwrap());
            assert!(proof
                .verify_with_index(&crh_parameters, &root, &leaf, *i)
                .unwrap());
        }

        assert!(tree.validate().unwrap());
    }

    #[test]
    fn good_root_membership_test() {
        let mut leaves: BTreeMap<u64, u8> = BTreeMap::new();
        for i in 0..4u8 {
            leaves.insert(i as u64, i);
        }
        generate_merkle_tree_and_test_membership(&leaves);
        let mut leaves: BTreeMap<u64, u8> = BTreeMap::new();
        for i in 0..100u8 {
            leaves.insert(i as u64, i);
        }
        generate_merkle_tree_and_test_membership(&leaves);
    }

    fn generate_merkle_tree_with_bad_root_and_test_membership<L: Default + ToBytes + Clone + Eq>(
        leaves: &BTreeMap<u64, L>,
    ) {
        let mut rng = ark_std::test_rng();

        let crh_parameters = H::setup(&mut rng).unwrap();
        let tree = JubJubMerkleTree::new(crh_parameters.clone(), leaves).unwrap();
        let root = Fr::zero();
        for (i, leaf) in leaves.iter() {
            let proof = tree.generate_proof(*i, &leaf).unwrap();
            assert!(proof.verify(&crh_parameters, &root, &leaf).unwrap());
            assert!(proof
                .verify_with_index(&crh_parameters, &root, &leaf, *i)
                .unwrap());
        }
    }

    #[should_panic]
    #[test]
    fn bad_root_membership_test() {
        let mut leaves: BTreeMap<u64, u8> = BTreeMap::new();
        for i in 0..100u8 {
            leaves.insert(i as u64, i);
        }
        generate_merkle_tree_with_bad_root_and_test_membership(&leaves);
    }

    fn generate_merkle_tree_and_test_update<L: Default + ToBytes + Clone + Eq>(
        old_leaves: &BTreeMap<u64, L>,
        new_leaves: &BTreeMap<u64, L>,
    ) {
        let mut rng = ark_std::test_rng();

        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut tree = JubJubMerkleTree::new(crh_parameters.clone(), old_leaves).unwrap();
        for (i, new_leaf) in new_leaves.iter() {
            let old_root = tree.root.unwrap();
            let old_leaf_option = old_leaves.get(i);

            match old_leaf_option {
                Some(old_leaf) => {
                    let old_leaf_membership_proof = tree.generate_proof(*i, &old_leaf).unwrap();
                    let update_proof = tree.update_and_prove(*i, &new_leaf).unwrap();
                    let new_leaf_membership_proof = tree.generate_proof(*i, &new_leaf).unwrap();
                    let new_root = tree.root.unwrap();

                    assert!(old_leaf_membership_proof
                        .verify_with_index(&crh_parameters, &old_root, &old_leaf, *i)
                        .unwrap());
                    assert!(
                        !(old_leaf_membership_proof
                            .verify_with_index(&crh_parameters, &new_root, &old_leaf, *i)
                            .unwrap())
                    );
                    assert!(new_leaf_membership_proof
                        .verify_with_index(&crh_parameters, &new_root, &new_leaf, *i)
                        .unwrap());
                    assert!(
                        !(new_leaf_membership_proof
                            .verify_with_index(&crh_parameters, &new_root, &old_leaf, *i)
                            .unwrap())
                    );

                    assert!(update_proof
                        .verify(&crh_parameters, &old_root, &new_root, &new_leaf, *i)
                        .unwrap());
                }
                None => {
                    let update_proof = tree.update_and_prove(*i, &new_leaf).unwrap();
                    let new_leaf_membership_proof = tree.generate_proof(*i, &new_leaf).unwrap();
                    let new_root = tree.root.unwrap();

                    assert!(new_leaf_membership_proof
                        .verify_with_index(&crh_parameters, &new_root, &new_leaf, *i)
                        .unwrap());
                    assert!(update_proof
                        .verify(&crh_parameters, &old_root, &new_root, &new_leaf, *i)
                        .unwrap());
                }
            }
        }
    }

    #[test]
    fn good_root_update_test() {
        let mut old_leaves: BTreeMap<u64, u8> = BTreeMap::new();
        for i in 0..10u8 {
            old_leaves.insert(i as u64, i);
        }
        let mut new_leaves: BTreeMap<u64, u8> = BTreeMap::new();
        for i in 0..20u8 {
            new_leaves.insert(i as u64, i + 1);
        }
        generate_merkle_tree_and_test_update(&old_leaves, &new_leaves);
    }
}
