use ark_r1cs_std::alloc::AllocationMode;
use ark_relations::r1cs::{ConstraintSystemRef, Namespace};
use ark_serialize::{CanonicalSerialize, SerializationError};
use ark_sponge::constraints::AbsorbableGadget;
use ark_sponge::Absorbable;
use ark_std::collections::BTreeMap;
use ark_std::fmt::Debug;
use ark_std::rand::{CryptoRng, Rng};
use ark_std::{
    io::{Result as IoResult, Write},
    string::ToString,
};

use crate::{
    building_blocks::{
        crh::{CRHforMerkleTree, CRHforMerkleTreeGadget},
        mt::merkle_sparse_tree::{
            constraints::{MerkleSparseTreePathVar, MerkleSparseTreeTwoPathsVar},
            MerkleSparseTree, MerkleSparseTreeConfig, MerkleSparseTreePath,
            MerkleSparseTreeTwoPaths,
        },
    },
    gadgets::{AllocVar, Boolean, CondSelectGadget, EqGadget, ToBytesGadget, UInt64},
    Borrow, Error, PhantomData, PrimeField, SynthesisError, ToBytes, Vec,
};

/// implementation of sparse Merkle tree
pub mod merkle_sparse_tree;

/// trait for a Merkle tree primitive
pub trait MT<F: PrimeField, Addr: ToBytes + Default + Eq + Clone + Ord, AddrVar: AllocVar<Addr, F>>
{
    /// public parameters
    type PublicParameters: Clone;
    /// digest
    type Digest: Default + Eq + Clone + ToBytes + Absorbable<F> + CanonicalSerialize;
    /// tree
    type T;
    /// lookup proof
    type LookupProof: Default + ToBytes + Clone + Debug + CanonicalSerialize;
    /// modifying proof
    type ModifyProof: Default + ToBytes + Clone + CanonicalSerialize;

    /// gadgets for digest
    type DigestVar: AllocVar<Self::Digest, F>
        + Clone
        + ToBytesGadget<F>
        + AbsorbableGadget<F>
        + CondSelectGadget<F>;
    /// gadgets for lookup proof
    type LookupProofVar: AllocVar<Self::LookupProof, F>;
    /// gadgets for modifying proof
    type ModifyProofVar: AllocVar<Self::ModifyProof, F>;

    /// sample the Merkle tree public parameters
    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self::PublicParameters, Error>;
    /// initialize an empty tree using the public parameters
    fn new<L: Default + ToBytes>(pp: &Self::PublicParameters) -> Result<Self::T, Error>;
    /// obtain the root hash
    fn root(pp: &Self::PublicParameters, tree: &Self::T) -> Result<Self::Digest, Error>;
    /// obtain the empty leaf hash
    fn empty_leaf(pp: &Self::PublicParameters, tree: &Self::T) -> Result<Self::Digest, Error>;
    /// check if a tree if structurally valid
    fn validate(pp: &Self::PublicParameters, tree: &Self::T) -> Result<bool, Error>;

    /// lookup data
    fn lookup(
        pp: &Self::PublicParameters,
        tree: &Self::T,
        addr: &[Addr],
    ) -> Result<Self::LookupProof, Error>;

    /// verify a lookup proof
    fn verify_lookup<Data: ToBytes + Clone + Default>(
        pp: &Self::PublicParameters,
        rh: &Self::Digest,
        addr: &[Addr],
        data: &[Data],
        lookup_proof: &Self::LookupProof,
    ) -> Result<bool, Error>;

    /// verify a modifying proof
    fn verify_modify<Data: ToBytes + Clone + Default>(
        pp: &Self::PublicParameters,
        rh_old: &Self::Digest,
        rh_new: &Self::Digest,
        addr: &[Addr],
        data: &[Data],
        modify_proof: &Self::ModifyProof,
    ) -> Result<bool, Error>;

    /// create a new tree with an existing data map
    fn _new_with_map<Data: ToBytes + Clone + Default>(
        pp: &Self::PublicParameters,
        map: &BTreeMap<Addr, Data>,
    ) -> Result<Self::T, Error>;

    /// modify the tree and apply the change
    fn _modify_and_apply<Data: ToBytes + Clone + Default>(
        pp: &Self::PublicParameters,
        tree: &mut Self::T,
        addr: &[Addr],
        data: &[Data],
        store_history: bool,
    ) -> Result<(Self::Digest, Self::ModifyProof), Error>;

    /// clear the data in the tree
    fn clear(pp: &Self::PublicParameters, tree: &mut Self::T) -> Result<(), Error>;

    /// check a lookup proof
    fn verify_lookup_gadget<DataVar: ToBytesGadget<F>>(
        cs: ConstraintSystemRef<F>,
        pp_g: &Self::PublicParameters,
        rh_g: &Self::DigestVar,
        addr_g: &[AddrVar],
        data_g: &[DataVar],
        lookup_proof_g: &Self::LookupProofVar,
    ) -> Result<(), SynthesisError>;

    /// conditionally check a lookup proof
    fn conditionally_verify_lookup_gadget<DataVar: ToBytesGadget<F>>(
        cs: ConstraintSystemRef<F>,
        pp_g: &Self::PublicParameters,
        rh_g: &Self::DigestVar,
        addr_g: &[AddrVar],
        data_g: &[DataVar],
        lookup_proof_g: &Self::LookupProofVar,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError>;

    /// conditionally check a modifying proof
    fn conditionally_verify_modify_gadget<DataVar: ToBytesGadget<F>>(
        cs: ConstraintSystemRef<F>,
        pp_g: &Self::PublicParameters,
        rh_old_g: &Self::DigestVar,
        rh_new_g: &Self::DigestVar,
        addr_g: &[AddrVar],
        data_g: &[DataVar],
        modify_proof_g: &Self::ModifyProofVar,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError>;

    /// output a dummy lookup proof
    fn default_lookup_proof(num: usize) -> Result<Self::LookupProof, Error>;
    /// output a dummy modifying proof
    fn default_modify_proof(num: usize) -> Result<Self::ModifyProof, Error>;
}

/// Sparse Merkle tree
pub struct SparseMT<
    F: PrimeField,
    P: MerkleSparseTreeConfig,
    CRHVar: CRHforMerkleTreeGadget<P::H, F>,
> {
    f_phantom: PhantomData<F>,
    tree_config_phantom: PhantomData<P>,
    crh_gadget_phantom: PhantomData<CRHVar>,
}

/// A single Merkle tree modifying proof
#[derive(CanonicalSerialize, Derivative)]
#[derivative(Debug(bound = "P: MerkleSparseTreeConfig"))]
pub struct ModifyProofType<P: MerkleSparseTreeConfig> {
    /// the new digest
    pub new_digest: <<P as MerkleSparseTreeConfig>::H as CRHforMerkleTree>::Output,
    /// the modifying proof
    pub modify_proof: MerkleSparseTreeTwoPaths<P>,
}

impl<P: MerkleSparseTreeConfig> Clone for ModifyProofType<P> {
    fn clone(&self) -> Self {
        ModifyProofType {
            new_digest: self.new_digest,
            modify_proof: self.modify_proof.clone(),
        }
    }
}

impl<P: MerkleSparseTreeConfig> Default for ModifyProofType<P> {
    fn default() -> Self {
        ModifyProofType {
            new_digest: <<P as MerkleSparseTreeConfig>::H as CRHforMerkleTree>::Output::default(),
            modify_proof: MerkleSparseTreeTwoPaths::<P>::default(),
        }
    }
}

struct ModifyProofTypeVar<
    P: MerkleSparseTreeConfig,
    CRHVar: CRHforMerkleTreeGadget<P::H, F>,
    F: PrimeField,
> {
    new_digest_g: CRHVar::OutputVar,
    modify_proof_g: MerkleSparseTreeTwoPathsVar<P, CRHVar, F>,
}

impl<P: MerkleSparseTreeConfig, CRHVar: CRHforMerkleTreeGadget<P::H, F>, F: PrimeField>
    AllocVar<ModifyProofType<P>, F> for ModifyProofTypeVar<P, CRHVar, F>
{
    fn new_variable<T: Borrow<ModifyProofType<P>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let val = f()?;
        let modify_proof_type = val.borrow().clone();

        let ns = cs.into();
        let cs = ns.cs();

        let new_digest_g = CRHVar::OutputVar::new_variable(
            ark_relations::ns!(cs, "modify_proof_type_gadget_new_digest"),
            || Ok(&modify_proof_type.new_digest),
            mode,
        )?;
        let modify_proof_g = MerkleSparseTreeTwoPathsVar::new_variable(
            ark_relations::ns!(cs, "modify_proof_type_gadget_modify_proof"),
            || Ok(&modify_proof_type.modify_proof),
            mode,
        )?;

        Ok(ModifyProofTypeVar {
            new_digest_g,
            modify_proof_g,
        })
    }
}

impl<P: MerkleSparseTreeConfig> ToBytes for ModifyProofType<P> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.new_digest.write(&mut writer)?;
        self.modify_proof.write(&mut writer)?;
        Ok(())
    }
}

/// lookup proof gadgets
pub struct LookupProofVar<
    F: PrimeField,
    P: MerkleSparseTreeConfig,
    CRHVar: CRHforMerkleTreeGadget<P::H, F>,
>(Vec<MerkleSparseTreePathVar<P, CRHVar, F>>);

/// modifying proof gadgets
pub struct ModifyProofVar<
    F: PrimeField,
    P: MerkleSparseTreeConfig,
    CRHVar: CRHforMerkleTreeGadget<P::H, F>,
>(Vec<ModifyProofTypeVar<P, CRHVar, F>>);

impl<F: PrimeField, P: MerkleSparseTreeConfig, CRHVar: CRHforMerkleTreeGadget<P::H, F>>
    AllocVar<Vec<MerkleSparseTreePath<P>>, F> for LookupProofVar<F, P, CRHVar>
{
    fn new_variable<T: Borrow<Vec<MerkleSparseTreePath<P>>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let mut vec = Vec::new();
        for value in f()?.borrow().iter() {
            vec.push(MerkleSparseTreePathVar::<P, CRHVar, F>::new_variable(
                ark_relations::ns!(cs, "value"),
                || Ok(value),
                mode,
            )?);
        }
        Ok(LookupProofVar(vec))
    }
}

impl<F: PrimeField, P: MerkleSparseTreeConfig, CRHVar: CRHforMerkleTreeGadget<P::H, F>>
    AllocVar<Vec<ModifyProofType<P>>, F> for ModifyProofVar<F, P, CRHVar>
{
    fn new_variable<T: Borrow<Vec<ModifyProofType<P>>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let mut vec = Vec::new();
        for value in f()?.borrow().iter() {
            vec.push(ModifyProofTypeVar::<P, CRHVar, F>::new_variable(
                ark_relations::ns!(cs, "value"),
                || Ok(value),
                mode,
            )?);
        }
        Ok(ModifyProofVar(vec))
    }
}

impl<F: PrimeField, P: MerkleSparseTreeConfig, CRHVar: CRHforMerkleTreeGadget<P::H, F>>
    MT<F, u64, UInt64<F>> for SparseMT<F, P, CRHVar>
where
    <<P as MerkleSparseTreeConfig>::H as CRHforMerkleTree>::Output: Absorbable<F>,
{
    type PublicParameters = <<P as MerkleSparseTreeConfig>::H as CRHforMerkleTree>::Parameters;
    type Digest = <<P as MerkleSparseTreeConfig>::H as CRHforMerkleTree>::Output;
    type T = MerkleSparseTree<P>;
    type LookupProof = Vec<MerkleSparseTreePath<P>>;
    type ModifyProof = Vec<ModifyProofType<P>>;

    type DigestVar = CRHVar::OutputVar;
    type LookupProofVar = LookupProofVar<F, P, CRHVar>;
    type ModifyProofVar = ModifyProofVar<F, P, CRHVar>;

    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self::PublicParameters, Error> {
        <<P as MerkleSparseTreeConfig>::H as CRHforMerkleTree>::setup(rng)
    }

    fn new<L: Default + ToBytes>(pp: &Self::PublicParameters) -> Result<Self::T, Error> {
        Ok(MerkleSparseTree::blank::<L>(pp.clone()))
    }

    fn root(_pp: &Self::PublicParameters, tree: &Self::T) -> Result<Self::Digest, Error> {
        Ok(tree.root())
    }

    fn empty_leaf(_pp: &Self::PublicParameters, tree: &Self::T) -> Result<Self::Digest, Error> {
        Ok(tree.empty_leaf())
    }

    fn validate(_pp: &Self::PublicParameters, tree: &Self::T) -> Result<bool, Error> {
        tree.validate()
    }

    fn lookup(
        _pp: &Self::PublicParameters,
        tree: &Self::T,
        addr: &[u64],
    ) -> Result<Self::LookupProof, Error> {
        let mut lookup_proof: Self::LookupProof = Vec::with_capacity(addr.len());

        for i in addr {
            lookup_proof.push(tree.generate_membership_proof(*i)?);
        }

        Ok(lookup_proof)
    }

    fn verify_lookup<Data: ToBytes + Clone + Default>(
        pp: &Self::PublicParameters,
        rh: &Self::Digest,
        addr: &[u64],
        data: &[Data],
        lookup_proof: &Self::LookupProof,
    ) -> Result<bool, Error> {
        let addr_len = addr.len();
        let data_len = data.len();
        let lookup_proof_len = lookup_proof.len();

        if addr_len != data_len || data_len != lookup_proof_len {
            return Err(SparseMTError::IncorrectInput.into());
        }

        let mut addr_iter = addr.iter();
        let mut data_iter = data.iter();
        let mut lookup_proof_iter = lookup_proof.iter();

        loop {
            let addr_iter_next_item = addr_iter.next();
            match addr_iter_next_item {
                Some(addr_item) => {
                    let data_item = data_iter.next().unwrap();
                    let lookup_proof_item = lookup_proof_iter.next().unwrap();

                    if !lookup_proof_item.verify_with_index(pp, rh, data_item, *addr_item)? {
                        return Ok(false);
                    }
                }
                _ => break,
            }
        }

        Ok(true)
    }

    fn verify_modify<Data: ToBytes + Clone + Default>(
        pp: &Self::PublicParameters,
        rh_old: &Self::Digest,
        rh_new: &Self::Digest,
        addr: &[u64],
        data: &[Data],
        modify_proof: &Self::ModifyProof,
    ) -> Result<bool, Error> {
        let addr_len = addr.len();
        let data_len = data.len();
        let modify_proof_len = modify_proof.len();

        if addr_len != data_len || data_len != modify_proof_len {
            return Err(SparseMTError::IncorrectInput.into());
        }

        let mut addr_iter = addr.iter();
        let mut data_iter = data.iter();
        let mut modify_proof_iter = modify_proof.iter();

        let mut last_hash: Self::Digest = *rh_old;
        let mut cur_hash: Self::Digest;

        loop {
            let addr_iter_next_item = addr_iter.next();
            match addr_iter_next_item {
                Some(addr_item) => {
                    let data_item = data_iter.next().unwrap();
                    let modify_proof_item = modify_proof_iter.next().unwrap();

                    cur_hash = modify_proof_item.new_digest;

                    if !modify_proof_item
                        .modify_proof
                        .verify(pp, &last_hash, &cur_hash, data_item, *addr_item)?
                    {
                        return Ok(false);
                    }

                    last_hash = cur_hash;
                }
                _ => break,
            }
        }

        if last_hash != *rh_new {
            return Ok(false);
        }

        Ok(true)
    }

    fn _new_with_map<Data: ToBytes + Clone + Default>(
        pp: &Self::PublicParameters,
        map: &BTreeMap<u64, Data>,
    ) -> Result<Self::T, Error> {
        MerkleSparseTree::new(pp.clone(), map)
    }

    fn _modify_and_apply<Data: ToBytes + Clone + Default>(
        _pp: &Self::PublicParameters,
        tree: &mut Self::T,
        addr: &[u64],
        data: &[Data],
        store_history: bool,
    ) -> Result<(Self::Digest, Self::ModifyProof), Error> {
        let addr_len = addr.len();
        let data_len = data.len();

        if addr_len != data_len {
            return Err(SparseMTError::IncorrectInput.into());
        }

        let mut modify_proof: Self::ModifyProof = Vec::with_capacity(addr_len);

        let mut addr_iter = addr.iter();
        let mut data_iter = data.iter();

        loop {
            let addr_iter_next_item = addr_iter.next();
            match addr_iter_next_item {
                Some(addr_item) => {
                    let data_item = data_iter.next().unwrap();
                    let proof = tree.update_and_prove(*addr_item, data_item)?;
                    let rh = tree.root();
                    modify_proof.push(ModifyProofType {
                        new_digest: rh,
                        modify_proof: proof,
                    });
                    if store_history {
                        let proof = tree.update_and_prove(*addr_item + 1, &tree.root())?;
                        let rh = tree.root();
                        modify_proof.push(ModifyProofType {
                            new_digest: rh,
                            modify_proof: proof,
                        });
                    }
                }
                _ => break,
            }
        }

        let last_rh = tree.root();

        Ok((last_rh, modify_proof))
    }

    fn clear(_pp: &Self::PublicParameters, tree: &mut Self::T) -> Result<(), Error> {
        tree.tree.clear();

        Ok(())
    }

    fn verify_lookup_gadget<DataVar: ToBytesGadget<F>>(
        _cs: ConstraintSystemRef<F>,
        pp_g: &Self::PublicParameters,
        rh_g: &Self::DigestVar,
        addr_g: &[UInt64<F>],
        data_g: &[DataVar],
        lookup_proof_g_wrapped: &Self::LookupProofVar,
    ) -> Result<(), SynthesisError> {
        let addr_g_len = addr_g.len();
        let data_g_len = data_g.len();

        let lookup_proof_g = &lookup_proof_g_wrapped.0;
        let lookup_proof_g_len = lookup_proof_g.len();

        assert_eq!(
            addr_g_len, data_g_len,
            "the address len {addr_g_len} does not equal the data len {data_g_len}"
        );
        assert_eq!(
            data_g_len, lookup_proof_g_len,
            "the data len {data_g_len} does not equal the proof len {lookup_proof_g_len}"
        );

        let mut addr_g_iter = addr_g.iter();
        let mut data_g_iter = data_g.iter();
        let mut lookup_proof_g_iter = lookup_proof_g.iter();

        loop {
            let addr_g_iter_next_item = addr_g_iter.next();
            match addr_g_iter_next_item {
                Some(addr_g_item) => {
                    let data_g_item = data_g_iter.next().unwrap();
                    let lookup_proof_g_item = lookup_proof_g_iter.next().unwrap();

                    lookup_proof_g_item.check_membership_with_index(
                        pp_g,
                        rh_g,
                        data_g_item,
                        addr_g_item,
                    )?;
                }
                _ => break,
            }
        }

        Ok(())
    }

    fn conditionally_verify_lookup_gadget<DataVar: ToBytesGadget<F>>(
        _cs: ConstraintSystemRef<F>,
        pp_g: &Self::PublicParameters,
        rh_g: &Self::DigestVar,
        addr_g: &[UInt64<F>],
        data_g: &[DataVar],
        lookup_proof_g_wrapped: &Self::LookupProofVar,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        let addr_g_len = addr_g.len();
        let data_g_len = data_g.len();

        let lookup_proof_g = &lookup_proof_g_wrapped.0;
        let lookup_proof_g_len = lookup_proof_g.len();

        assert_eq!(
            addr_g_len, data_g_len,
            "the address len {addr_g_len} does not equal the data len {data_g_len}"
        );
        assert_eq!(
            data_g_len, lookup_proof_g_len,
            "the data len {data_g_len} does not equal the proof len {lookup_proof_g_len}"
        );

        let mut addr_g_iter = addr_g.iter();
        let mut data_g_iter = data_g.iter();
        let mut lookup_proof_g_iter = lookup_proof_g.iter();

        loop {
            let addr_g_iter_next_item = addr_g_iter.next();
            match addr_g_iter_next_item {
                Some(addr_g_item) => {
                    let data_g_item = data_g_iter.next().unwrap();
                    let lookup_proof_g_item = lookup_proof_g_iter.next().unwrap();

                    lookup_proof_g_item.conditionally_check_membership_with_index(
                        pp_g,
                        rh_g,
                        data_g_item,
                        addr_g_item,
                        should_enforce,
                    )?;
                }
                _ => break,
            }
        }

        Ok(())
    }

    fn conditionally_verify_modify_gadget<DataVar: ToBytesGadget<F>>(
        _cs: ConstraintSystemRef<F>,
        pp_g: &Self::PublicParameters,
        rh_old_g: &Self::DigestVar,
        rh_new_g: &Self::DigestVar,
        addr_g: &[UInt64<F>],
        data_g: &[DataVar],
        modify_proof_g_wrapped: &Self::ModifyProofVar,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        let addr_g_len = addr_g.len();
        let data_g_len = data_g.len();
        let modify_proof_g = &modify_proof_g_wrapped.0;
        let modify_proof_g_len = modify_proof_g.len();

        assert_eq!(addr_g_len, data_g_len);
        assert_eq!(data_g_len, modify_proof_g_len);

        let mut addr_g_iter = addr_g.iter();
        let mut data_g_iter = data_g.iter();
        let mut modify_proof_g_iter = modify_proof_g.iter();

        let mut last_hash_g: Self::DigestVar = rh_old_g.clone();
        let mut cur_hash_g: Self::DigestVar;

        loop {
            let addr_g_iter_next_item = addr_g_iter.next();
            match addr_g_iter_next_item {
                Some(addr_g_item) => {
                    let data_g_item = data_g_iter.next().unwrap();
                    let modify_proof_g_item = modify_proof_g_iter.next().unwrap();

                    cur_hash_g = modify_proof_g_item.new_digest_g.clone();

                    modify_proof_g_item
                        .modify_proof_g
                        .conditionally_check_update(
                            pp_g,
                            &last_hash_g,
                            &cur_hash_g,
                            data_g_item,
                            addr_g_item,
                            should_enforce,
                        )?;

                    last_hash_g = cur_hash_g;
                }
                _ => break,
            }
        }

        last_hash_g.conditional_enforce_equal(rh_new_g, should_enforce)?;

        Ok(())
    }

    fn default_lookup_proof(num: usize) -> Result<Self::LookupProof, Error> {
        let mut res = Vec::with_capacity(num);
        for _ in 0..num {
            res.push(MerkleSparseTreePath::<P>::default());
        }
        Ok(res)
    }

    fn default_modify_proof(num: usize) -> Result<Self::ModifyProof, Error> {
        let mut res = Vec::with_capacity(num);
        for _ in 0..num {
            res.push(ModifyProofType::<P>::default());
        }
        Ok(res)
    }
}

#[derive(Debug)]
/// error type for sparse Merkle tree
pub enum SparseMTError {
    /// length of data/proof does not match each other
    IncorrectInput,
}

impl core::fmt::Display for SparseMTError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            SparseMTError::IncorrectInput => "incorrect input".to_string(),
        };
        write!(f, "{msg}")
    }
}

impl ark_std::error::Error for SparseMTError {
    #[inline]
    fn source(&self) -> Option<&(dyn ark_std::error::Error + 'static)> {
        None
    }
}
