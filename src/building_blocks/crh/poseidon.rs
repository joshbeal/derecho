// Note: Poseidon here is for benchmark purposes.
// The upstream sponge does not sample random parameters, and the default parameters may be insecure for certain fields.
// We leave it as a future item. The more stable sponge may be later implemented in the ark-sponge repo.

use ark_ff::{BigInteger, FpParameters, PrimeField};
use ark_r1cs_std::bits::uint8::UInt8;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_sponge::Absorbable;
use ark_std::rand::{CryptoRng, Rng, SeedableRng};
use ark_std::{marker::PhantomData, vec::Vec};

use crate::building_blocks::crh::{CRHforMerkleTree, CRHforMerkleTreeGadget};
use crate::fiat_shamir::constraints::AlgebraicSpongeVar;
use crate::fiat_shamir::poseidon::constraints::PoseidonSpongeVar;
use crate::fiat_shamir::{poseidon::PoseidonSponge, AlgebraicSponge};
use crate::gadgets::{FieldVar, FpVar, ToBitsGadget};
use crate::Error;

/// Poseidon CRH combining with the compressor (taking only the x-coordinate in the affine representation)
/// The RO is not used now, but should be used later for generating the parameters.
pub struct PoseidonCRHforMerkleTree<
    RO: Rng + CryptoRng + SeedableRng,
    F: PrimeField + Absorbable<F>,
> {
    _rand: PhantomData<RO>,
    _field: PhantomData<F>,
}

impl<RO: Rng + CryptoRng + SeedableRng, F: PrimeField + Absorbable<F>> CRHforMerkleTree
    for PoseidonCRHforMerkleTree<RO, F>
{
    type Output = F;
    type Parameters = PoseidonSponge<F>;

    fn setup<R: Rng + CryptoRng>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(PoseidonSponge::<F>::new())
    }

    fn hash_bytes(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        // Step 1: pack the bytes into little-endian bit sequences
        let mut bits = Vec::new();

        for input_elem in input.iter() {
            bits.push(0 != input_elem & 1);
            bits.push(0 != input_elem & 2);
            bits.push(0 != input_elem & 4);
            bits.push(0 != input_elem & 8);
            bits.push(0 != input_elem & 16);
            bits.push(0 != input_elem & 32);
            bits.push(0 != input_elem & 64);
            bits.push(0 != input_elem & 128);
        }

        // Step 2: split it into a few field elements
        let mut field_elements = Vec::new();
        for field_bits in bits.chunks(<F::Params as FpParameters>::CAPACITY as usize) {
            let mut field_bits_big_endian = field_bits.to_vec();
            field_bits_big_endian.resize(<F::BigInt as BigInteger>::NUM_LIMBS * 64, false);
            field_bits_big_endian.reverse();

            field_elements.push(
                F::from_repr(<F::BigInt as BigInteger>::from_bits_be(
                    &field_bits_big_endian,
                ))
                .unwrap(),
            );
        }

        // Step 3: clone a freshly new sponge and put the field elements into
        let mut sponge = parameters.clone();
        sponge.absorb(&field_elements);

        // Step 4: output one element
        let res = sponge.squeeze(1);
        Ok(res[0])
    }

    fn two_to_one_compress(
        parameters: &Self::Parameters,
        left: &Self::Output,
        right: &Self::Output,
    ) -> Result<Self::Output, Error> {
        // Step 1: clone a freshly new sponge and put the field elements into
        let mut sponge = parameters.clone();
        sponge.absorb(&[*left, *right]);

        // Step 2: output one element
        let res = sponge.squeeze(1);
        Ok(res[0])
    }

    fn four_to_one_compress(
        parameters: &Self::Parameters,
        elts: &[Self::Output],
    ) -> Result<Self::Output, Error> {
        // Step 1: clone a freshly new sponge and put the field elements into
        let mut sponge = parameters.clone();
        sponge.absorb(elts);

        // Step 2: output one element
        let res = sponge.squeeze(1);
        Ok(res[0])
    }
}

/// Gadgets of the Bowe-Hopwood CRH combining with the compressor
pub struct PoseidonCRHforMerkleTreeGadget<
    RO: Rng + CryptoRng + SeedableRng,
    F: PrimeField + Absorbable<F>,
> {
    _rand: PhantomData<RO>,
    _field: PhantomData<F>,
}

impl<RO: Rng + CryptoRng + SeedableRng, F: PrimeField + Absorbable<F>>
    CRHforMerkleTreeGadget<PoseidonCRHforMerkleTree<RO, F>, F>
    for PoseidonCRHforMerkleTreeGadget<RO, F>
{
    type OutputVar = FpVar<F>;

    fn hash_bytes(
        parameters: &<PoseidonCRHforMerkleTree<RO, F> as CRHforMerkleTree>::Parameters,
        input: &[UInt8<F>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        let cs = input.cs();

        if cs == ConstraintSystemRef::None {
            let mut bytes = Vec::new();

            for input_elem in input.iter() {
                bytes.push(input_elem.value()?);
            }

            Ok(FpVar::<F>::constant(
                PoseidonCRHforMerkleTree::<RO, F>::hash_bytes(parameters, &bytes).unwrap(),
            ))
        } else {
            // Step 1: pack the bytes into little-endian bit sequences
            let mut bits = Vec::new();

            for input_elem in input.iter() {
                bits.extend_from_slice(&input_elem.to_bits_le()?);
            }

            // Step 2: split it into a few field elements
            let mut field_elements = Vec::new();
            for field_bits in bits.chunks(<F::Params as FpParameters>::CAPACITY as usize) {
                let mut res = FpVar::<F>::zero();
                let mut cur = F::one();

                for bit in field_bits.iter() {
                    res += <FpVar<F> as From<Boolean<F>>>::from((*bit).clone()) * cur;
                    cur.double_in_place();
                }

                field_elements.push(res);
            }

            // Step 3: clone a freshly new sponge and put the field elements into
            let mut sponge = PoseidonSpongeVar::constant(cs, parameters);
            sponge.absorb(&field_elements)?;

            // Step 4: output one element
            let res = sponge.squeeze(1)?;
            Ok(res[0].clone())
        }
    }

    fn two_to_one_compress(
        parameters: &<PoseidonCRHforMerkleTree<RO, F> as CRHforMerkleTree>::Parameters,
        left: &Self::OutputVar,
        right: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let cs = left.cs().or(right.cs());

        if cs == ConstraintSystemRef::None {
            Ok(FpVar::<F>::Constant(
                PoseidonCRHforMerkleTree::<RO, F>::two_to_one_compress(
                    parameters,
                    &left.value()?,
                    &right.value()?,
                )
                .unwrap(),
            ))
        } else {
            // Step 1: clone a freshly new sponge and put the field elements into
            let mut sponge = PoseidonSpongeVar::constant(cs, parameters);
            sponge.absorb(&[left.clone(), right.clone()])?;

            // Step 2: output one element
            let res = sponge.squeeze(1)?;
            Ok(res[0].clone())
        }
    }

    fn four_to_one_compress(
        parameters: &<PoseidonCRHforMerkleTree<RO, F> as CRHforMerkleTree>::Parameters,
        elts: &[Self::OutputVar],
    ) -> Result<Self::OutputVar, SynthesisError> {
        let cs = elts.cs();

        if cs == ConstraintSystemRef::None {
            let mut vals: Vec<F> = Vec::new();
            for i in 0..elts.len() {
                vals.push(elts[i].value()?);
            }

            Ok(FpVar::<F>::Constant(
                PoseidonCRHforMerkleTree::<RO, F>::four_to_one_compress(parameters, &vals).unwrap(),
            ))
        } else {
            // Step 1: clone a freshly new sponge and put the field elements into
            let mut sponge = PoseidonSpongeVar::constant(cs, parameters);
            sponge.absorb(elts)?;

            // Step 2: output one element
            let res = sponge.squeeze(1)?;
            Ok(res[0].clone())
        }
    }
}
