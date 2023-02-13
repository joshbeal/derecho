use ark_ec::{ModelParameters, TEModelParameters};
use ark_ff::{PrimeField, ToBytes};
use ark_pcd::variable_length_crh::bowe_hopwood::constraints::{
    VariableLengthBoweHopwoodCompressedCRHGadget, VariableLengthBoweHopwoodParametersVar,
};
use ark_pcd::variable_length_crh::constraints::VariableLengthCRHGadget;
use ark_pcd::variable_length_crh::{
    bowe_hopwood::{VariableLengthBoweHopwoodCompressedCRH, VariableLengthBoweHopwoodParameters},
    VariableLengthCRH,
};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::bits::uint8::UInt8;
use ark_r1cs_std::{R1CSVar, ToBytesGadget};
use ark_relations::r1cs::ConstraintSystemRef;
use ark_sponge::Absorbable;
use ark_std::rand::{CryptoRng, Rng, SeedableRng};
use ark_std::{io::Cursor, vec::Vec};

use crate::building_blocks::crh::{CRHforMerkleTree, CRHforMerkleTreeGadget};
use crate::gadgets::FpVar;
use crate::{Error, PhantomData, SynthesisError};

/// Bowe-Hopwood CRH combining with the compressor (taking only the x-coordinate in the affine representation)
pub struct BoweHopwoodCRHforMerkleTree<RO: Rng + CryptoRng + SeedableRng, P: TEModelParameters>
where
    P::BaseField: PrimeField<BasePrimeField = P::BaseField>,
    <P as ModelParameters>::BaseField: Absorbable<P::BaseField>,
{
    _rand: PhantomData<RO>,
    _group: PhantomData<P>,
}

impl<RO: Rng + CryptoRng + SeedableRng, P: TEModelParameters> CRHforMerkleTree
    for BoweHopwoodCRHforMerkleTree<RO, P>
where
    P::BaseField: PrimeField<BasePrimeField = P::BaseField>,
    <P as ModelParameters>::BaseField: Absorbable<P::BaseField>,
{
    type Output = P::BaseField;
    type Parameters = VariableLengthBoweHopwoodParameters<P>;

    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        VariableLengthBoweHopwoodCompressedCRH::<RO, P>::setup(rng)
    }

    fn hash_bytes(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        VariableLengthBoweHopwoodCompressedCRH::<RO, P>::evaluate(parameters, input)
    }

    fn two_to_one_compress(
        parameters: &Self::Parameters,
        left: &Self::Output,
        right: &Self::Output,
    ) -> Result<Self::Output, Error> {
        let mut writer = Cursor::new(Vec::<u8>::new());
        left.write(&mut writer)?;
        right.write(&mut writer)?;

        VariableLengthBoweHopwoodCompressedCRH::<RO, P>::evaluate(parameters, &writer.into_inner())
    }

    fn four_to_one_compress(
        parameters: &Self::Parameters,
        elts: &[Self::Output],
    ) -> Result<Self::Output, Error> {
        let mut writer = Cursor::new(Vec::<u8>::new());
        elts[0].write(&mut writer)?;
        elts[1].write(&mut writer)?;
        elts[2].write(&mut writer)?;
        elts[3].write(&mut writer)?;

        VariableLengthBoweHopwoodCompressedCRH::<RO, P>::evaluate(parameters, &writer.into_inner())
    }
}

/// Gadgets of the Bowe-Hopwood CRH combining with the compressor
pub struct BoweHopwoodCRHforMerkleTreeGadget<
    RO: Rng + CryptoRng + SeedableRng,
    P: TEModelParameters,
> where
    P::BaseField: PrimeField<BasePrimeField = P::BaseField>,
    <P as ModelParameters>::BaseField: Absorbable<P::BaseField>,
{
    _rand: PhantomData<RO>,
    _group: PhantomData<P>,
}

impl<RO: Rng + CryptoRng + SeedableRng, P: TEModelParameters>
    CRHforMerkleTreeGadget<BoweHopwoodCRHforMerkleTree<RO, P>, P::BaseField>
    for BoweHopwoodCRHforMerkleTreeGadget<RO, P>
where
    P::BaseField: PrimeField<BasePrimeField = P::BaseField>,
    <P as ModelParameters>::BaseField: Absorbable<P::BaseField>,
{
    type OutputVar =
        <VariableLengthBoweHopwoodCompressedCRHGadget<RO, P> as VariableLengthCRHGadget<
            VariableLengthBoweHopwoodCompressedCRH<RO, P>,
            P::BaseField,
        >>::OutputVar;

    fn hash_bytes(
        parameters: &<BoweHopwoodCRHforMerkleTree<RO, P> as CRHforMerkleTree>::Parameters,
        input: &[UInt8<<P as ModelParameters>::BaseField>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        let cs = input.cs();

        if cs == ConstraintSystemRef::None {
            let mut input_value = Vec::new();

            for input_elem in input.iter() {
                input_value.push(input_elem.value()?);
            }

            Ok(Self::OutputVar::Constant(
                VariableLengthBoweHopwoodCompressedCRH::<RO, P>::evaluate(parameters, &input_value)
                    .unwrap(),
            ))
        } else {
            let parameters =
                VariableLengthBoweHopwoodParametersVar::<P>::new_constant(cs, parameters)?;

            VariableLengthBoweHopwoodCompressedCRHGadget::<RO, P>::check_evaluation_gadget(
                &parameters,
                input,
            )
        }
    }

    fn two_to_one_compress(
        parameters: &<BoweHopwoodCRHforMerkleTree<RO, P> as CRHforMerkleTree>::Parameters,
        left: &Self::OutputVar,
        right: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let cs = left.cs().or(right.cs());

        if cs == ConstraintSystemRef::None {
            let mut writer = Cursor::new(Vec::<u8>::new());
            left.value()?.write(&mut writer).unwrap();
            right.value()?.write(&mut writer).unwrap();

            Ok(FpVar::<P::BaseField>::Constant(
                VariableLengthBoweHopwoodCompressedCRH::<RO, P>::evaluate(
                    parameters,
                    &writer.into_inner(),
                )
                .unwrap(),
            ))
        } else {
            let mut input = Vec::<UInt8<<P as ModelParameters>::BaseField>>::new();

            input.extend_from_slice(&left.to_bytes()?);
            input.extend_from_slice(&right.to_bytes()?);

            let parameters =
                VariableLengthBoweHopwoodParametersVar::<P>::new_constant(cs, parameters)?;

            VariableLengthBoweHopwoodCompressedCRHGadget::<RO, P>::check_evaluation_gadget(
                &parameters,
                &input,
            )
        }
    }

    fn four_to_one_compress(
        parameters: &<BoweHopwoodCRHforMerkleTree<RO, P> as CRHforMerkleTree>::Parameters,
        elts: &[Self::OutputVar],
    ) -> Result<Self::OutputVar, SynthesisError> {
        let cs = elts.cs();

        if cs == ConstraintSystemRef::None {
            // Constant values
            // Do not create constraints for them
            let mut writer = Cursor::new(Vec::<u8>::new());
            elts[0].value()?.write(&mut writer).unwrap();
            elts[1].value()?.write(&mut writer).unwrap();
            elts[2].value()?.write(&mut writer).unwrap();
            elts[3].value()?.write(&mut writer).unwrap();

            Ok(FpVar::<P::BaseField>::Constant(
                VariableLengthBoweHopwoodCompressedCRH::<RO, P>::evaluate(
                    parameters,
                    &writer.into_inner(),
                )
                .unwrap(),
            ))
        } else {
            let mut input = Vec::<UInt8<<P as ModelParameters>::BaseField>>::new();

            input.extend_from_slice(&elts[0].to_bytes()?);
            input.extend_from_slice(&elts[1].to_bytes()?);
            input.extend_from_slice(&elts[2].to_bytes()?);
            input.extend_from_slice(&elts[3].to_bytes()?);

            let parameters =
                VariableLengthBoweHopwoodParametersVar::<P>::new_constant(cs, parameters)?;

            VariableLengthBoweHopwoodCompressedCRHGadget::<RO, P>::check_evaluation_gadget(
                &parameters,
                &input,
            )
        }
    }
}
