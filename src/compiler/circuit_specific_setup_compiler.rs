use ark_pcd::PCD;
use ark_std::rand::{CryptoRng, RngCore};

use crate::compiler::Derecho;
use crate::{
    building_blocks::{crh::CRHforMerkleTree, mt::MT},
    derecho::{
        disclosure::{VerifiableDisclosure, VerifiableDisclosureConfig},
        state::VerifiableState,
    },
    gadgets::UInt64,
    Error, PhantomData,
};

/// compiler for circuit-specific setup Derecho
pub struct CircuitSpecificSetupDerechoCompiler<VC: VerifiableDisclosureConfig> {
    vc_phantom: PhantomData<VC>,
}

/// public parameters for circuit-specific setup Derecho
pub struct CircuitSpecificSetupDerechoPP<VC: VerifiableDisclosureConfig> {
    /// Merkle tree public parameters
    pub pp_mt: (
        <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
        <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
        <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
    ),
    /// CRH public parameters
    pub pp_crh: <VC::H as CRHforMerkleTree>::Parameters,
    /// allowlist id
    pub allowlist_id: VC::F,
}

impl<VC: VerifiableDisclosureConfig> CircuitSpecificSetupDerechoCompiler<VC> {
    /// D.setup (circuit-specific)
    pub fn circuit_specific_setup<R: RngCore + CryptoRng>(
        rng: &mut R,
        allowlist_id: VC::F,
    ) -> Result<CircuitSpecificSetupDerechoPP<VC>, Error> {
        let pp_mt = (
            <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::setup(rng)?,
            <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::setup(rng)?,
            <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::setup(rng)?,
        );
        let pp_crh = <VC::H as CRHforMerkleTree>::setup(rng)?;

        Ok(CircuitSpecificSetupDerechoPP {
            pp_mt,
            pp_crh,
            allowlist_id,
        })
    }

    /// D.make_ds
    pub fn make_ds<R: RngCore + CryptoRng>(
        pp: &CircuitSpecificSetupDerechoPP<VC>,
        rng: &mut R,
    ) -> Result<Derecho<VC>, Error> {
        let p = VerifiableDisclosure::<VC> {
            pp_mt: pp.pp_mt.clone(),
            pp_crh: pp.pp_crh.clone(),
            allowlist_id: pp.allowlist_id,
            ipk: None,
            ivk: None,
        };

        let (ipk, ivk) =
            <VC::I as PCD<VC::F>>::circuit_specific_setup::<VerifiableDisclosure<VC>, R>(&p, rng)?;

        Ok(Derecho::<VC> {
            vd: VerifiableDisclosure::<VC> {
                pp_mt: pp.pp_mt.clone(),
                pp_crh: pp.pp_crh.clone(),
                allowlist_id: pp.allowlist_id,
                ipk: Some(ipk),
                ivk: Some(ivk.clone()),
            },
            vs: VerifiableState::<VC> {
                pp_mt: pp.pp_mt.clone(),
                ivk,
            },
        })
    }
}
