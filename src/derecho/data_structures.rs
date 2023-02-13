use ark_ff::to_bytes;
use ark_r1cs_std::alloc::AllocationMode;
use ark_r1cs_std::bits::uint8::UInt8;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::Namespace;
use ark_serialize::{CanonicalSerialize, SerializationError};
use ark_sponge::constraints::AbsorbableGadget;
use ark_sponge::Absorbable;
use ark_std::io::{Result as IoResult, Write};

use crate::{
    building_blocks::{
        crh::{CRHforMerkleTree, CRHforMerkleTreeGadget},
        mt::MT,
    },
    derecho::disclosure::VerifiableDisclosureConfig,
    gadgets::{AllocVar, ToBytesGadget, UInt64},
    Borrow, SynthesisError, ToBytes, Vec,
};

/// The below components are recursively composed to yield message and local data for PCDPredicate.
///
/// Each component of message needs to implement:
///     Absorbable + ToBytes + Clone + Default.
///
/// Each component of message gadget needs to implement:
///     AbsorbableGadget<F> + ToBytesGadget<F> + AllocVar<Self::Message, F>.
///
/// Each component of witness needs to implement:
///     Clone + Default.
///
/// Each component of witness gadget needs to implement
///     AllocVar<Self::LocalWitness, F>.

/// the public tx info in Derecho
#[derive(CanonicalSerialize)]
pub struct PublicTxInfo<VC: VerifiableDisclosureConfig> {
    /// input nullifier
    pub in_null: <VC::H as CRHforMerkleTree>::Output,

    /// output coin commitment
    pub out_cm: <VC::H as CRHforMerkleTree>::Output,
}

impl<VC: VerifiableDisclosureConfig> Absorbable<VC::F> for PublicTxInfo<VC> {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.append(&mut Absorbable::<VC::F>::to_sponge_bytes(
            &to_bytes!(self.in_null).unwrap(),
        ));
        output.append(&mut Absorbable::<VC::F>::to_sponge_bytes(
            &to_bytes!(self.out_cm).unwrap(),
        ));
        output
    }

    fn to_sponge_field_elements(&self) -> Vec<VC::F> {
        let mut output = Vec::new();
        output.append(&mut Absorbable::<VC::F>::to_sponge_field_elements(
            &to_bytes!(self.in_null).unwrap(),
        ));
        output.append(&mut Absorbable::<VC::F>::to_sponge_field_elements(
            &to_bytes!(self.out_cm).unwrap(),
        ));
        output
    }
}

impl<VC: VerifiableDisclosureConfig> ToBytes for PublicTxInfo<VC> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.in_null.write(&mut writer)?;
        self.out_cm.write(&mut writer)?;
        Ok(())
    }
}

impl<VC: VerifiableDisclosureConfig> Clone for PublicTxInfo<VC> {
    fn clone(&self) -> Self {
        PublicTxInfo {
            in_null: self.in_null,
            out_cm: self.out_cm,
        }
    }
}

impl<VC: VerifiableDisclosureConfig> Default for PublicTxInfo<VC> {
    fn default() -> Self {
        PublicTxInfo {
            in_null: <VC::H as CRHforMerkleTree>::Output::default(),
            out_cm: <VC::H as CRHforMerkleTree>::Output::default(),
        }
    }
}

/// the public tx info gadget in Derecho
pub struct PublicTxInfoVar<VC: VerifiableDisclosureConfig> {
    /// input nullifier
    pub in_null_g: <VC::HG as CRHforMerkleTreeGadget<VC::H, VC::F>>::OutputVar,
    /// output coin commitment
    pub out_cm_g: <VC::HG as CRHforMerkleTreeGadget<VC::H, VC::F>>::OutputVar,
}

impl<VC: VerifiableDisclosureConfig> AllocVar<PublicTxInfo<VC>, VC::F> for PublicTxInfoVar<VC> {
    fn new_variable<T: Borrow<PublicTxInfo<VC>>>(
        cs: impl Into<Namespace<<VC as VerifiableDisclosureConfig>::F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let t = f()?;
        let tx_info = t.borrow().clone();

        let in_null_g = <VC::HG as CRHforMerkleTreeGadget<VC::H, VC::F>>::OutputVar::new_variable(
            ark_relations::ns!(cs, "public_tx_info_gadget_in_null"),
            || Ok(tx_info.in_null),
            mode,
        )?;
        let out_cm_g = <VC::HG as CRHforMerkleTreeGadget<VC::H, VC::F>>::OutputVar::new_variable(
            ark_relations::ns!(cs, "public_tx_info_gadget_out_cm"),
            || Ok(tx_info.out_cm),
            mode,
        )?;

        Ok(PublicTxInfoVar {
            in_null_g,
            out_cm_g,
        })
    }
}

impl<VC: VerifiableDisclosureConfig> ToBytesGadget<VC::F> for PublicTxInfoVar<VC> {
    fn to_bytes(&self) -> Result<Vec<UInt8<VC::F>>, SynthesisError> {
        let mut res: Vec<UInt8<VC::F>> = Vec::new();
        let in_null_g_bytes = self.in_null_g.to_bytes()?;
        let out_cm_g_bytes = self.out_cm_g.to_bytes()?;

        res.extend_from_slice(&in_null_g_bytes);
        res.extend_from_slice(&out_cm_g_bytes);

        Ok(res)
    }
}

impl<VC: VerifiableDisclosureConfig> AbsorbableGadget<VC::F> for PublicTxInfoVar<VC> {
    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<VC::F>>, SynthesisError> {
        let mut output = Vec::new();
        output.append(&mut (self.in_null_g.to_bytes()?.to_sponge_field_elements()?));
        output.append(&mut (self.out_cm_g.to_bytes()?.to_sponge_field_elements()?));
        Ok(output)
    }
}

/// the private tx info in Derecho
#[derive(CanonicalSerialize)]
pub struct PrivateTxInfo<VC: VerifiableDisclosureConfig> {
    /// input amount
    pub in_amt: VC::F,
    /// input public key
    pub in_pk: VC::F,
    /// input commitment randomness
    pub in_rand: VC::F,
    /// output amount
    pub out_amt: VC::F,
    /// output public key
    pub out_pk: VC::F,
    /// output commitment randomness
    pub out_rand: VC::F,
}

impl<VC: VerifiableDisclosureConfig> Clone for PrivateTxInfo<VC> {
    fn clone(&self) -> Self {
        PrivateTxInfo {
            in_amt: self.in_amt,
            in_pk: self.in_pk,
            in_rand: self.in_rand,
            out_amt: self.out_amt,
            out_pk: self.out_pk,
            out_rand: self.out_rand,
        }
    }
}

impl<VC: VerifiableDisclosureConfig> Default for PrivateTxInfo<VC> {
    fn default() -> Self {
        PrivateTxInfo {
            in_amt: VC::F::default(),
            in_pk: VC::F::default(),
            in_rand: VC::F::default(),
            out_amt: VC::F::default(),
            out_pk: VC::F::default(),
            out_rand: VC::F::default(),
        }
    }
}

/// the private tx info gadget in Derecho
pub struct PrivateTxInfoVar<VC: VerifiableDisclosureConfig> {
    /// input amount
    pub in_amt_g: FpVar<VC::F>,
    /// input public key
    pub in_pk_g: FpVar<VC::F>,
    /// input commitment randomness
    pub in_rand_g: FpVar<VC::F>,
    /// output amount
    pub out_amt_g: FpVar<VC::F>,
    /// output public key
    pub out_pk_g: FpVar<VC::F>,
    /// output commitment randomness
    pub out_rand_g: FpVar<VC::F>,
}

impl<VC: VerifiableDisclosureConfig> AllocVar<PrivateTxInfo<VC>, VC::F> for PrivateTxInfoVar<VC> {
    fn new_variable<T: Borrow<PrivateTxInfo<VC>>>(
        cs: impl Into<Namespace<<VC as VerifiableDisclosureConfig>::F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let t = f()?;
        let tx_info = t.borrow().clone();

        let in_amt_g = FpVar::<VC::F>::new_variable(
            ark_relations::ns!(cs, "private_tx_info_gadget_in_amt"),
            || Ok(&tx_info.in_amt),
            mode,
        )?;
        let in_pk_g = FpVar::<VC::F>::new_variable(
            ark_relations::ns!(cs, "private_tx_info_gadget_in_pk"),
            || Ok(&tx_info.in_pk),
            mode,
        )?;
        let in_rand_g = FpVar::<VC::F>::new_variable(
            ark_relations::ns!(cs, "private_tx_info_gadget_in_rand"),
            || Ok(&tx_info.in_rand),
            mode,
        )?;
        let out_amt_g = FpVar::<VC::F>::new_variable(
            ark_relations::ns!(cs, "private_tx_info_gadget_out_amt"),
            || Ok(&tx_info.out_amt),
            mode,
        )?;
        let out_pk_g = FpVar::<VC::F>::new_variable(
            ark_relations::ns!(cs, "private_tx_info_gadget_out_pk"),
            || Ok(&tx_info.out_pk),
            mode,
        )?;
        let out_rand_g = FpVar::<VC::F>::new_variable(
            ark_relations::ns!(cs, "private_tx_info_gadget_out_rand"),
            || Ok(&tx_info.out_rand),
            mode,
        )?;

        Ok(PrivateTxInfoVar {
            in_amt_g,
            in_pk_g,
            in_rand_g,
            out_amt_g,
            out_pk_g,
            out_rand_g,
        })
    }
}

/// the public acc info in Derecho
#[derive(CanonicalSerialize)]
pub struct PublicAccInfo<VC: VerifiableDisclosureConfig> {
    /// membership declaration
    pub member_decl: <VC::H as CRHforMerkleTree>::Output,
    /// root hash of the membership declaration tree
    pub member_rh: <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::Digest,
    /// deposit record
    pub deposit_rec: <VC::H as CRHforMerkleTree>::Output,
    /// deposit uid
    pub deposit_uid: VC::F,
    /// root hash of the deposit record tree
    pub deposit_rh: <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::Digest,
    /// transfer record
    pub transfer_rec: <VC::H as CRHforMerkleTree>::Output,
    /// root hash of the transfer record tree
    pub transfer_rh: <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::Digest,
}

impl<VC: VerifiableDisclosureConfig> Absorbable<VC::F> for PublicAccInfo<VC> {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.append(&mut Absorbable::<VC::F>::to_sponge_bytes(
            &to_bytes!(self.member_decl).unwrap(),
        ));
        output.append(&mut Absorbable::<VC::F>::to_sponge_bytes(
            &to_bytes!(self.member_rh).unwrap(),
        ));
        output.append(&mut Absorbable::<VC::F>::to_sponge_bytes(
            &to_bytes!(self.deposit_rec).unwrap(),
        ));
        output.append(&mut Absorbable::<VC::F>::to_sponge_bytes(
            &to_bytes!(self.deposit_uid).unwrap(),
        ));
        output.append(&mut Absorbable::<VC::F>::to_sponge_bytes(
            &to_bytes!(self.deposit_rh).unwrap(),
        ));
        output.append(&mut Absorbable::<VC::F>::to_sponge_bytes(
            &to_bytes!(self.transfer_rec).unwrap(),
        ));
        output.append(&mut Absorbable::<VC::F>::to_sponge_bytes(
            &to_bytes!(self.transfer_rh).unwrap(),
        ));
        output
    }

    fn to_sponge_field_elements(&self) -> Vec<VC::F> {
        let mut output = Vec::new();
        output.append(&mut Absorbable::<VC::F>::to_sponge_field_elements(
            &to_bytes!(self.member_decl).unwrap(),
        ));
        output.append(&mut Absorbable::<VC::F>::to_sponge_field_elements(
            &to_bytes!(self.member_rh).unwrap(),
        ));
        output.append(&mut Absorbable::<VC::F>::to_sponge_field_elements(
            &to_bytes!(self.deposit_rec).unwrap(),
        ));
        output.append(&mut Absorbable::<VC::F>::to_sponge_field_elements(
            &to_bytes!(self.deposit_uid).unwrap(),
        ));
        output.append(&mut Absorbable::<VC::F>::to_sponge_field_elements(
            &to_bytes!(self.deposit_rh).unwrap(),
        ));
        output.append(&mut Absorbable::<VC::F>::to_sponge_field_elements(
            &to_bytes!(self.transfer_rec).unwrap(),
        ));
        output.append(&mut Absorbable::<VC::F>::to_sponge_field_elements(
            &to_bytes!(self.transfer_rh).unwrap(),
        ));
        output
    }
}

impl<VC: VerifiableDisclosureConfig> ToBytes for PublicAccInfo<VC> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.member_decl.write(&mut writer)?;
        self.member_rh.write(&mut writer)?;
        self.deposit_rec.write(&mut writer)?;
        self.deposit_uid.write(&mut writer)?;
        self.deposit_rh.write(&mut writer)?;
        self.transfer_rec.write(&mut writer)?;
        self.transfer_rh.write(&mut writer)?;
        Ok(())
    }
}

impl<VC: VerifiableDisclosureConfig> Clone for PublicAccInfo<VC> {
    fn clone(&self) -> Self {
        PublicAccInfo {
            member_decl: self.member_decl,
            member_rh: self.member_rh.clone(),
            deposit_rec: self.deposit_rec,
            deposit_uid: self.deposit_uid,
            deposit_rh: self.deposit_rh.clone(),
            transfer_rec: self.transfer_rec,
            transfer_rh: self.transfer_rh.clone(),
        }
    }
}

impl<VC: VerifiableDisclosureConfig> Default for PublicAccInfo<VC> {
    fn default() -> Self {
        PublicAccInfo {
            member_decl: <VC::H as CRHforMerkleTree>::Output::default(),
            member_rh: <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::Digest::default(),
            deposit_rec: <VC::H as CRHforMerkleTree>::Output::default(),
            deposit_uid: VC::F::default(),
            deposit_rh: <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::Digest::default(),
            transfer_rec: <VC::H as CRHforMerkleTree>::Output::default(),
            transfer_rh: <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::Digest::default(),
        }
    }
}

/// the public acc info gadget in Derecho
pub struct PublicAccInfoVar<VC: VerifiableDisclosureConfig> {
    /// membership declaration
    pub member_decl_g: <VC::HG as CRHforMerkleTreeGadget<VC::H, VC::F>>::OutputVar,
    /// root hash of the membership declaration tree
    pub member_rh_g: <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::DigestVar,
    /// deposit record
    pub deposit_rec_g: <VC::HG as CRHforMerkleTreeGadget<VC::H, VC::F>>::OutputVar,
    /// deposit uid
    pub deposit_uid_g: FpVar<VC::F>,
    /// root hash of the deposit record tree
    pub deposit_rh_g: <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::DigestVar,
    /// transfer record
    pub transfer_rec_g: <VC::HG as CRHforMerkleTreeGadget<VC::H, VC::F>>::OutputVar,
    /// root hash of the transfer record tree
    pub transfer_rh_g: <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::DigestVar,
}

impl<VC: VerifiableDisclosureConfig> AllocVar<PublicAccInfo<VC>, VC::F> for PublicAccInfoVar<VC> {
    fn new_variable<T: Borrow<PublicAccInfo<VC>>>(
        cs: impl Into<Namespace<<VC as VerifiableDisclosureConfig>::F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let t = f()?;
        let acc_info = t.borrow().clone();

        let member_decl_g =
            <VC::HG as CRHforMerkleTreeGadget<VC::H, VC::F>>::OutputVar::new_variable(
                ark_relations::ns!(cs, "public_acc_info_gadget_member_decl"),
                || Ok(acc_info.member_decl),
                mode,
            )?;
        let member_rh_g = <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::DigestVar::new_variable(
            ark_relations::ns!(cs, "public_acc_info_gadget_member_rh"),
            || Ok(&acc_info.member_rh),
            mode,
        )?;
        let deposit_rec_g =
            <VC::HG as CRHforMerkleTreeGadget<VC::H, VC::F>>::OutputVar::new_variable(
                ark_relations::ns!(cs, "public_acc_info_gadget_deposit_rec"),
                || Ok(acc_info.deposit_rec),
                mode,
            )?;
        let deposit_uid_g = FpVar::<VC::F>::new_variable(
            ark_relations::ns!(cs, "public_acc_info_gadget_deposit_uid"),
            || Ok(&acc_info.deposit_uid),
            mode,
        )?;
        let deposit_rh_g =
            <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::DigestVar::new_variable(
                ark_relations::ns!(cs, "public_acc_info_gadget_deposit_rh"),
                || Ok(&acc_info.deposit_rh),
                mode,
            )?;
        let transfer_rec_g =
            <VC::HG as CRHforMerkleTreeGadget<VC::H, VC::F>>::OutputVar::new_variable(
                ark_relations::ns!(cs, "public_acc_info_gadget_transfer_rec"),
                || Ok(acc_info.transfer_rec),
                mode,
            )?;
        let transfer_rh_g =
            <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::DigestVar::new_variable(
                ark_relations::ns!(cs, "public_acc_info_gadget_transfer_rh"),
                || Ok(&acc_info.transfer_rh),
                mode,
            )?;
        Ok(PublicAccInfoVar {
            member_decl_g,
            member_rh_g,
            deposit_rec_g,
            deposit_uid_g,
            deposit_rh_g,
            transfer_rec_g,
            transfer_rh_g,
        })
    }
}

impl<VC: VerifiableDisclosureConfig> ToBytesGadget<VC::F> for PublicAccInfoVar<VC> {
    fn to_bytes(&self) -> Result<Vec<UInt8<VC::F>>, SynthesisError> {
        let mut res: Vec<UInt8<VC::F>> = Vec::new();
        let member_decl_g_bytes = self.member_decl_g.to_bytes()?;
        let member_rh_g_bytes = self.member_rh_g.to_bytes()?;
        let deposit_rec_g_bytes = self.deposit_rec_g.to_bytes()?;
        let deposit_uid_g_bytes = self.deposit_uid_g.to_bytes()?;
        let deposit_rh_g_bytes = self.deposit_rh_g.to_bytes()?;
        let transfer_rec_g_bytes = self.transfer_rec_g.to_bytes()?;
        let transfer_rh_g_bytes = self.transfer_rh_g.to_bytes()?;

        res.extend_from_slice(&member_decl_g_bytes);
        res.extend_from_slice(&member_rh_g_bytes);
        res.extend_from_slice(&deposit_rec_g_bytes);
        res.extend_from_slice(&deposit_uid_g_bytes);
        res.extend_from_slice(&deposit_rh_g_bytes);
        res.extend_from_slice(&transfer_rec_g_bytes);
        res.extend_from_slice(&transfer_rh_g_bytes);

        Ok(res)
    }
}

impl<VC: VerifiableDisclosureConfig> AbsorbableGadget<VC::F> for PublicAccInfoVar<VC> {
    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<VC::F>>, SynthesisError> {
        let mut output = Vec::new();
        output.append(&mut (self.member_decl_g.to_bytes()?.to_sponge_field_elements()?));
        output.append(&mut (self.member_rh_g.to_bytes()?.to_sponge_field_elements()?));
        output.append(&mut (self.deposit_rec_g.to_bytes()?.to_sponge_field_elements()?));
        output.append(&mut (self.deposit_uid_g.to_bytes()?.to_sponge_field_elements()?));
        output.append(&mut (self.deposit_rh_g.to_bytes()?.to_sponge_field_elements()?));
        output.append(&mut (self.transfer_rec_g.to_bytes()?.to_sponge_field_elements()?));
        output.append(&mut (self.transfer_rh_g.to_bytes()?.to_sponge_field_elements()?));
        Ok(output)
    }
}

/// the private acc info in Derecho
#[derive(CanonicalSerialize)]
pub struct PrivateAccInfo<VC: VerifiableDisclosureConfig> {
    /// membership witness (address) for the membership declaration tree
    pub member_addr: Vec<u64>,
    /// membership witness (path) for the membership declaration tree
    pub member_proof: <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::LookupProof,
    /// history proof (address) for the membership declaration tree
    pub member_history_addr: Vec<u64>,
    /// history proof (path) for the membership declaration tree
    pub member_history_proof: <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::LookupProof,
    /// membership witness (address) for the deposit record tree
    pub deposit_addr: Vec<u64>,
    /// membership witness (path) for the deposit record tree
    pub deposit_proof: <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::LookupProof,
    /// history proof (address) for the deposit record tree
    pub deposit_history_addr: Vec<u64>,
    /// history proof (path) for the deposit record tree
    pub deposit_history_proof: <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::LookupProof,
    /// membership witness (address) for the transfer record tree
    pub transfer_addr: Vec<u64>,
    /// membership witness (path) for the transfer record tree
    pub transfer_proof: <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::LookupProof,
    /// history proof (address) for the transfer record tree
    pub transfer_history_addr: Vec<u64>,
    /// history proof (path) for the transfer record tree
    pub transfer_history_proof: <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::LookupProof,
}

impl<VC: VerifiableDisclosureConfig> Clone for PrivateAccInfo<VC> {
    fn clone(&self) -> Self {
        PrivateAccInfo {
            member_addr: self.member_addr.clone(),
            deposit_addr: self.deposit_addr.clone(),
            transfer_addr: self.transfer_addr.clone(),
            member_proof: self.member_proof.clone(),
            deposit_proof: self.deposit_proof.clone(),
            transfer_proof: self.transfer_proof.clone(),
            member_history_addr: self.member_history_addr.clone(),
            deposit_history_addr: self.deposit_history_addr.clone(),
            transfer_history_addr: self.transfer_history_addr.clone(),
            member_history_proof: self.member_history_proof.clone(),
            deposit_history_proof: self.deposit_history_proof.clone(),
            transfer_history_proof: self.transfer_history_proof.clone(),
        }
    }
}

impl<VC: VerifiableDisclosureConfig> Default for PrivateAccInfo<VC> {
    fn default() -> Self {
        let member_addr = vec![0];
        let member_proof =
            <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::default_lookup_proof(1).unwrap();
        let member_history_addr = vec![0];
        let member_history_proof =
            <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::default_lookup_proof(1).unwrap();
        let deposit_addr = vec![0];
        let deposit_proof =
            <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::default_lookup_proof(1).unwrap();
        let deposit_history_addr = vec![0];
        let deposit_history_proof =
            <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::default_lookup_proof(1).unwrap();
        let transfer_addr = vec![0];
        let transfer_proof =
            <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::default_lookup_proof(1).unwrap();
        let transfer_history_addr = vec![0];
        let transfer_history_proof =
            <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::default_lookup_proof(1).unwrap();
        PrivateAccInfo {
            member_addr,
            deposit_addr,
            transfer_addr,
            member_proof,
            deposit_proof,
            transfer_proof,
            member_history_addr,
            deposit_history_addr,
            transfer_history_addr,
            member_history_proof,
            deposit_history_proof,
            transfer_history_proof,
        }
    }
}

/// the private acc info gadget in Derecho
pub struct PrivateAccInfoVar<VC: VerifiableDisclosureConfig> {
    /// membership witness (address) for the membership declaration tree
    pub member_addr_g: Vec<UInt64<VC::F>>,
    /// membership witness (path) for the membership declaration tree
    pub member_proof_g: <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::LookupProofVar,
    /// history proof (address) for the membership declaration tree
    pub member_history_addr_g: Vec<UInt64<VC::F>>,
    /// history proof (path) for the membership declaration tree
    pub member_history_proof_g: <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::LookupProofVar,
    /// membership witness (address) for the deposit record tree
    pub deposit_addr_g: Vec<UInt64<VC::F>>,
    /// membership witness (path) for the deposit record tree
    pub deposit_proof_g: <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::LookupProofVar,
    /// history proof (address) for the deposit record tree
    pub deposit_history_addr_g: Vec<UInt64<VC::F>>,
    /// history proof (path) for the deposit record tree
    pub deposit_history_proof_g: <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::LookupProofVar,
    /// membership witness (address) for the transfer record tree
    pub transfer_addr_g: Vec<UInt64<VC::F>>,
    /// membership witness (path) for the transfer record tree
    pub transfer_proof_g: <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::LookupProofVar,
    /// history proof (address) for the transfer record tree
    pub transfer_history_addr_g: Vec<UInt64<VC::F>>,
    /// history proof (path) for the transfer record tree
    pub transfer_history_proof_g: <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::LookupProofVar,
}

impl<VC: VerifiableDisclosureConfig> AllocVar<PrivateAccInfo<VC>, VC::F> for PrivateAccInfoVar<VC> {
    fn new_variable<T: Borrow<PrivateAccInfo<VC>>>(
        cs: impl Into<Namespace<<VC as VerifiableDisclosureConfig>::F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let t = f()?;
        let acc_info = t.borrow().clone();

        assert_eq!(acc_info.member_addr.len(), 1);
        assert_eq!(acc_info.deposit_addr.len(), 1);
        assert_eq!(acc_info.transfer_addr.len(), 1);

        let member_addr_g = Vec::<UInt64<VC::F>>::new_variable(
            ark_relations::ns!(cs, "private_acc_info_gadget_member_addr"),
            || Ok(acc_info.member_addr.clone()),
            mode,
        )?;
        let member_proof_g =
            <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::LookupProofVar::new_variable(
                ark_relations::ns!(cs, "private_acc_info_gadget_member_proof"),
                || Ok(&acc_info.member_proof),
                mode,
            )?;
        let member_history_addr_g = Vec::<UInt64<VC::F>>::new_variable(
            ark_relations::ns!(cs, "private_acc_info_gadget_member_history_addr"),
            || Ok(acc_info.member_history_addr.clone()),
            mode,
        )?;
        let member_history_proof_g =
            <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::LookupProofVar::new_variable(
                ark_relations::ns!(cs, "private_acc_info_gadget_member_history_proof"),
                || Ok(&acc_info.member_history_proof),
                mode,
            )?;

        let deposit_addr_g = Vec::<UInt64<VC::F>>::new_variable(
            ark_relations::ns!(cs, "private_acc_info_gadget_deposit_addr"),
            || Ok(acc_info.deposit_addr.clone()),
            mode,
        )?;
        let deposit_proof_g =
            <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::LookupProofVar::new_variable(
                ark_relations::ns!(cs, "private_acc_info_gadget_deposit_proof"),
                || Ok(&acc_info.deposit_proof),
                mode,
            )?;
        let deposit_history_addr_g = Vec::<UInt64<VC::F>>::new_variable(
            ark_relations::ns!(cs, "private_acc_info_gadget_deposit_history_addr"),
            || Ok(acc_info.deposit_history_addr.clone()),
            mode,
        )?;
        let deposit_history_proof_g =
            <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::LookupProofVar::new_variable(
                ark_relations::ns!(cs, "private_acc_info_gadget_deposit_history_proof"),
                || Ok(&acc_info.deposit_history_proof),
                mode,
            )?;

        let transfer_addr_g = Vec::<UInt64<VC::F>>::new_variable(
            ark_relations::ns!(cs, "private_acc_info_gadget_transfer_addr"),
            || Ok(acc_info.transfer_addr.clone()),
            mode,
        )?;
        let transfer_proof_g =
            <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::LookupProofVar::new_variable(
                ark_relations::ns!(cs, "private_acc_info_gadget_transfer_proof"),
                || Ok(&acc_info.transfer_proof),
                mode,
            )?;
        let transfer_history_addr_g = Vec::<UInt64<VC::F>>::new_variable(
            ark_relations::ns!(cs, "private_acc_info_gadget_transfer_history_addr"),
            || Ok(acc_info.transfer_history_addr.clone()),
            mode,
        )?;
        let transfer_history_proof_g =
            <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::LookupProofVar::new_variable(
                ark_relations::ns!(cs, "private_acc_info_gadget_transfer_history_proof"),
                || Ok(&acc_info.transfer_history_proof),
                mode,
            )?;

        Ok(PrivateAccInfoVar {
            member_addr_g,
            member_proof_g,
            member_history_addr_g,
            member_history_proof_g,
            deposit_addr_g,
            deposit_proof_g,
            deposit_history_addr_g,
            deposit_history_proof_g,
            transfer_addr_g,
            transfer_proof_g,
            transfer_history_addr_g,
            transfer_history_proof_g,
        })
    }
}

/// the PCD message for Derecho
#[derive(CanonicalSerialize)]
pub struct VerifiableDisclosureMsg<VC: VerifiableDisclosureConfig> {
    /// the public tx info
    pub tx_info: PublicTxInfo<VC>,
    /// the public acc info
    pub acc_info: PublicAccInfo<VC>,
}

impl<VC: VerifiableDisclosureConfig> Absorbable<VC::F> for VerifiableDisclosureMsg<VC> {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.append(&mut self.tx_info.to_sponge_bytes());
        output.append(&mut self.acc_info.to_sponge_bytes());
        output
    }

    fn to_sponge_field_elements(&self) -> Vec<VC::F> {
        let mut output = Vec::new();
        output.append(&mut self.tx_info.to_sponge_field_elements());
        output.append(&mut self.acc_info.to_sponge_field_elements());
        output
    }
}

impl<VC: VerifiableDisclosureConfig> ToBytes for VerifiableDisclosureMsg<VC> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.tx_info.write(&mut writer)?;
        self.acc_info.write(&mut writer)?;
        Ok(())
    }
}

impl<VC: VerifiableDisclosureConfig> Clone for VerifiableDisclosureMsg<VC> {
    fn clone(&self) -> Self {
        VerifiableDisclosureMsg {
            tx_info: self.tx_info.clone(),
            acc_info: self.acc_info.clone(),
        }
    }
}

impl<VC: VerifiableDisclosureConfig> Default for VerifiableDisclosureMsg<VC> {
    fn default() -> Self {
        let tx_info = PublicTxInfo::<VC>::default();
        let acc_info = PublicAccInfo::<VC>::default();
        VerifiableDisclosureMsg { tx_info, acc_info }
    }
}

/// the PCD message gadget for Derecho
pub struct VerifiableDisclosureMsgVar<VC: VerifiableDisclosureConfig> {
    /// the public tx info
    pub tx_info_g: PublicTxInfoVar<VC>,
    /// the public acc info
    pub acc_info_g: PublicAccInfoVar<VC>,
}

impl<VC: VerifiableDisclosureConfig> AllocVar<VerifiableDisclosureMsg<VC>, VC::F>
    for VerifiableDisclosureMsgVar<VC>
{
    fn new_variable<T: Borrow<VerifiableDisclosureMsg<VC>>>(
        cs: impl Into<Namespace<<VC as VerifiableDisclosureConfig>::F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let t = f()?;
        let msg = t.borrow().clone();

        let tx_info_g = PublicTxInfoVar::<VC>::new_variable(
            ark_relations::ns!(cs, "msg_gadget_tx_info"),
            || Ok(&msg.tx_info),
            mode,
        )?;
        let acc_info_g = PublicAccInfoVar::<VC>::new_variable(
            ark_relations::ns!(cs, "msg_gadget_acc_info"),
            || Ok(&msg.acc_info),
            mode,
        )?;

        Ok(VerifiableDisclosureMsgVar {
            tx_info_g,
            acc_info_g,
        })
    }
}

impl<VC: VerifiableDisclosureConfig> ToBytesGadget<VC::F> for VerifiableDisclosureMsgVar<VC> {
    fn to_bytes(&self) -> Result<Vec<UInt8<VC::F>>, SynthesisError> {
        let mut res: Vec<UInt8<VC::F>> = Vec::new();
        let tx_info_bytes = self.tx_info_g.to_bytes()?;
        let acc_info_bytes = self.acc_info_g.to_bytes()?;

        res.extend_from_slice(&tx_info_bytes);
        res.extend_from_slice(&acc_info_bytes);

        Ok(res)
    }
}

impl<VC: VerifiableDisclosureConfig> AbsorbableGadget<VC::F> for VerifiableDisclosureMsgVar<VC> {
    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<VC::F>>, SynthesisError> {
        let mut output = Vec::new();
        output.append(&mut self.tx_info_g.to_sponge_field_elements()?);
        output.append(&mut self.acc_info_g.to_sponge_field_elements()?);
        Ok(output)
    }
}

/// Witness for Derecho's PCD
#[derive(CanonicalSerialize)]
pub struct VerifiableDisclosureWitness<VC: VerifiableDisclosureConfig> {
    /// the private tx info
    pub tx_info: PrivateTxInfo<VC>,
    /// the private acc info
    pub acc_info: PrivateAccInfo<VC>,
}

impl<VC: VerifiableDisclosureConfig> Clone for VerifiableDisclosureWitness<VC> {
    fn clone(&self) -> Self {
        VerifiableDisclosureWitness {
            tx_info: self.tx_info.clone(),
            acc_info: self.acc_info.clone(),
        }
    }
}

impl<VC: VerifiableDisclosureConfig> Default for VerifiableDisclosureWitness<VC> {
    fn default() -> Self {
        let tx_info = PrivateTxInfo::<VC>::default();
        let acc_info = PrivateAccInfo::<VC>::default();
        VerifiableDisclosureWitness { tx_info, acc_info }
    }
}

/// Witness gadget for Derecho's PCD
pub struct VerifiableDisclosureWitnessVar<VC: VerifiableDisclosureConfig> {
    /// the private tx info
    pub tx_info_g: PrivateTxInfoVar<VC>,
    /// the private acc info
    pub acc_info_g: PrivateAccInfoVar<VC>,
}

impl<VC: VerifiableDisclosureConfig> AllocVar<VerifiableDisclosureWitness<VC>, VC::F>
    for VerifiableDisclosureWitnessVar<VC>
{
    fn new_variable<T: Borrow<VerifiableDisclosureWitness<VC>>>(
        cs: impl Into<Namespace<<VC as VerifiableDisclosureConfig>::F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let t = f()?;
        let witness = t.borrow().clone();

        let tx_info_g = PrivateTxInfoVar::<VC>::new_variable(
            ark_relations::ns!(cs, "witness_gadget_tx_info"),
            || Ok(&witness.tx_info),
            mode,
        )?;
        let acc_info_g = PrivateAccInfoVar::<VC>::new_variable(
            ark_relations::ns!(cs, "witness_gadget_acc_info"),
            || Ok(&witness.acc_info),
            mode,
        )?;

        Ok(VerifiableDisclosureWitnessVar {
            tx_info_g,
            acc_info_g,
        })
    }
}
