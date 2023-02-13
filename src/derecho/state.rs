use ark_pcd::PCD;
use ark_std::collections::BTreeMap;

use crate::{
    building_blocks::{crh::CRHforMerkleTree, mt::MT},
    derecho::{
        data_structures::{
            PrivateAccInfo, PrivateTxInfo, PublicAccInfo, PublicTxInfo, VerifiableDisclosureMsg,
        },
        disclosure::{VerifiableDisclosure, VerifiableDisclosureConfig},
    },
    gadgets::UInt64,
    Error,
};

// this module verifies disclosure and system state

/// the system's state
pub struct State<VC: VerifiableDisclosureConfig> {
    /// the membership declaration map
    pub member_map: BTreeMap<u64, <VC::H as CRHforMerkleTree>::Output>,

    /// the deposit record map
    pub deposit_map: BTreeMap<u64, <VC::H as CRHforMerkleTree>::Output>,

    /// the transfer record map
    pub transfer_map: BTreeMap<u64, <VC::H as CRHforMerkleTree>::Output>,

    /// data to be returned when the item does not exist
    pub default_data: <VC::H as CRHforMerkleTree>::Output,
}

impl<VC: VerifiableDisclosureConfig> Default for State<VC> {
    fn default() -> Self {
        let member_map: BTreeMap<u64, <VC::H as CRHforMerkleTree>::Output> = BTreeMap::new();
        let deposit_map: BTreeMap<u64, <VC::H as CRHforMerkleTree>::Output> = BTreeMap::new();
        let transfer_map: BTreeMap<u64, <VC::H as CRHforMerkleTree>::Output> = BTreeMap::new();
        let default_data = <VC::H as CRHforMerkleTree>::Output::default();

        State {
            member_map,
            deposit_map,
            transfer_map,
            default_data,
        }
    }
}

impl<VC: VerifiableDisclosureConfig> State<VC> {
    /// initialize the state
    pub fn new() -> Result<Self, Error> {
        Ok(Self::default())
    }

    /// read the member state
    pub fn read_member(
        &mut self,
        addr: &u64,
    ) -> Result<&<VC::H as CRHforMerkleTree>::Output, Error> {
        let data = match self.member_map.get(addr) {
            Some(data) => data,
            None => &self.default_data,
        };
        Ok(data)
    }

    /// write to the member state
    pub fn write_member(
        &mut self,
        addr: &u64,
        data: &<VC::H as CRHforMerkleTree>::Output,
    ) -> Result<(), Error> {
        self.member_map.insert(*addr, *data);
        Ok(())
    }

    /// clear the member state
    pub fn clear_member(&mut self) -> Result<(), Error> {
        self.member_map.clear();
        Ok(())
    }

    /// read the deposit state
    pub fn read_deposit(
        &mut self,
        addr: &u64,
    ) -> Result<&<VC::H as CRHforMerkleTree>::Output, Error> {
        let data = match self.deposit_map.get(addr) {
            Some(data) => data,
            None => &self.default_data,
        };
        Ok(data)
    }

    /// write to the deposit state
    pub fn write_deposit(
        &mut self,
        addr: &u64,
        data: &<VC::H as CRHforMerkleTree>::Output,
    ) -> Result<(), Error> {
        self.deposit_map.insert(*addr, *data);
        Ok(())
    }

    /// clear the deposit state
    pub fn clear_deposit(&mut self) -> Result<(), Error> {
        self.deposit_map.clear();
        Ok(())
    }

    /// read the transfer state
    pub fn read_transfer(
        &mut self,
        addr: &u64,
    ) -> Result<&<VC::H as CRHforMerkleTree>::Output, Error> {
        let data = match self.transfer_map.get(addr) {
            Some(data) => data,
            None => &self.default_data,
        };
        Ok(data)
    }

    /// write to the transfer state
    pub fn write_transfer(
        &mut self,
        addr: &u64,
        data: &<VC::H as CRHforMerkleTree>::Output,
    ) -> Result<(), Error> {
        self.transfer_map.insert(*addr, *data);
        Ok(())
    }

    /// clear the transfer state
    pub fn clear_transfer(&mut self) -> Result<(), Error> {
        self.transfer_map.clear();
        Ok(())
    }
}

/// auxiliary state
pub struct AuxState<VC: VerifiableDisclosureConfig> {
    /// the current step count
    pub t: u64,
    // the current opening
    /// the current value amount
    pub amt: Option<VC::F>,
    /// the current public key
    pub pk: Option<VC::F>,
    /// the current commitment randomness
    pub r: Option<VC::F>,
    /// the current public tx info
    pub public_tx_info: Option<PublicTxInfo<VC>>,
    /// the current private tx info
    pub private_tx_info: Option<PrivateTxInfo<VC>>,
    /// the current public acc info
    pub public_acc_info: Option<PublicAccInfo<VC>>,
    /// the current private acc info
    pub private_acc_info: Option<PrivateAccInfo<VC>>,
    /// the current proof
    pub proof: Option<<VC::I as PCD<VC::F>>::Proof>,
    // Current MT state for membership proofs
    /// Merkle tree for membership declarations
    pub tree_member_m: Option<<VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::T>,
    /// Merkle tree for deposit records
    pub tree_deposit_m: Option<<VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::T>,
    /// Merkle tree for transfer records
    pub tree_transfer_m: Option<<VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::T>,
    // Historical MT state for consistency checks
    /// history digest address for membership declarations
    pub old_tree_member_history_addr: u64,
    /// history digest address for deposit records
    pub old_tree_deposit_history_addr: u64,
    /// history digest address for transfer records
    pub old_tree_transfer_history_addr: u64,
}

impl<VC: VerifiableDisclosureConfig> Default for AuxState<VC> {
    fn default() -> Self {
        AuxState {
            t: 0,
            amt: None,
            pk: None,
            r: None,
            public_tx_info: None,
            private_tx_info: None,
            public_acc_info: None,
            private_acc_info: None,
            proof: None,
            tree_member_m: None,
            tree_deposit_m: None,
            tree_transfer_m: None,
            old_tree_member_history_addr: 0,
            old_tree_deposit_history_addr: 0,
            old_tree_transfer_history_addr: 0,
        }
    }
}

impl<VC: VerifiableDisclosureConfig> AuxState<VC> {
    /// initialization
    pub fn init(
        &mut self,
        pp_member: &<VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
        pp_deposit: &<VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
        pp_transfer: &<VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
    ) -> Result<(), Error> {
        self.tree_member_m = Some(VC::MTMember::new::<VC::F>(pp_member)?);
        self.tree_deposit_m = Some(VC::MTDeposit::new::<VC::F>(pp_deposit)?);
        self.tree_transfer_m = Some(VC::MTTransfer::new::<VC::F>(pp_transfer)?);
        Ok(())
    }

    /// seed with initial records and commitment
    pub fn seed(
        &mut self,
        t: u64,
        amt: VC::F,
        pk: VC::F,
        r: VC::F,
        pp_member: &<VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
        member_map: &BTreeMap<u64, <VC::H as CRHforMerkleTree>::Output>,
        old_member_map: &BTreeMap<u64, <VC::H as CRHforMerkleTree>::Output>,
        pp_deposit: &<VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
        deposit_map: &BTreeMap<u64, <VC::H as CRHforMerkleTree>::Output>,
        old_deposit_map: &BTreeMap<u64, <VC::H as CRHforMerkleTree>::Output>,
        pp_transfer: &<VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
        transfer_map: &BTreeMap<u64, <VC::H as CRHforMerkleTree>::Output>,
        old_transfer_map: &BTreeMap<u64, <VC::H as CRHforMerkleTree>::Output>,
    ) -> Result<(), Error> {
        self.t = t;
        self.amt = Some(amt);
        self.pk = Some(pk);
        self.r = Some(r);

        let member_tree_m = self.tree_member_m.as_mut().unwrap();
        for (i, leaf) in member_map.iter() {
            if *i < self.t {
                VC::MTMember::_modify_and_apply(pp_member, member_tree_m, &[*i], &[*leaf], true)
                    .unwrap();
            } else {
                VC::MTMember::_modify_and_apply(pp_member, member_tree_m, &[*i], &[*leaf], false)
                    .unwrap();
            }
        }
        self.old_tree_member_history_addr = old_member_map.keys().cloned().last().unwrap() + 1;

        let deposit_tree_m = self.tree_deposit_m.as_mut().unwrap();
        for (i, leaf) in deposit_map.iter() {
            if *i < self.t {
                VC::MTDeposit::_modify_and_apply(pp_deposit, deposit_tree_m, &[*i], &[*leaf], true)
                    .unwrap();
            } else {
                VC::MTDeposit::_modify_and_apply(
                    pp_deposit,
                    deposit_tree_m,
                    &[*i],
                    &[*leaf],
                    false,
                )
                .unwrap();
            }
        }
        self.old_tree_deposit_history_addr = old_deposit_map.keys().cloned().last().unwrap() + 1;

        let transfer_tree_m = self.tree_transfer_m.as_mut().unwrap();
        for (i, leaf) in transfer_map.iter() {
            if *i < self.t {
                VC::MTTransfer::_modify_and_apply(
                    pp_transfer,
                    transfer_tree_m,
                    &[*i],
                    &[*leaf],
                    true,
                )
                .unwrap();
            } else {
                VC::MTTransfer::_modify_and_apply(
                    pp_transfer,
                    transfer_tree_m,
                    &[*i],
                    &[*leaf],
                    false,
                )
                .unwrap();
            }
        }
        self.old_tree_transfer_history_addr = old_transfer_map.keys().cloned().last().unwrap() + 1;

        Ok(())
    }
}

/// vS
pub struct VerifiableState<VC: VerifiableDisclosureConfig> {
    /// the Merkle tree public parameters
    pub pp_mt: (
        <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
        <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
        <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
    ),
    /// the PCD vk
    pub ivk: <VC::I as PCD<VC::F>>::VerifyingKey,
}

impl<VC: VerifiableDisclosureConfig> VerifiableState<VC> {
    /// vS.verify_disclosure
    pub fn verify_disclosure(
        &self,
        _state: &State<VC>,
        aux_state: &AuxState<VC>,
    ) -> Result<bool, Error> {
        if aux_state.public_tx_info.is_none()
            && aux_state.private_tx_info.is_none()
            && aux_state.public_acc_info.is_none()
            && aux_state.private_acc_info.is_none()
            && aux_state.proof.is_none()
        {
            let member_tree = aux_state.tree_member_m.as_ref().unwrap();
            let member_tree_well_formed = VC::MTMember::validate(&self.pp_mt.0, member_tree)?;
            if !member_tree_well_formed {
                return Ok(false);
            }
            let deposit_tree = aux_state.tree_deposit_m.as_ref().unwrap();
            let deposit_tree_well_formed = VC::MTDeposit::validate(&self.pp_mt.1, deposit_tree)?;
            if !deposit_tree_well_formed {
                return Ok(false);
            }
            let transfer_tree = aux_state.tree_transfer_m.as_ref().unwrap();
            let transfer_tree_well_formed = VC::MTTransfer::validate(&self.pp_mt.2, transfer_tree)?;
            if !transfer_tree_well_formed {
                return Ok(false);
            }
            Ok(true)
        } else {
            let tx_info = aux_state.public_tx_info.as_ref().unwrap();
            let acc_info = aux_state.public_acc_info.as_ref().unwrap();
            let z = VerifiableDisclosureMsg {
                tx_info: tx_info.clone(),
                acc_info: acc_info.clone(),
            };

            let proof = aux_state.proof.as_ref().unwrap();
            let pcd_verify_result =
                VC::I::verify::<VerifiableDisclosure<VC>>(&self.ivk, &z, proof)?;

            if !pcd_verify_result {
                return Ok(false);
            }

            Ok(true)
        }
    }
}
