use ark_pcd::{PCDPredicate, PCD};
use ark_relations::r1cs::ConstraintSystemRef;
use ark_sponge::Absorbable;
use ark_std::fmt::Debug;
use ark_std::io::Cursor;
use ark_std::rand::CryptoRng;
use ark_std::time::Instant;
use ark_std::vec;

use crate::{
    building_blocks::{
        crh::{CRHforMerkleTree, CRHforMerkleTreeGadget},
        mt::MT,
    },
    derecho::{
        data_structures::{
            PrivateAccInfo, PrivateTxInfo, PublicAccInfo, PublicTxInfo, VerifiableDisclosureMsg,
            VerifiableDisclosureMsgVar, VerifiableDisclosureWitness,
            VerifiableDisclosureWitnessVar,
        },
        state::{AuxState, State},
        transfer::ExampleTransfer,
    },
    gadgets::{AllocVar, Boolean, EqGadget, FpVar, ToBytesGadget, UInt64},
    Error, PrimeField, RngCore, Sized, SynthesisError, ToBytes,
};

// this module creates and verifies disclosures

/// a collection of types for verifiable disclosures
pub trait VerifiableDisclosureConfig: Sized {
    /// the main field
    type F: PrimeField + Absorbable<Self::F> + Debug;

    /// CRH for nullifiers, commitments, transfer records
    type H: CRHforMerkleTree;

    /// CRH gadget for nullifiers, commitments, transfer records
    type HG: CRHforMerkleTreeGadget<Self::H, Self::F>;

    /// Merkle tree for membership declarations
    type MTMember: MT<Self::F, u64, UInt64<Self::F>>;

    /// Merkle tree for deposit records
    type MTDeposit: MT<Self::F, u64, UInt64<Self::F>>;

    /// Merkle tree for transfer records
    type MTTransfer: MT<Self::F, u64, UInt64<Self::F>>;

    /// The PCD engine
    type I: PCD<Self::F>;
}

/// verifiable disclosure
pub struct VerifiableDisclosure<VC: VerifiableDisclosureConfig> {
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
    /// the PCD pk
    pub ipk: Option<<VC::I as PCD<VC::F>>::ProvingKey>,
    /// the PCD vk
    pub ivk: Option<<VC::I as PCD<VC::F>>::VerifyingKey>,
}

impl<VC: VerifiableDisclosureConfig> Clone for VerifiableDisclosure<VC> {
    fn clone(&self) -> Self {
        VerifiableDisclosure::<VC> {
            pp_mt: self.pp_mt.clone(),
            pp_crh: self.pp_crh.clone(),
            allowlist_id: self.allowlist_id,
            ipk: self.ipk.clone(),
            ivk: self.ivk.clone(),
        }
    }
}

impl<VC: VerifiableDisclosureConfig> VerifiableDisclosure<VC> {
    /// vD.info
    pub fn info(
        &self,
        _state: &State<VC>,
        aux_state: &AuxState<VC>,
    ) -> Result<
        (
            u64,
            Option<PublicTxInfo<VC>>,
            Option<PublicAccInfo<VC>>,
            Option<<VC::I as PCD<VC::F>>::Proof>,
        ),
        Error,
    > {
        Ok((
            aux_state.t,
            aux_state.public_tx_info.clone(),
            aux_state.public_acc_info.clone(),
            aux_state.proof.clone(),
        ))
    }

    /// vD.run
    pub fn run<R: RngCore + CryptoRng>(
        &mut self,
        state: &mut State<VC>,
        aux_state: &mut AuxState<VC>,
        tfr: &ExampleTransfer<VC>,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut z_old: Option<VerifiableDisclosureMsg<VC>> = None;
        let mut pcd_proof_old: Option<<VC::I as PCD<VC::F>>::Proof> = None;
        let member_read_proof: <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::LookupProof;
        let deposit_read_proof: <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::LookupProof;
        let member_history_proof: <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::LookupProof;
        let deposit_history_proof: <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::LookupProof;
        let transfer_history_proof: <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::LookupProof;
        let member_decl_key_new;
        let deposit_rec_key_new;
        let deposit_uid_new;
        let t_old = aux_state.t;
        let t_new = t_old + 2;

        let tree_member_m = aux_state.tree_member_m.as_ref().unwrap();
        let rh_member_new_m =
            <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::root(&self.pp_mt.0, tree_member_m)?;
        let tree_deposit_m = aux_state.tree_deposit_m.as_ref().unwrap();
        let rh_deposit_new_m =
            <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::root(&self.pp_mt.1, tree_deposit_m)?;
        if tfr.base_case {
            /* the base case */
            println!("executing base case logic...");
            member_decl_key_new = tfr.member_key;
            deposit_rec_key_new = tfr.deposit_key;
            deposit_uid_new = tfr.deposit_uid;

            member_read_proof = <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::lookup(
                &self.pp_mt.0,
                tree_member_m,
                std::slice::from_ref(&member_decl_key_new),
            )?;
            deposit_read_proof = <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::lookup(
                &self.pp_mt.1,
                tree_deposit_m,
                std::slice::from_ref(&deposit_rec_key_new),
            )?;
            member_history_proof =
                <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::default_lookup_proof(1)?;
            deposit_history_proof =
                <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::default_lookup_proof(1)?;
        } else {
            println!("executing regular logic...");
            let tx_info_old = aux_state.public_tx_info.as_ref().unwrap().clone();
            let acc_info_old = aux_state.public_acc_info.as_ref().unwrap().clone();
            let member_h_addr_old = aux_state.old_tree_member_history_addr;
            let deposit_h_addr_old = aux_state.old_tree_deposit_history_addr;

            z_old = Some(VerifiableDisclosureMsg::<VC> {
                tx_info: tx_info_old,
                acc_info: acc_info_old,
            });
            pcd_proof_old = Some(aux_state.proof.as_ref().unwrap().clone());

            member_decl_key_new = u64::default();
            deposit_rec_key_new = u64::default();
            deposit_uid_new = VC::F::default();
            member_read_proof =
                <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::default_lookup_proof(1)?;
            deposit_read_proof =
                <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::default_lookup_proof(1)?;
            member_history_proof = <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::lookup(
                &self.pp_mt.0,
                tree_member_m,
                std::slice::from_ref(&member_h_addr_old),
            )?;
            deposit_history_proof = <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::lookup(
                &self.pp_mt.1,
                tree_deposit_m,
                std::slice::from_ref(&deposit_h_addr_old),
            )?;
        }
        // Compute nullifier from aux_state.r
        let aux_state_r = aux_state.r.as_ref().unwrap();
        let mut r_writer = Cursor::new(Vec::<u8>::new());
        aux_state_r.write(&mut r_writer).unwrap();
        let in_null_new_h =
            <VC::H as CRHforMerkleTree>::hash_bytes(&self.pp_crh, &r_writer.into_inner()).unwrap();

        // Compute commitment from tfr.amt, tfr.pk, tfr.r
        let mut out_amt_writer = Cursor::new(Vec::<u8>::new());
        tfr.out_amt.write(&mut out_amt_writer).unwrap();
        let mut out_pk_writer = Cursor::new(Vec::<u8>::new());
        tfr.out_pk.write(&mut out_pk_writer).unwrap();
        let mut out_rand_writer = Cursor::new(Vec::<u8>::new());
        tfr.out_rand.write(&mut out_rand_writer).unwrap();
        let out_cm_new_h = <VC::H as CRHforMerkleTree>::hash_bytes(
            &self.pp_crh,
            &[
                out_amt_writer.into_inner(),
                out_pk_writer.into_inner(),
                out_rand_writer.into_inner(),
            ]
            .concat(),
        )
        .unwrap();

        // Compute transfer record from nullifier and commitment
        let mut null_writer = Cursor::new(Vec::<u8>::new());
        in_null_new_h.write(&mut null_writer).unwrap();
        let mut cm_writer = Cursor::new(Vec::<u8>::new());
        out_cm_new_h.write(&mut cm_writer).unwrap();
        let transfer_rec_new = <VC::H as CRHforMerkleTree>::hash_bytes(
            &self.pp_crh,
            &[null_writer.into_inner(), cm_writer.into_inner()].concat(),
        )
        .unwrap();

        // Update transfer merkle tree.
        // Compute lookup proof for newly-updated transfer merkle tree.
        // Add transfer record to shared state.
        let tfr_addr_vec = vec![t_old];
        let tfr_data_vec = vec![transfer_rec_new];
        let tree_transfer_m = aux_state.tree_transfer_m.as_mut().unwrap();
        let (rh_transfer_new_m, _) =
            <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::_modify_and_apply(
                &self.pp_mt.2,
                tree_transfer_m,
                &tfr_addr_vec,
                &tfr_data_vec,
                false,
            )?;
        let transfer_read_proof = <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::lookup(
            &self.pp_mt.2,
            tree_transfer_m,
            std::slice::from_ref(&t_old),
        )?;
        state.write_transfer(&t_old, &transfer_rec_new)?;

        // Check consistency of transfer tree
        if tfr.base_case {
            transfer_history_proof =
                <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::default_lookup_proof(1)?;
        } else {
            let transfer_h_addr_old = vec![aux_state.old_tree_transfer_history_addr];
            transfer_history_proof = <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::lookup(
                &self.pp_mt.2,
                tree_transfer_m,
                &transfer_h_addr_old,
            )?;
        }

        // Create new tx_info
        let public_tx_info_new = PublicTxInfo::<VC> {
            in_null: in_null_new_h,
            out_cm: out_cm_new_h,
        };
        let private_tx_info_new = PrivateTxInfo::<VC> {
            in_amt: *aux_state.amt.as_ref().unwrap(),
            in_pk: *aux_state.pk.as_ref().unwrap(),
            in_rand: *aux_state.r.as_ref().unwrap(),
            out_amt: tfr.out_amt,
            out_pk: tfr.out_pk,
            out_rand: tfr.out_rand,
        };
        // Create new acc_info
        let member_h_addr = vec![aux_state.old_tree_member_history_addr];
        let deposit_h_addr = vec![aux_state.old_tree_deposit_history_addr];
        let transfer_h_addr = vec![aux_state.old_tree_transfer_history_addr];
        let public_acc_info_new = PublicAccInfo::<VC> {
            member_rh: rh_member_new_m,
            deposit_rh: rh_deposit_new_m,
            transfer_rec: transfer_rec_new,
            transfer_rh: rh_transfer_new_m,
        };

        let mem_addr_vec = vec![member_decl_key_new];
        let dep_addr_vec = vec![deposit_rec_key_new];
        let private_acc_info_new = PrivateAccInfo::<VC> {
            member_decl: tfr.member_val,
            deposit_rec: tfr.deposit_val,
            deposit_uid: deposit_uid_new,
            member_addr: mem_addr_vec,
            member_proof: member_read_proof,
            member_history_addr: member_h_addr,
            member_history_proof: member_history_proof,
            deposit_addr: dep_addr_vec,
            deposit_proof: deposit_read_proof,
            deposit_history_addr: deposit_h_addr,
            deposit_history_proof: deposit_history_proof,
            transfer_addr: tfr_addr_vec,
            transfer_proof: transfer_read_proof,
            transfer_history_addr: transfer_h_addr,
            transfer_history_proof: transfer_history_proof,
        };
        // Create new message
        let z_new = VerifiableDisclosureMsg::<VC> {
            tx_info: public_tx_info_new.clone(),
            acc_info: public_acc_info_new.clone(),
        };
        // Create new witness
        let w = VerifiableDisclosureWitness::<VC> {
            tx_info: private_tx_info_new.clone(),
            acc_info: private_acc_info_new.clone(),
        };
        // Create new proof
        let pcd_proof_create_start = Instant::now();
        let pcd_proof_new = if z_old.is_some() {
            VC::I::prove::<Self, R>(
                &self.ipk.clone().unwrap(),
                self,
                &z_new,
                &w,
                &[z_old.unwrap()],
                &[pcd_proof_old.unwrap()],
                rng,
            )?
        } else {
            VC::I::prove::<Self, R>(&self.ipk.clone().unwrap(), self, &z_new, &w, &[], &[], rng)?
        };
        println!(
            "proving time (in ms): {}",
            pcd_proof_create_start.elapsed().as_millis()
        );
        // Update aux state
        aux_state.t = t_new;
        aux_state.amt = Some(tfr.out_amt);
        aux_state.pk = Some(tfr.out_pk);
        aux_state.r = Some(tfr.out_rand);
        aux_state.public_tx_info = Some(public_tx_info_new);
        aux_state.private_tx_info = Some(private_tx_info_new);
        aux_state.public_acc_info = Some(public_acc_info_new);
        aux_state.private_acc_info = Some(private_acc_info_new);
        aux_state.proof = Some(pcd_proof_new);

        Ok(())
    }

    /// vD.verify
    pub fn verify(
        &self,
        tx_info: &PublicTxInfo<VC>,
        acc_info: &PublicAccInfo<VC>,
        pcd_proof: &<VC::I as PCD<VC::F>>::Proof,
    ) -> Result<bool, Error> {
        let z = VerifiableDisclosureMsg {
            tx_info: tx_info.clone(),
            acc_info: acc_info.clone(),
        };
        let pcd_proof_verify_start = Instant::now();
        let result = VC::I::verify::<Self>(&self.ivk.clone().unwrap(), &z, pcd_proof);
        println!(
            "verification time (in ms): {}",
            pcd_proof_verify_start.elapsed().as_millis()
        );
        result
    }
}

impl<VC: VerifiableDisclosureConfig> PCDPredicate<VC::F> for VerifiableDisclosure<VC> {
    type Message = VerifiableDisclosureMsg<VC>;
    type MessageVar = VerifiableDisclosureMsgVar<VC>;
    type LocalWitness = VerifiableDisclosureWitness<VC>;
    type LocalWitnessVar = VerifiableDisclosureWitnessVar<VC>;

    const PRIOR_MSG_LEN: usize = 1;

    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<VC::F>,
        msg: &Self::MessageVar,
        witness: &Self::LocalWitnessVar,
        prior_msgs: &[Self::MessageVar],
        base_bit: &Boolean<VC::F>,
    ) -> Result<(), SynthesisError> {
        let base_constraints = cs.num_constraints();
        let mut pred_constraints = 0;

        let allowlist_id_g = FpVar::<VC::F>::new_constant(
            ark_relations::ns!(cs, "allowlist_id"),
            self.allowlist_id,
        )?;

        // 1a. Check the membership decl computation in base case
        let mut decl_input_bytes_g = allowlist_id_g.to_bytes()?;
        let decl_input_pk_bytes_g = witness.tx_info_g.in_pk_g.to_bytes()?;
        decl_input_bytes_g.extend(decl_input_pk_bytes_g);

        let decl_hash_g = VC::HG::hash_bytes(&self.pp_crh, &decl_input_bytes_g).unwrap();
        decl_hash_g.conditional_enforce_equal(&witness.acc_info_g.member_decl_g, base_bit)?;
        let constraints_from_step1a = cs.num_constraints() - pred_constraints - base_constraints;
        println!("constraints from membership declaration computation: {constraints_from_step1a}");
        pred_constraints += constraints_from_step1a;

        // 1b. Check the membership decl lookup proof in base case
        let pp_member_mt_state_g = self.pp_mt.0.clone();
        let member_decl_g_vec = vec![witness.acc_info_g.member_decl_g.clone()];
        <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::conditionally_verify_lookup_gadget(
            ark_relations::ns!(cs, "member_read_proof").cs(),
            &pp_member_mt_state_g,
            &msg.acc_info_g.member_rh_g,
            &witness.acc_info_g.member_addr_g,
            &member_decl_g_vec,
            &witness.acc_info_g.member_proof_g,
            base_bit,
        )?;
        let constraints_from_step1b = cs.num_constraints() - pred_constraints - base_constraints;
        pred_constraints += constraints_from_step1b;
        println!("constraints from membership declaration lookup proof: {constraints_from_step1b}");

        // 1c. Check the membership decl history proof in non-base case
        let member_rh_old_g_vec = vec![prior_msgs[0].acc_info_g.member_rh_g.clone()];
        <VC::MTMember as MT<VC::F, u64, UInt64<VC::F>>>::conditionally_verify_lookup_gadget(
            ark_relations::ns!(cs, "member_history_proof").cs(),
            &pp_member_mt_state_g,
            &msg.acc_info_g.member_rh_g,
            &witness.acc_info_g.member_history_addr_g,
            &member_rh_old_g_vec,
            &witness.acc_info_g.member_history_proof_g,
            &base_bit.not(),
        )?;
        let constraints_from_step1c = cs.num_constraints() - pred_constraints - base_constraints;
        pred_constraints += constraints_from_step1c;
        println!(
            "constraints from membership declaration history proof: {constraints_from_step1c}"
        );

        // 2a. Check the deposit record computation in base case
        let mut deposit_rec_input_bytes_g = witness.tx_info_g.in_amt_g.to_bytes()?;

        let in_pk_bytes_g = witness.tx_info_g.in_pk_g.to_bytes()?;
        deposit_rec_input_bytes_g.extend(in_pk_bytes_g);

        let mut cm_in_bytes_g = witness.tx_info_g.in_amt_g.to_bytes()?;
        let cm_in_pk_bytes_g = witness.tx_info_g.in_pk_g.to_bytes()?;
        cm_in_bytes_g.extend(cm_in_pk_bytes_g);
        let cm_in_rand_bytes_g = witness.tx_info_g.in_rand_g.to_bytes()?;
        cm_in_bytes_g.extend(cm_in_rand_bytes_g);
        let cm_in_hash_g = VC::HG::hash_bytes(&self.pp_crh, &cm_in_bytes_g).unwrap();
        let cm_in_hash_bytes_g = cm_in_hash_g.to_bytes()?;
        deposit_rec_input_bytes_g.extend(cm_in_hash_bytes_g);

        let deposit_uid_bytes_g = witness.acc_info_g.deposit_uid_g.to_bytes()?;
        deposit_rec_input_bytes_g.extend(deposit_uid_bytes_g);

        let member_rh_bytes_g = msg.acc_info_g.member_rh_g.to_bytes()?;
        deposit_rec_input_bytes_g.extend(member_rh_bytes_g);

        let deposit_rec_hash_g =
            VC::HG::hash_bytes(&self.pp_crh, &deposit_rec_input_bytes_g).unwrap();
        deposit_rec_hash_g.conditional_enforce_equal(&witness.acc_info_g.deposit_rec_g, base_bit)?;
        let constraints_from_step2a = cs.num_constraints() - pred_constraints - base_constraints;
        pred_constraints += constraints_from_step2a;
        println!("constraints from deposit record computation: {constraints_from_step2a}");

        // 2b. Check the deposit record lookup proof in base case
        let pp_deposit_mt_state_g = self.pp_mt.1.clone();
        let deposit_rec_g_vec = vec![witness.acc_info_g.deposit_rec_g.clone()];
        <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::conditionally_verify_lookup_gadget(
            ark_relations::ns!(cs, "deposit_read_proof").cs(),
            &pp_deposit_mt_state_g,
            &msg.acc_info_g.deposit_rh_g,
            &witness.acc_info_g.deposit_addr_g,
            &deposit_rec_g_vec,
            &witness.acc_info_g.deposit_proof_g,
            base_bit,
        )?;
        let constraints_from_step2b = cs.num_constraints() - pred_constraints - base_constraints;
        pred_constraints += constraints_from_step2b;
        println!("constraints from deposit record lookup proof: {constraints_from_step2b}");

        // 2c. Check the deposit record history proof in non-base case
        let deposit_rh_old_g_vec = vec![prior_msgs[0].acc_info_g.deposit_rh_g.clone()];
        <VC::MTDeposit as MT<VC::F, u64, UInt64<VC::F>>>::conditionally_verify_lookup_gadget(
            ark_relations::ns!(cs, "deposit_history_proof").cs(),
            &pp_deposit_mt_state_g,
            &msg.acc_info_g.deposit_rh_g,
            &witness.acc_info_g.deposit_history_addr_g,
            &deposit_rh_old_g_vec,
            &witness.acc_info_g.deposit_history_proof_g,
            &base_bit.not(),
        )?;
        let constraints_from_step2c = cs.num_constraints() - pred_constraints - base_constraints;
        pred_constraints += constraints_from_step2c;
        println!("constraints from deposit record history proof: {constraints_from_step2c}");

        // 3. Check the input nullifier computation
        let in_null_rand_bytes_g = witness.tx_info_g.in_rand_g.to_bytes()?;
        let in_null_hash_g = VC::HG::hash_bytes(&self.pp_crh, &in_null_rand_bytes_g).unwrap();
        in_null_hash_g.enforce_equal(&msg.tx_info_g.in_null_g)?;
        let constraints_from_step3 = cs.num_constraints() - pred_constraints - base_constraints;
        pred_constraints += constraints_from_step3;
        println!("constraints from input nullifier computation: {constraints_from_step3}");

        // 4. Check the output commitment computation
        let mut out_cm_bytes_g = witness.tx_info_g.out_amt_g.to_bytes()?;
        let out_cm_pk_bytes_g = witness.tx_info_g.out_pk_g.to_bytes()?;
        out_cm_bytes_g.extend(out_cm_pk_bytes_g);
        let out_cm_rand_bytes_g = witness.tx_info_g.out_rand_g.to_bytes()?;
        out_cm_bytes_g.extend(out_cm_rand_bytes_g);
        let out_cm_hash_g = VC::HG::hash_bytes(&self.pp_crh, &out_cm_bytes_g).unwrap();
        out_cm_hash_g.enforce_equal(&msg.tx_info_g.out_cm_g)?;
        let constraints_from_step4 = cs.num_constraints() - pred_constraints - base_constraints;
        pred_constraints += constraints_from_step4;
        println!("constraints from output commitment computation: {constraints_from_step4}");

        // 5. Check the consistency of commitments in non-base case
        prior_msgs[0]
            .tx_info_g
            .out_cm_g
            .conditional_enforce_equal(&cm_in_hash_g, &base_bit.not())?;
        let constraints_from_step5 = cs.num_constraints() - pred_constraints - base_constraints;
        pred_constraints += constraints_from_step5;
        println!("constraints from commitment consistency check: {constraints_from_step5}");

        // 6. Check the transfer record computation
        let mut transfer_rec_bytes_g = msg.tx_info_g.in_null_g.to_bytes()?;
        transfer_rec_bytes_g.extend(msg.tx_info_g.out_cm_g.to_bytes()?);
        let transfer_rec_hash_g = VC::HG::hash_bytes(&self.pp_crh, &transfer_rec_bytes_g).unwrap();
        transfer_rec_hash_g.enforce_equal(&msg.acc_info_g.transfer_rec_g)?;
        let constraints_from_step6 = cs.num_constraints() - pred_constraints - base_constraints;
        pred_constraints += constraints_from_step6;
        println!("constraints from transfer record computation: {constraints_from_step6}");

        // 7. Check the transfer record lookup proof
        let pp_transfer_mt_state_g = self.pp_mt.2.clone();
        let transfer_rec_g_vec = vec![msg.acc_info_g.transfer_rec_g.clone()];
        <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::verify_lookup_gadget(
            ark_relations::ns!(cs, "transfer_read_proof").cs(),
            &pp_transfer_mt_state_g,
            &msg.acc_info_g.transfer_rh_g,
            &witness.acc_info_g.transfer_addr_g,
            &transfer_rec_g_vec,
            &witness.acc_info_g.transfer_proof_g,
        )?;
        let constraints_from_step7 = cs.num_constraints() - pred_constraints - base_constraints;
        pred_constraints += constraints_from_step7;
        println!("constraints from transfer record lookup proof: {constraints_from_step7}");

        // 8. Check the transfer record history proof in non-base case
        let transfer_rh_old_g_vec = vec![prior_msgs[0].acc_info_g.transfer_rh_g.clone()];
        <VC::MTTransfer as MT<VC::F, u64, UInt64<VC::F>>>::conditionally_verify_lookup_gadget(
            ark_relations::ns!(cs, "transfer_history_proof").cs(),
            &pp_transfer_mt_state_g,
            &msg.acc_info_g.transfer_rh_g,
            &witness.acc_info_g.transfer_history_addr_g,
            &transfer_rh_old_g_vec,
            &witness.acc_info_g.transfer_history_proof_g,
            &base_bit.not(),
        )?;

        let constraints_from_step8 = cs.num_constraints() - pred_constraints - base_constraints;
        pred_constraints += constraints_from_step8;
        println!("constraints from transfer record history proof: {constraints_from_step8}");

        let remaining_constraints = cs.num_constraints() - pred_constraints - base_constraints;
        assert!(remaining_constraints == 0);
        println!("constraints from predicate (total): {pred_constraints}");
        Ok(())
    }
}
