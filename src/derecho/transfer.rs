use crate::{
    building_blocks::crh::CRHforMerkleTree, derecho::disclosure::VerifiableDisclosureConfig,
};

/// a transfer in this example system
#[derive(Derivative)]
#[derivative(Clone(bound = "VC: VerifiableDisclosureConfig"))]
pub struct ExampleTransfer<VC: VerifiableDisclosureConfig> {
    /// output public key
    pub out_pk: VC::F,
    /// output amount
    pub out_amt: VC::F,
    /// output commitment randomness
    pub out_rand: VC::F,
    /// member decl key
    pub member_key: u64,
    /// member decl value
    pub member_val: <VC::H as CRHforMerkleTree>::Output,
    /// deposit rec key
    pub deposit_key: u64,
    /// deposit rec value
    pub deposit_val: <VC::H as CRHforMerkleTree>::Output,
    /// deposit uid
    pub deposit_uid: VC::F,
    /// base case indicator
    pub base_case: bool,
}
