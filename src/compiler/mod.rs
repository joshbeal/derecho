use crate::derecho::disclosure::{VerifiableDisclosure, VerifiableDisclosureConfig};
use crate::derecho::state::VerifiableState;

/// compiler for circuit-specific setup
pub mod circuit_specific_setup_compiler;

/// Derecho
pub struct Derecho<VC: VerifiableDisclosureConfig> {
    /// verifiable disclosure
    pub vd: VerifiableDisclosure<VC>,
    /// verifiable state
    pub vs: VerifiableState<VC>,
}
