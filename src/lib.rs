//! A crate for proof-carrying disclosures
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unused_import_braces, unused_qualifications, trivial_casts)]
#![deny(trivial_numeric_casts, private_in_public, variant_size_differences)]
#![deny(stable_features, unreachable_pub, non_shorthand_field_patterns)]
#![deny(unused_attributes, unused_mut)]
#![deny(missing_docs)]
#![deny(unused_imports)]
#![deny(renamed_and_removed_lints, stable_features, unused_allocation)]
#![deny(unused_comparisons, bare_trait_objects, unused_must_use)]
#![forbid(unsafe_code)]
#![allow(clippy::op_ref, clippy::type_complexity, clippy::too_many_arguments)]

/// building blocks (here mt)
pub mod building_blocks;
/// compilers
pub mod compiler;
/// the derecho constructions
pub mod derecho;
/// copied from marlin
pub mod fiat_shamir;

#[macro_use]
extern crate derivative;

pub(crate) use ark_ff::{Field, PrimeField, ToBytes};
pub(crate) use ark_relations::r1cs::SynthesisError;
pub(crate) use ark_std::rand::RngCore;
pub(crate) use ark_std::{
    borrow::Borrow,
    marker::{PhantomData, Sized},
};
pub(crate) use ark_std::{boxed::Box, vec::Vec};

/// wrapped error types
pub type Error = Box<dyn ark_std::error::Error>;

/// prelude for common gadgets
pub mod gadgets;
