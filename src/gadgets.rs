pub use ark_ff::ToConstraintField;
pub use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::{
        boolean::{AllocatedBit, Boolean},
        uint64::UInt64,
        uint8::UInt8,
        ToBitsGadget, ToBytesGadget,
    },
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
    Assignment,
};
use ark_relations::r1cs::Namespace;
use ark_std::vec::Vec;

use crate::{Borrow, Field, PhantomData, SynthesisError};

/// An EmptyVar used to write test examples
#[derive(Debug)]
pub struct EmptyVar<F: Field> {
    f_phantom: PhantomData<F>,
}

impl<F: Field> Clone for EmptyVar<F> {
    fn clone(&self) -> Self {
        EmptyVar {
            f_phantom: PhantomData,
        }
    }
}

impl<F: Field> Default for EmptyVar<F> {
    fn default() -> Self {
        EmptyVar {
            f_phantom: PhantomData,
        }
    }
}

impl<F: Field> CondSelectGadget<F> for EmptyVar<F> {
    fn conditionally_select(
        _cond: &Boolean<F>,
        _true_value: &Self,
        _false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        Ok(EmptyVar {
            f_phantom: PhantomData,
        })
    }
}

impl<F: Field> PartialEq for EmptyVar<F> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<F: Field> Eq for EmptyVar<F> {}

impl<F: Field> EqGadget<F> for EmptyVar<F> {
    fn is_eq(&self, _other: &Self) -> Result<Boolean<F>, SynthesisError> {
        Ok(Boolean::Constant(true))
    }
}

impl<F: Field> ToBytesGadget<F> for EmptyVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok(Vec::new())
    }
}

impl<F: Field> AllocVar<(), F> for EmptyVar<F> {
    fn new_variable<T: Borrow<()>>(
        _cs: impl Into<Namespace<F>>,
        _f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            f_phantom: PhantomData,
        })
    }
}
