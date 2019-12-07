// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use oqs_sys::common::OQS_STATUS;
use oqs_sys::rand as ffi;

/// Enum representation of the supported PRNG algorithms. Used to select backing algorithm when
/// creating [`OqsRand`](struct.OqsRand.html) instances.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OqsRandAlg {
    /// Reads bytes directly from `/dev/urandom`.
    System,
    /// OpenSSL's PRNG.
    OpenSsl,
    /// NIST deterministic RNG for KATs
    NistKat,
}

impl OqsRandAlg {
    pub fn alg_name(&self) -> &'static [u8] {
        match self {
            OqsRandAlg::System => ffi::OQS_RAND_alg_system,
            OqsRandAlg::NistKat => ffi::OQS_RAND_alg_nist_kat,
            OqsRandAlg::OpenSsl => ffi::OQS_RAND_alg_openssl,
        }
    }
}


impl Default for OqsRandAlg {
    fn default() -> Self {
        OqsRandAlg::System
    }
}

pub fn switch_algorithm(alg: OqsRandAlg) -> Result<(), ()> {
    let alg_name = alg.alg_name();
    let status = unsafe {
        ffi::OQS_randombytes_switch_algorithm(alg_name.as_ptr() as *const ::libc::c_char)
    };
    if status == OQS_STATUS::OQS_SUCCESS { Ok(()) } else { Err(()) }
}
