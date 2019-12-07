// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//!
//! This module has the types used to perform key exchange between two parties. These two parties
//! are denoted Alice and Bob in [liboqs] so this library will use the same terminology. Out of
//! these two parties, Alice is the one initiating a key exchange operation.
//!
//! See the [`OqsKem`] struct for details on key exchange.
//!
//! [liboqs]: https://github.com/open-quantum-safe/liboqs
//! [`OqsKem`]: struct.OqsKem.html

use core::ptr::NonNull;
use std::fmt;

use oqs_sys::kex as ffi;
use oqs_sys::common::OQS_STATUS::OQS_SUCCESS;


/// Enum representation of the supported key exchange algorithms. Used to select backing algorithm
/// when creating [`OqsKem`](struct.OqsKem.html) instances.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[allow(missing_docs)]
pub enum OqsKemAlg {
    Default,
    Bike1L1Cpa,
    Bike1L3Cpa,
    Bike1L1Fo,
    Bike1L3Fo,
    Kyber512,
    Kyber768,
    Kyber1024,
    Kyber51290s,
    Kyber76890s,
    Kyber102490s,
    Newhope512cca,
    Newhope1024cca,
    NtruHps2048509,
    NtruHps2048677,
    NtruHps4096821,
    NtruHrss701,
    SaberLightsaber,
    SaberSaber,
    SaberFiresaber,
    Frodokem640Aes,
    Frodokem640Shake,
    Frodokem976Aes,
    Frodokem976Shake,
    Frodokem1344Aes,
    Frodokem1344Shake,
    SidhP434,
    SidhP434Compressed,
    SidhP503,
    SidhP503Compressed,
    SidhP610,
    SidhP610Compressed,
    SidhP751,
    SidhP751Compressed,
    SikeP434,
    SikeP434Compressed,
    SikeP503,
    SikeP503Compressed,
    SikeP610,
    SikeP610Compressed,
    SikeP751,
    SikeP751Compressed,
}

impl OqsKemAlg {
    pub fn alg_name(&self) -> &'static [u8] {
        use self::OqsKemAlg::*;
        match self {
            Default => ffi::OQS_KEM_alg_default,
            Bike1L1Cpa => ffi::OQS_KEM_alg_bike1_l1_cpa,
            Bike1L3Cpa => ffi::OQS_KEM_alg_bike1_l3_cpa,
            Bike1L1Fo => ffi::OQS_KEM_alg_bike1_l1_fo,
            Bike1L3Fo => ffi::OQS_KEM_alg_bike1_l3_fo,
            Kyber512 => ffi::OQS_KEM_alg_kyber_512,
            Kyber768 => ffi::OQS_KEM_alg_kyber_768,
            Kyber1024 => ffi::OQS_KEM_alg_kyber_1024,
            Kyber51290s => ffi::OQS_KEM_alg_kyber_512_90s,
            Kyber76890s => ffi::OQS_KEM_alg_kyber_768_90s,
            Kyber102490s => ffi::OQS_KEM_alg_kyber_1024_90s,
            Newhope512cca => ffi::OQS_KEM_alg_newhope_512cca,
            Newhope1024cca => ffi::OQS_KEM_alg_newhope_1024cca,
            NtruHps2048509 => ffi::OQS_KEM_alg_ntru_hps2048509,
            NtruHps2048677 => ffi::OQS_KEM_alg_ntru_hps2048677,
            NtruHps4096821 => ffi::OQS_KEM_alg_ntru_hps4096821,
            NtruHrss701 => ffi::OQS_KEM_alg_ntru_hrss701,
            SaberLightsaber => ffi::OQS_KEM_alg_saber_lightsaber,
            SaberSaber => ffi::OQS_KEM_alg_saber_saber,
            SaberFiresaber => ffi::OQS_KEM_alg_saber_firesaber,
            Frodokem640Aes => ffi::OQS_KEM_alg_frodokem_640_aes,
            Frodokem640Shake => ffi::OQS_KEM_alg_frodokem_640_shake,
            Frodokem976Aes => ffi::OQS_KEM_alg_frodokem_976_aes,
            Frodokem976Shake => ffi::OQS_KEM_alg_frodokem_976_shake,
            Frodokem1344Aes => ffi::OQS_KEM_alg_frodokem_1344_aes,
            Frodokem1344Shake => ffi::OQS_KEM_alg_frodokem_1344_shake,
            SidhP434 => ffi::OQS_KEM_alg_sidh_p434,
            SidhP434Compressed => ffi::OQS_KEM_alg_sidh_p434_compressed,
            SidhP503 => ffi::OQS_KEM_alg_sidh_p503,
            SidhP503Compressed => ffi::OQS_KEM_alg_sidh_p503_compressed,
            SidhP610 => ffi::OQS_KEM_alg_sidh_p610,
            SidhP610Compressed => ffi::OQS_KEM_alg_sidh_p610_compressed,
            SidhP751 => ffi::OQS_KEM_alg_sidh_p751,
            SidhP751Compressed => ffi::OQS_KEM_alg_sidh_p751_compressed,
            SikeP434 => ffi::OQS_KEM_alg_sike_p434,
            SikeP434Compressed => ffi::OQS_KEM_alg_sike_p434_compressed,
            SikeP503 => ffi::OQS_KEM_alg_sike_p503,
            SikeP503Compressed => ffi::OQS_KEM_alg_sike_p503_compressed,
            SikeP610 => ffi::OQS_KEM_alg_sike_p610,
            SikeP610Compressed => ffi::OQS_KEM_alg_sike_p610_compressed,
            SikeP751 => ffi::OQS_KEM_alg_sike_p751,
            SikeP751Compressed => ffi::OQS_KEM_alg_sike_p751_compressed,
        }
    }
}

/// The main key exchange struct. Used by both Alice and Bob to generate their respective public
/// messages and the final [shared secret key].
///
/// # Usage
///
/// A full key exchange involves the following steps:
///
/// 1. Alice calls [`alice_0`]. This will create her [public message].
/// 2. Alice sends her public message to Bob.
/// 3. Bob calls [`bob`] with Alice's public message. This will create his public message, and
///    the final shared key.
/// 4. Bob sends his public message to Alice.
/// 5. Alice calls [`alice_1`] with Bob's public message. This will create the same shared key as
///    Bob got from [`bob`].
///
/// [`alice_0`]: #method.alice_0
/// [`bob`]: #method.bob
/// [`alice_1`]: struct.OqsKemAlice.html#method.alice_1
/// [public message]: struct.OqsKemAlice.html#method.get_alice_msg
pub struct OqsKem {
    algorithm: OqsKemAlg,
    oqs_kex: NonNull<ffi::OQS_KEM>,
}

impl OqsKem {
    /// Initializes and returns a new OQS key exchange instance.
    pub fn new(algorithm: OqsKemAlg) -> Result<Self> {
        let oqs_kex = unsafe {
            ffi::OQS_KEM_new(
                algorithm.alg_name().as_ptr() as *const ::libc::c_char
            )
        };
        match NonNull::new(oqs_kex) {
            Some(oqs_kex) => Ok(OqsKem{ algorithm, oqs_kex }),
            None => Err(Error),
        }
    }

    #[inline]
    pub fn public_key_length(&self) -> usize {
        unsafe { self.oqs_kex.as_ref() }.length_public_key
    }

    #[inline]
    pub fn private_key_length(&self) -> usize {
        unsafe { self.oqs_kex.as_ref() }.length_secret_key
    }

    #[inline]
    pub fn cipher_text_length(&self) -> usize {
        unsafe { self.oqs_kex.as_ref() }.length_ciphertext
    }

    #[inline]
    pub fn shared_secret_length(&self) -> usize {
        unsafe { self.oqs_kex.as_ref() }.length_shared_secret
    }

    /// Returns the key exchange algorithm used by this instance.
    pub fn algorithm(&self) -> OqsKemAlg {
        self.algorithm
    }

    pub fn generate_keypair<'a>(&'a self, public_key: &mut [u8], private_key: &mut [u8]) -> Result<()> {
        if public_key.len() < self.public_key_length() {
            // Public key length violation
            return Err(Error)
        }
        if private_key.len() < self.private_key_length() {
            // Private key length violation
            return Err(Error)
        }
        let result = unsafe {
            ffi::OQS_KEM_keypair(
                self.oqs_kex.as_ptr(),
                public_key.as_mut_ptr(),
                private_key.as_mut_ptr(),
            )
        };
        if result == OQS_SUCCESS { Ok(()) } else { Err(Error) }
    }

    pub fn encapsulate(&self, public_key: &[u8], shared_secret: &mut [u8], ciphertext: &mut [u8]) -> Result<()> {
        if public_key.len() < self.public_key_length() {
            // Public key length violation
            return Err(Error)
        }
        if ciphertext.len() < self.cipher_text_length() {
            // Ciphertext length violation
            return Err(Error)
        }
        let result = unsafe {
            ffi::OQS_KEM_encaps(
                self.oqs_kex.as_ptr(),
                ciphertext.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
                public_key.as_ptr(),
            )
        };
        if result == OQS_SUCCESS { Ok(()) } else { Err(Error) }
    }

    pub fn decapsulate(&self, private_key: &[u8], ciphertext: &[u8], shared_secret: &mut [u8]) -> Result<()> {
        if ciphertext.len() < self.cipher_text_length() {
            // Ciphertext length violation
            return Err(Error)
        }
        if shared_secret.len() < self.shared_secret_length() {
            // Shared secret length violation
            return Err(Error)
        }
        let result = unsafe {
            ffi::OQS_KEM_decaps(
                self.oqs_kex.as_ptr(),
                shared_secret.as_mut_ptr(),
                ciphertext.as_ptr() as *const ::libc::c_uchar,
                private_key.as_ptr(),
            )
        };
        if result == OQS_SUCCESS { Ok(()) } else { Err(Error) }
    }
}

impl Drop for OqsKem {
    fn drop(&mut self) {
        unsafe { ffi::OQS_KEM_free(self.oqs_kex.as_ptr()) };
    }
}

/// The local result alias for fallible operations in this module.
pub type Result<T> = ::std::result::Result<T, Error>;

/// Error representing a failure in any [`OqsKem`](struct.OqsRand.html) operation.
#[derive(Debug, Copy, Clone, Hash)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        use std::error::Error;
        self.description().fmt(f)
    }
}

impl ::std::error::Error for Error {
    fn description(&self) -> &str {
        "Key exchange operation failed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::OqsKemAlg::*;

    macro_rules! test_factory {
        ($test_name: ident over $kem_alg: expr) => {
            #[test]
            fn $test_name() {
                test_algorithm($kem_alg)
            }
        };
        ($a: ident over $b: expr, $($rest: tt)*) => {
            test_factory!($a over $b);
            test_factory!($($rest)*);
        };
        () => {}
    }

    test_factory! {
        alg_default              over Default,
        alg_bike1_l1_cpa         over Bike1L1Cpa,
        alg_bike1_l3_cpa         over Bike1L3Cpa,
        alg_bike1_l1_fo          over Bike1L1Fo,
        alg_bike1_l3_fo          over Bike1L3Fo,
        alg_kyber_512            over Kyber512,
        alg_kyber_768            over Kyber768,
        alg_kyber_1024           over Kyber1024,
        alg_kyber_512_90s        over Kyber51290s,
        alg_kyber_768_90s        over Kyber76890s,
        alg_kyber_1024_90s       over Kyber102490s,
        alg_newhope_512cca       over Newhope512cca,
        alg_newhope_1024cca      over Newhope1024cca,
        alg_ntru_hps2048509      over NtruHps2048509,
        alg_ntru_hps2048677      over NtruHps2048677,
        alg_ntru_hps4096821      over NtruHps4096821,
        alg_ntru_hrss701         over NtruHrss701,
        alg_saber_lightsaber     over SaberLightsaber,
        alg_saber_saber          over SaberSaber,
        alg_saber_firesaber      over SaberFiresaber,
        alg_frodokem_640_aes     over Frodokem640Aes,
        alg_frodokem_640_shake   over Frodokem640Shake,
        alg_frodokem_976_aes     over Frodokem976Aes,
        alg_frodokem_976_shake   over Frodokem976Shake,
        alg_frodokem_1344_aes    over Frodokem1344Aes,
        alg_frodokem_1344_shake  over Frodokem1344Shake,
        alg_sidh_p434            over SidhP434,
        alg_sidh_p434_compressed over SidhP434Compressed,
        alg_sidh_p503            over SidhP503,
        alg_sidh_p503_compressed over SidhP503Compressed,
        alg_sidh_p610            over SidhP610,
        alg_sidh_p610_compressed over SidhP610Compressed,
        alg_sidh_p751            over SidhP751,
        alg_sidh_p751_compressed over SidhP751Compressed,
        alg_sike_p434            over SikeP434,
        alg_sike_p434_compressed over SikeP434Compressed,
        alg_sike_p503            over SikeP503,
        alg_sike_p503_compressed over SikeP503Compressed,
        alg_sike_p610            over SikeP610,
        alg_sike_p610_compressed over SikeP610Compressed,
        alg_sike_p751            over SikeP751,
        alg_sike_p751_compressed over SikeP751Compressed,
    }

    fn test_algorithm(alg: OqsKemAlg) {
        let kem = OqsKem::new(alg).unwrap();

        // Alice
        let mut alice_private_key = vec![0u8; kem.private_key_length()];
        let mut alice_public_key = vec![0u8; kem.public_key_length()];
        kem.generate_keypair(&mut alice_public_key, &mut alice_private_key).unwrap();

        // Alice -> Bob
        let bob_received_public_key = alice_public_key;

        // Bob
        let mut bob_ciphertext = vec![0u8; kem.cipher_text_length()];
        let mut bob_shared_secret = vec![0u8; kem.shared_secret_length()];
        kem.encapsulate(&bob_received_public_key, &mut bob_shared_secret, &mut bob_ciphertext).unwrap();

        // Bob -> Alice
        let alice_received_ciphertext = bob_ciphertext;

        // Alice
        let mut alice_shared_secret = vec![0u8; kem.shared_secret_length()];
        kem.decapsulate(&alice_private_key, &alice_received_ciphertext, &mut alice_shared_secret).unwrap();

        // Finally
        assert_eq!(alice_shared_secret, bob_shared_secret, "Shared secret must be the same")
    }
}
