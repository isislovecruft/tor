// Copyright (c) 2017-2018, The Tor Project, Inc.
// Copyright (c) 2017-2018, isis agora lovecruft
// See LICENSE for licensing information

//! Interface for calling (ed25519-dalek)[https://github.com/isislovecruft/ed25519-dalek]
//! from Tor's C code.
//!
//! We define the functions in here which are in the `impl_dalek` struct of
//! function pointers in .../tor/src/common/crypto_ed25519.c.  The headers for
//! inclusion of these function from C are stored in
//! .../tor/src/ext/ed25519/dalek/ed25519_dalek_tor.h.

use std::slice;

use ed25519_dalek::ExpandedSecretKey;
use ed25519_dalek::Keypair;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use ed25519_dalek::Signature;

use libc::{c_uchar, c_int, size_t};

use rand::Rng;

use crypto::digests::sha2::Sha512;
use crypto::rand::rng::TorRng;

#[cfg(not(feature = "std"))]
pub extern fn fix_linking_when_using_no_std() { panic!() }

/// Return `1` if the raw pointer (a `*mut T` or `*const T`) is NULL.  In Rust,
/// references are never allowed to be NULL.
macro_rules! fail_if_null {
    ($ ($p:expr), *) => {{
        $(
            if $p.is_null() {
                return 1;
            }
        )*
    }}
}

/// Convert from a raw pointer and a length to a slice.
///
/// # Inputs
///
/// * `$p`: A `*mut T` or `*const T`;
/// * `$len: A `libc::size_t`.
///
/// # Returns
///
/// A slice of bytes, i.e. `[u8; $len]`.
macro_rules! ptr_to_slice {
    ( $p:expr, $len:expr ) => {{
        // Rust references may never be NULL.
        fail_if_null!($p);
        // Convert from pointer and length to a slice. This is unsafe,
        // as we may be dereferencing invalid memory.
        slice::from_raw_parts($p, $len as usize)
    }}
}

macro_rules! keypair_from_bytes {
    ( $secret_key:expr, $public_key:expr ) => {{
        let secret_bytes = ptr_to_slice!($secret_key, 32);
        let public_bytes = ptr_to_slice!($public_key, 32);

        let sk: SecretKey = SecretKey::from_bytes(&secret_bytes);
        let pk: PublicKey = PublicKey::from_bytes(&public_bytes);

        Keypair{ secret: sk , public: pk }
    }}
}

/// Perform a self-test to ensure our copy of ed25519-dalek is likely
/// functioning correctly.
#[no_mangle]
pub extern fn ed25519_dalek_selftest() -> c_int {
    let mut csprng: TorRng = TorRng::new();
    let keypair: Keypair = Keypair::generate::<Sha512, TorRng>(&mut csprng);
    let message: &[u8] = "This is a test of the tsunami alert system. This is just a test.".as_bytes();
    let signature1: Signature = keypair.sign(&message);
    // Also perform signatures and verification with the pre-expanded key, as
    // tor does in normal operation with other libraries.
    let expanded: ExpandedSecretKey = ExpandedSecretKey::from_secret_key::<Sha512>(&keypair.secret);
    let signature2: Signature = expanded.sign(&message, &keypair.public);

    for sig in [signature1, signature2].iter() {
        let verified: bool = keypair.public.verify(&message, &sig);

        if ! verified {
            return 1;
        }
    }
    0
}

/// "Expand" the `secret_key` by hashing it.
///
/// # Note
///
/// We derive the public key from the secret key by hashing a seed, then
/// reducing the hash digest to a scalar and multiplying it by the ed25519
/// basepoint. (This behaviour is identical to ref10.)
///
/// The donna code instead hashes a seed and treats the lower 32 bytes as the
/// secret key and the upper 32 bytes as a scalar, which it then multiplies by
/// the basepoint to produce the public key.
#[no_mangle]
pub extern fn ed25519_dalek_seckey(secret_key: *mut c_uchar) -> c_int {
    let mut csprng: TorRng = TorRng::new();
    let secret: SecretKey = SecretKey::generate(&mut csprng);
    let expand: ExpandedSecretKey = ExpandedSecretKey::from_secret_key::<Sha512>(&secret);

    *secret_key = expand.to_bytes().as_mut_ptr();

    0
}

/// "Expand" the `secret_key` by taking the "secret key"¹ and turning it into
/// the "actual secret key" and static "nonce" by hashing the 256-bit
/// `secret_key` with a 512-bit output size digest function and then doing other
/// mostly pointless things with the two halves that would protect against
/// non-existent theoretically bad implementations.
///
/// ¹ Air quotations mine because this "design" is frickin stupid and
///   pointless. —isis
///
/// # Warning
///
/// Writes 64 octets to the `secret_key` pointer.  It's a pointer.  It's going
/// to write 64 bytes.  Make sure you have allocated at least 64 bytes.
#[no_mangle]
pub extern fn ed25519_dalek_seckey_expand(secret_key: *mut c_uchar,
                                          seed: *const c_uchar) -> c_int {
    fail_if_null!(seed);

    let secret: SecretKey;
    let expand: ExpandedSecretKey;

    secret = match SecretKey::from_bytes(seed) {
        Ok(key) => key,
        Err(_)  => return 1,
    };
    expand = ExpandedSecretKey::from_secret_key::<Sha512>(&secret);

    *secret_key = expand.to_bytes().as_mut_ptr();

    0
}

/// DOCDOC
#[no_mangle]
pub extern fn ed25519_dalek_pubkey(public_key: *mut *mut c_uchar,
                                   secret_key: *const *const c_uchar) -> c_int {
    fail_if_null!(secret_key);

    let secret: SecretKey = SecretKey::from_bytes(secret_key);
    let public: PublicKey = PublicKey::from_secret::<Sha512>(&secret);

    *public_key = public.to_bytes().as_mut_ptr();

    0
}

/// DOCDOC
#[no_mangle]
pub extern fn ed25519_dalek_keygen(public_key: *mut *mut c_uchar,
                                   secret_key: *mut *mut c_uchar) -> c_int {
    let mut ok: isize = 0;

    ok  = ed25519_dalek_seckey(secret_key);
    ok |= ed25519_dalek_pubkey(public_key, secret_key);
    ok
}

/// DOCDOC
#[no_mangle]
pub extern fn ed25519_dalek_open(signature: *const c_uchar,
                                 message: *const c_uchar,
                                 message_len: size_t,
                                 public_key: *const c_uchar) -> c_int {
    fail_if_null!(signature, public_key);

    // ptr_to_slice!() calls if_null_return_1!(message) for us
    let msg = ptr_to_slice!(message, message_len);
    let public: PublicKey = PublicKey::from_bytes(public_key);
    let sig: Signature = Signature::from_bytes(signature);
    let verified: bool = public.verify::<Sha512>(&msg, &sig);

    if verified {
        return 0;
    }
    1
}

/// DOCDOC
#[no_mangle]
pub unsafe extern fn ed25519_dalek_sign(signature: *mut *mut c_uchar,
                                        message: *const *const c_uchar,
                                        message_len: size_t,
                                        secret_key: *const *const c_uchar,
                                        public_key: *const *const c_uchar) -> c_int {
    fail_if_null!(secret_key, public_key);

    // ptr_to_slice!() calls if_null_return_1!(message) for us
    let msg = ptr_to_slice!(message, message_len);
    let key: Keypair = keypair_from_bytes!(secret_key, public_key);
    let sig: Signature = key.sign::<Sha512>(msg);

    *signature = sig.to_bytes().as_mut_ptr();
       
    0
}

/// DOCDOC
#[no_mangle]
pub extern fn ed25519_dalek_open_batch(message: *const *const c_uchar,
                                       message_len: *mut size_t, // XXX wtf donna does *size_t
                                       public_key: *const *const c_uchar,
                                       RS: *const *const c_uchar,
                                       num: size_t,
                                       valid: *mut c_int) -> c_int { // XXX wtf donna does *int
    unimplemented!()
}

/// DOCDOC
#[no_mangle]
pub extern fn ed25519_dalek_blind_secret_key(output: *mut *mut c_uchar,
                                             input: *const *const c_uchar,
                                             param: *const *const c_uchar) -> c_int {
    unimplemented!()
}

/// DOCDOC
#[no_mangle]
pub extern fn ed25519_dalek_blind_public_key(output: *mut *mut c_uchar,
                                             input: *const *const c_uchar,
                                             param: *const *const c_uchar) -> c_int {
    unimplemented!()
}

/// DOCDOC
#[no_mangle]
pub extern fn ed25519_dalek_pubkey_from_curve25519_pubkey(output: *mut *mut c_uchar,
                                                          input: *const *const c_uchar,
                                                          signbit: c_int) -> c_int {
    unimplemented!()
}

