/* 
 * Copyright (c) 2017, The Tor Project, Inc.
 * Copyright (c) 2017, Isis Lovecruft
 * See LICENSE for licensing information */

//! Interface for calling (ed25519-dalek)[https://github.com/isislovecruft/ed25519-dalek]
//! from Tor's C code.
//!
//! We define the functions in here which are in the `impl_dalek` struct of
//! function pointers in .../tor/src/common/crypto_ed25519.c.

use ed25519_dalek::KeyPair;
use ed25519_dalek::SecretKey;
use ed25519_dalek::ffi::*;

use libc{c_char, c_uchar, c_int, size_t};

use external;


#[cfg(not(feature = "std"))]
pub extern fn fix_linking_when_using_no_std() { panic!() }


/// Return `1` if the raw pointer (a `*mut T` or `*const T`) is NULL.  In Rust,
/// references are never allowed to be NULL.
macro_rules! if_null_return_1 {
    ($($p:ptr),*) => {{
        if $p.is_null() {
            return 1;
        }
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
        if_null_return_1!($p);
        // Convert from pointer and length to a slice. This is unsafe,
        // as we may be dereferencing invalid memory.
        slice::from_raw_parts($p, $len as usize)
    }}
}

/// Expand the seed into a secret key.
// XXX do we need this?
#[inline(always)]
fn ed25519_dalek_extsk(extsk: hash_512bits, secret_key: &SecretKey) {
    let secret_key: SecretKey = external::ed25519_hash()
}

/// Expand the secret key by hashing it.
///
/// # Note
///
/// We derive the public key from the secret key by hashing a seed, then
/// reducing the hash digest to a scalar and multiplying it by the ed25519
/// basepoint. (This behaviour is identical to ref10.)
///
/// The donna code instead hashes a seed and treats the lower 32 bytes as the
/// secret key and the upper 32 bytes as the public key.
#[no_mangle]
pub extern fn ed25519_dalek_seckey(secret_key: *mut c_uchar) -> c_int {
    let csprng: TorRng = external::TorRng::new();
    let keypair: Keypair = Keypair::generate::<external::TorSha512>(&mut csprng);

    *secret_key = keypair.secret.0;

    0
}

#[no_mangle]
pub extern fn ed25519_dalek_seckey_expand(secret_key: *mut c_uchar,
                                          seed: *const c_uchar) -> c_int {
    unimplemented!()
}

#[no_mangle]
pub extern fn ed25519_dalek_pubkey(public_key: *mut c_uchar,
                                   secret_key: *const c_uchar) -> c_int {
    unimplemented!()
}

#[no_mangle]
pub extern fn ed25519_dalek_keygen(public_key: *mut c_uchar,
                                   secret_key: *mut c_uchar) -> c_int {
    let mut csprng: external::StrongestRand = external::StrongestRand::new();

    let keypair: Keypair = Keypair::generate::<external::Sha512>(&mut csprng);

    *public_key = keypair.public.0;
    *secret_key = keypair.secret.0;

    0
}

#[no_mangle]
pub extern fn ed25519_dalek_open(signature: *const c_uchar,
                                 message: *const c_uchar,
                                 message_len: size_t,
                                 public_key: *const c_uchar) -> c_int {
    unimplemented!()
}

#[no_mangle]
pub unsafe extern fn ed25519_dalek_sign(signature: *mut c_uchar,
                                        message: *const c_uchar,
                                        message_len: size_t,
                                        secret_key: *const c_uchar,
                                        public_key: *const c_uchar) -> c_int {
    fail_if_null!(secret_key, public_key);

    // tor's ed25519 interface expects secret keys of 32 bytes in length,
    // whereas in dalek they are the concatenation of the secret and public key
    // (and thus 64 bytes)
    if (secret_key.len() != 32) || (public_key.len() != 32) {
        return 1;
    }

    // ptr_to_slice!() calls if_null_return_1!(message) for us
    let msg = ptr_to_slice!(message, message_len);
    let secret: SecretKey = SecretKey::from_bytes(concat!(secret_key, public_key));
    let sig: Signature = secret.sign::<external::Sha512>(msg);

    *signature = sig.0;
       
    0
}

#[no_mangle]
pub extern fn ed25519_dalek_open_batch(message: *const *const c_uchar,
                                       message_len: *mut size_t, // XXX wtf donna does *size_t
                                       public_key: *const *const c_uchar,
                                       RS: *const *const c_uchar,
                                       num: size_t,
                                       valid: *mut c_int) -> c_int { // XXX wtf donna does *int
    unimplemented!()
}

#[no_mangle]
pub extern fn ed25519_dalek_blind_secret_key(output: *mut c_uchar,
                                             input: *const c_uchar,
                                             param: *const c_uchar) -> c_int {
    unimplemented!()
}

#[no_mangle]
pub fn extern ed25519_dalek_blind_public_key(output: *mut c_uchar,
                                             input: *const c_uchar,
                                             param: *const c_uchar) -> c_int {
    unimplemented!()
}

#[no_mangle]
pub fn extern ed25519_dalek_pubkey_from_curve25519_pubkey(output: *mut c_uchar,
                                                          input: *const c_uchar,
                                                          signbit: c_int) -> c_int {
    unimplemented!()
}

