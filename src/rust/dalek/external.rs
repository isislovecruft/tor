/* 
 * Copyright (c) 2017, The Tor Project, Inc.
 * Copyright (c) 2017, Isis Lovecruft
 * See LICENSE for licensing information */

//! Methods for calling tor's C code which are necessary to our ed25519 rust
//! implementation.

use libc::c_int;
use libc::c_void;
use libc::size_t;
use libc::uint8_t;

use rand::Rng;


pub fn crypto_strongest_rand(out: *mut uint8_t, out_len: size_t) {
    unimplemented!()
}

pub fn ed25519_hash() {
    unimplemented!()
}

mod crypto {

/// Use tor's crypto_rand_strongest_* functions.
pub struct StrongestRand;

impl StrongestRand {
    pub fn new(&self) -> StrongestRand {
        crypto_seed_rng(c_void);

        StrongestRand
    }
}

impl Rng for StrongestRand {
    fn next_u32(&mut self) -> u32 {
        unsafe {
            crypto_rand_int(u32::max())
        }
    }

    fn next_u64(&mut self) -> u64 {
        unsafe {
            crypto_rand_uint64(u64::max())
        }
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        let len: size_t = bytes.len();

        unsafe {
            crypto_strongest_rand(bytes, len);
        }
    }
}
