// Copyright (c) 2018, The Tor Project, Inc.
// Copyright (c) 2018, isis agora lovecruft
// See LICENSE for licensing information

//! Wrappers for Tor's random number generator to provide implementations of
//! `rand_core` traits.

// This is the real implementation, in use in production, which calls into our C
// wrappers in /src/common/crypto_rand.c, which call into OpenSSL, system
// libraries, and make syscalls.
//
// TODO: If/when we sort linkage errors (https://bugs.torproject.org/25386), we
// can safely remove this code and the mocked version for testing below. -isis
#[cfg(not(test))]
mod internal {
    use std::u64;

    use rand_core::CryptoRng;
    use rand_core::Error;
    use rand_core::RngCore;
    use rand_core::impls::next_u32_via_fill;
    use rand_core::impls::next_u64_via_fill;

    use external::c_tor_crypto_strongest_rand;
    use external::c_tor_crypto_seed_rng;

    use tor_log::LogDomain;
    use tor_log::LogSeverity;

    /// Largest strong entropy request permitted.
    //
    // C_RUST_COUPLED: `MAX_STRONGEST_RAND_SIZE` /src/common/crypto_rand.c
    const MAX_STRONGEST_RAND_SIZE: usize = 256;

    /// A wrapper around OpenSSL's RNG.
    pub struct TorRng {
        // This private, zero-length field forces the struct to be treated the
        // same as its opaque C couterpart.
        _unused: [u8; 0],
    }

    /// Mark `TorRng` as being suitable for cryptographic purposes.
    impl CryptoRng for TorRng {}

    impl TorRng {
        // C_RUST_COUPLED: `crypto_seed_rng()` /src/common/crypto_rand.c
        fn new() -> Self {
            if !c_tor_crypto_seed_rng() {
                tor_log_msg!(LogSeverity::Warn, LogDomain::General,
                             "TorRng::from_seed()",
                             "The RNG could not be seeded!");
            }
            // XXX also log success at info level —isis
            TorRng{ _unused: [0u8; 0] }
        }
    }

    impl RngCore for TorRng {
        // C_RUST_COUPLED: `crypto_rand_uint64()` /src/common/crypto_rand.c
        fn next_u32(&mut self) -> u32 {
            next_u32_via_fill()
        }

        // C_RUST_COUPLED: `crypto_rand_uint64()` /src/common/crypto_rand.c
        fn next_u64(&mut self) -> u64 {
            next_u64_via_fill()
        }

        // C_RUST_COUPLED: `crypto_rand()` /src/common/crypto_rand.c
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            debug_assert!(dest.len() <= MAX_STRONGEST_RAND_SIZE);

            c_tor_crypto_strongest_rand(dest);
        }

        // C_RUST_COUPLED: `crypto_rand()` /src/common/crypto_rand.c
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            Ok(self.fill_bytes(dest))
        }
    }
}

// For testing, we expose the pure-Rust implementation of a
// cryptographically-insecure PRNG which mirrors the implementation of
// `tor_weak_rng_t` in C.
#[cfg(test)]
mod internal {
    use prng::TorInsecurePrng;

    pub type TorRng = TorInsecurePrng;
}

// Finally, expose the public functionality of whichever appropriate internal
// module.
pub use self::internal::*;

