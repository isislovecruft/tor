/* Copyright (c) 2017, The Tor Project, Inc. */
/* Copyright (c) 2017, Isis Lovecruft        */
/* See LICENSE for licensing information     */

#ifndef SRC_EXT_ED25519_DALEK_H_INCLUDED_
#define SRC_EXT_ED25519_DALEK_H_INCLUDED_

#include <torint.h>

int ed25519_sign_open_batch_dalek(const unsigned char **m, size_t *mlen, const unsigned char **pk, const unsigned char **RS, size_t num, int *valid);

/* Tor specific interface to match the `ref10` and `donna` glue code.
 * The corresponding FFI definitions are included within
 * .../tor/src/rust/dalek/ffi.rs. */
int ed25519_dalek_selftest(void);
int ed25519_dalek_seckey(unsigned char *sk);
int ed25519_dalek_seckey_expand(unsigned char *sk, const unsigned char *sk_seed);
int ed25519_dalek_pubkey(unsigned char *pk, const unsigned char *sk);
int ed25519_dalek_keygen(unsigned char *pk, unsigned char *sk);

int ed25519_dalek_open(const unsigned char *signature, const unsigned char *m,
  size_t mlen, const unsigned char *pk);

int ed25519_dalek_sign(unsigned char *sig, const unsigned char *m, size_t mlen,
  const unsigned char *sk, const unsigned char *pk);

int ed25519_dalek_blind_secret_key(unsigned char *out, const unsigned char *inp,
  const unsigned char *param);

int ed25519_dalek_blind_public_key(unsigned char *out, const unsigned char *inp,
  const unsigned char *param);

int ed25519_dalek_pubkey_from_curve25519_pubkey(unsigned char *out,
  const unsigned char *inp, int signbit);


int
ed25519_dalek_scalarmult_with_group_order(unsigned char *out,
                                          const unsigned char *pubkey);

#endif
