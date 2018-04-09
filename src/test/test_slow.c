/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_slow.c
 * \brief Slower unit tests for many pieces of the lower level Tor modules.
 **/

#include "orconfig.h"
#include "test.h"
#include "tinytest.h"

struct testgroup_t testgroups[] = {
  { "slow/crypto/", slow_crypto_tests },
  { "slow/util/", slow_util_tests },
  END_OF_GROUPS
};

