/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define ROUTERPARSE_PRIVATE

#include "or.h"
#include "routerparse.h"
#include "test.h"

/**
 * Calling tor_version_parse() with "Tor " at the beginning of the
 * string should parse okay.
 */
static void
test_routerparse_tor_version_parse(void *arg)
{
  tor_version_t* out;
  int ret;

  (void)arg;

  out = tor_malloc(sizeof(tor_version_t));
  ret = tor_version_parse("Tor 0.2.6.2", out);
  tt_int_op(ret, OP_EQ, 0);

 done:
  if (out)
    tor_free(out);
}

/**
 * Calling tor_version_parse() without "Tor " at the beginning of the
 * string should parse okay.
 */
static void
test_routerparse_tor_version_parse_no_platform(void *arg)
{
  tor_version_t* out;
  int ret;

  (void)arg;

  out = tor_malloc(sizeof(tor_version_t));
  ret = tor_version_parse("0.2.6.2", out);
  tt_int_op(ret, OP_EQ, 0);

 done:
  if (out)
    tor_free(out);
}

/**
 * Calling tor_version_parse() with the name of an alternate Tor
 * implementation at the beginning of the string should NOT parse
 * okay.
 */
static void
test_routerparse_tor_version_parse_alt_impl(void *arg)
{
  tor_version_t* out;
  int ret;

  (void)arg;

  out = tor_malloc(sizeof(tor_version_t));
  ret = tor_version_parse("Unicorn 0.2.6.2", out);
  tt_int_op(ret, OP_EQ, -1);

 done:
  if (out)
    tor_free(out);
}

#define RP_TEST(name, flags)                       \
  { #name, test_routerparse_ ##name, (flags), NULL, NULL }

struct testcase_t routerparse_tests[] = {
  RP_TEST(tor_version_parse, 0),
  RP_TEST(tor_version_parse_no_platform, 0),
  RP_TEST(tor_version_parse_alt_impl, 0),
  END_OF_TESTCASES
};

