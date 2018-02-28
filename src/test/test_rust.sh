#!/bin/sh

cd "${abs_top_srcdir}/src/rust" || exit
exec "${abs_top_builddir}/scripts/cargo_test" --all --all-features
