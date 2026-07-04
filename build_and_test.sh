#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# build_and_test.sh: rebuild the shim against a pinned axioma-l0 tree and
# run the runner test suite. The runner adds no second implementation of
# any D1 path; the shim is the C truth. A green run proves the shim is
# built against the tree whose corpus produced the committed self-check
# vector, since rig import refuses on CTXHASH mismatch.
#
# Usage:
#   ./build_and_test.sh [L0_PATH] [SPEC_PATH]
# Defaults assume the estate layout: siblings under ~/axilog.

set -eu

L0=${1:-"$HOME/axilog/axioma-l0"}
SPEC=${2:-"$HOME/axilog/axioma-spec"}

if [ ! -d "$L0/exp1" ]; then
    echo "axioma-l0 not found at $L0 (or no exp1 subtree)" >&2
    exit 1
fi
if [ ! -f "$SPEC/include/axilog/types.h" ]; then
    echo "axioma-spec not found at $SPEC" >&2
    exit 1
fi

echo "building shim against L0=$L0 SPEC=$SPEC"
make -C cshim clean >/dev/null
make -C cshim L0="$L0" SPEC="$SPEC"

echo "running tests"
BATTERY=${EXP1_BATTERY:-"$L0/exp1/battery/task-battery-v1.json"}
export EXP1_LIBRIG="$PWD/cshim/librig.so"
export EXP1_BATTERY="$BATTERY"
python3 tests/test_rig.py
python3 tests/test_chain.py
python3 tests/test_agent.py

echo "all green"
