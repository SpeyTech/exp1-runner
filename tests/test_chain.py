# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# test_chain.py: the evidence chain writer against the gateway record
# format. These checks were run inline during session 1; written to a
# file here so the proof lives with the code. Run: python3 -m tests.test_chain
# from the runner root, or pytest.
#
# Proves:
#   commit construction matches the substrate's axilog_commit through
#     the shim, on three payload vectors
#   genesis head matches the substrate-derived value
#   write / replay / verify round-trips: a reopened chain recovers the
#     same head and seq
#   a single flipped byte is refused on replay, exactly as gw_ledger
#     refuses a divergent stored commit

import os
import sys
import hashlib
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from runner import chain, rig


def test_commit_matches_substrate():
    for payload in [b"x", b'{"a":1}', bytes(range(256))]:
        got = chain.commit(chain.TAG_OBS, payload)
        want = rig.axilog_commit(bytes(chain.TAG_OBS), payload)
        assert got == want, f"commit mismatch on {payload[:8]!r}"


def test_genesis_matches_substrate():
    e0 = rig.axilog_commit(bytes(chain.TAG_STATE), bytes(chain.GENESIS_PAYLOAD))
    want = hashlib.sha256(b"AX:LEDGER:v1" + e0).digest()
    assert want == chain.genesis_head()


def test_write_replay_verify(tmp_path=None):
    p = "/tmp/exp1_chain_test.bin"
    if os.path.exists(p):
        os.unlink(p)
    c = chain.EvidenceChain(p)
    h1, s1 = c.append(chain.TAG_STATE, b'{"seed":"deadbeef"}')
    h2, s2 = c.append(chain.TAG_OBS, b'{"obs":1}')
    c.close()

    c2 = chain.EvidenceChain(p)
    assert (c2.head, c2.seq) == (h2, 2), "replay diverged from written head"
    c2.close()

    frames = list(chain.read_frames(p))
    assert frames[-1][3] == h2
    os.unlink(p)


def test_tamper_refused():
    p = "/tmp/exp1_chain_tamper.bin"
    if os.path.exists(p):
        os.unlink(p)
    c = chain.EvidenceChain(p)
    c.append(chain.TAG_STATE, b'{"seed":"deadbeef"}')
    c.append(chain.TAG_OBS, b'{"obs":1}')
    c.close()

    data = bytearray(open(p, "rb").read())
    data[30] ^= 1
    open(p, "wb").write(bytes(data))

    refused = False
    try:
        list(chain.read_frames(p))
    except chain.ChainError:
        refused = True
    assert refused, "tamper not detected on replay"
    os.unlink(p)


def _run_all():
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
            passed += 1
    print(f"\n{passed} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
