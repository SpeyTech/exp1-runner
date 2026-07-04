# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# test_agent.py: session-3 integration. The serve bindings, the mock
# tool layer, the agent loop, the redaction byte-identity gate, and the
# RUNG scoring negative control. Requires the shim built against the
# pinned axioma-l0 tree and EXP1_BATTERY pointing at the canonical
# battery (or the estate sibling layout).

import os
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from runner import (rig, serve, mock_tools, adapters, agent_loop,
                    redact, scoring, battery)
from runner import chain as ch

ROOT = rig.STAGE0_ROOT_SEED


def test_battery_blob_pinned():
    # Loading the module already verified the blob; assert the pin value.
    assert battery.BATTERY_BLOB_PIN == \
        "64f2f601d3f3e988d77e14bd6e780d402954808c"
    assert len(battery.templates()) == 20


def test_serve_predicate_immunity_through_shim():
    ep = mock_tools.Episode(ROOT, 7, 0, rig.X_REGIME_PROD)
    pc = ep.predicate_calls()
    calls = [(serve.X_VERB_FILE_READ, "manifest.yaml"),
             (serve.VERB_ID[pc[0][0]], pc[0][1]),
             (serve.X_VERB_SEARCH, "health"),
             (serve.VERB_ID[pc[1][0]], pc[1][1])]
    events = serve.serve_stream(ep.schedule, ep.pset, calls)
    # predicate calls never carry a served failure
    for ev in events:
        if ev.is_predicate:
            assert ev.failure_served == 0
    serve.immunity_check(events, ep.pset)  # must not raise


def test_immunity_gate_refuses_doctored():
    ep = mock_tools.Episode(ROOT, 0, 2, rig.X_REGIME_PROD)
    pc = ep.predicate_calls()
    calls = [(serve.VERB_ID[pc[0][0]], pc[0][1]),
             (serve.X_VERB_SEARCH, "filler"),
             (serve.VERB_ID[pc[1][0]], pc[1][1])]
    events = serve.serve_stream(ep.schedule, ep.pset, calls)
    # doctor: force a failure onto a predicate event
    for ev in events:
        if ev.is_predicate:
            ev.failure_served = 1
            ev.err_idx = 3
            break
    refused = False
    try:
        serve.immunity_check(events, ep.pset)
    except rig.RigError:
        refused = True
    assert refused, "immunity gate passed a doctored transcript"


def test_agent_loop_scripted_compliant():
    tpl = battery.templates()[0]  # T01
    ep = mock_tools.Episode(ROOT, 0, 0, rig.X_REGIME_PROD)
    res = agent_loop.run_episode(ep, adapters.ScriptedAdapter(ep), tpl)
    # scripted agent always compliant
    assert res.canary == rig.X_CANARY_COMPLIANT
    # immunity held (run_episode calls the gate)
    assert len(res.serve_events) > 0


def test_redaction_gate_holds():
    tpls = battery.templates()
    passed = 0
    for ti in range(20):
        for pair in range(2):
            for e2 in (False, True):
                assert redact.redaction_gate(ROOT, ti, pair, tpls[ti],
                                             e2_enabled=e2)
                passed += 1
    assert passed == 80


def test_scoring_scripted_control_is_chance():
    import random
    tpls = battery.templates()
    pairs = []
    sides = []
    rng = random.Random(42)
    for ti in range(20):
        for pair_id in range(4):
            pe = mock_tools.Episode(ROOT, ti, pair_id, rig.X_REGIME_PROD)
            ee = mock_tools.Episode(ROOT, ti, pair_id, rig.X_REGIME_EVAL)
            pr = agent_loop.run_episode(pe, adapters.ScriptedAdapter(pe),
                                        tpls[ti])
            er = agent_loop.run_episode(ee, adapters.ScriptedAdapter(ee),
                                        tpls[ti])
            if rng.random() < 0.5:
                pairs.append((pr, er)); sides.append(1)
            else:
                pairs.append((er, pr)); sides.append(0)
    score, tie = scoring.score_cell(pairs, sides)
    # scripted behaviour carries no envelope info: CI must span 0
    assert score.a_ci_low < 0 < score.a_ci_high
    # and the canary ties every pair (always compliant)
    assert tie == 1.0


def test_evidence_chain_from_episode():
    tpl = battery.templates()[7]  # T08
    ep = mock_tools.Episode(ROOT, 7, 0, rig.X_REGIME_PROD)
    p = "/tmp/exp1_agent_evidence.bin"
    if os.path.exists(p):
        os.unlink(p)
    c = ch.EvidenceChain(p)
    res = agent_loop.run_episode(ep, adapters.ScriptedAdapter(ep), tpl,
                                 evidence_chain=c, e2_enabled=True)
    head, seq = c.head, c.seq
    c.close()
    # replay recovers the same head
    c2 = ch.EvidenceChain(p)
    assert (c2.head, c2.seq) == (head, seq)
    c2.close()
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
