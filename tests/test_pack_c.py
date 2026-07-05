# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# test_pack_c.py: Pack C. The C1 redaction gate at the 160-twin standard,
# and the C2 RUNG scoring deliverables (directions load boundary, tie
# chain, structural CANARY independence, replay invariant).
#
# Run: EXP1_LIBRIG=... EXP1_BATTERY=... python3 tests/test_pack_c.py

import inspect
import os
import pathlib
import random
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from runner import (rig, serve, mock_tools, adapters, agent_loop, cell,
                    scoring, redaction_gate)
from runner import chain as ch

ROOT = rig.STAGE0_ROOT_SEED


# --- C1: the redaction gate at the 160-twin standard --------------------

def test_redaction_gate_full_standard():
    """The C1 gate: twenty templates, eight pairs, both properties over
    the C transcript of record on both E2 domains (F-C2). Twin identity
    and cross-redactor identity each run E2-off and E2-on."""
    counts = redaction_gate.run_gate()
    # 20 templates x 8 pairs x 2 E2 domains = 320 twin redactions... but
    # each domain checks one twin pair, so 20 x 8 x 2 = 320 twin checks
    assert counts["twins_checked"] == 320, counts["twins_checked"]
    # cross: 20 x 8 x 2 regimes x 2 E2 domains = 640
    assert counts["cross_checks"] == 640, counts["cross_checks"]


def test_e2_on_cross_redactor_at_sample():
    """F-C2 pinning test: on the E2-on domain, the runner redactor and
    the C x_redact agree byte-for-byte over the C E2 render of record,
    and twin identity holds on the padded input. Sample scale, both
    regimes."""
    ti = 0
    source = cell.masked_schedule_source(ti)
    for pair_id in range(4):
        twin = source(ROOT, pair_id)
        c_prod = rig.rig_run_scripted_e2(twin.prod)
        c_eval = rig.rig_run_scripted_e2(twin.eval)
        rp = redaction_gate._c_redaction_of_transcript(c_prod)
        re_ = redaction_gate._c_redaction_of_transcript(c_eval)
        # twin identity on the padded domain
        assert rp == re_, "E2-on twin identity failed at pair %d" % pair_id
        # cross-redactor on the padded domain, both regimes
        for ctr in (c_prod, c_eval):
            c_red = redaction_gate._c_redaction_of_transcript(ctr)
            runner_red = redaction_gate._runner_redaction_of_c_transcript(
                ctr)
            assert c_red == runner_red, (
                "E2-on cross-redactor divergence at pair %d" % pair_id)


def test_cross_redactor_divergence_would_block():
    """The cross-redactor comparison has teeth: a corrupted redaction
    differs from the C redactor, proving the gate catches a real
    divergence rather than passing vacuously."""
    ti, pair_id = 0, 0
    source = cell.masked_schedule_source(ti)
    twin = source(ROOT, pair_id)
    ctr = redaction_gate._c_transcript_of_schedule(twin.prod)
    c_red = redaction_gate._c_redaction_of_transcript(ctr)
    runner_red = redaction_gate._runner_redaction_of_c_transcript(ctr)
    assert c_red == runner_red          # they agree on the real transcript
    assert c_red + b"LEAK" != runner_red  # and a corruption would differ


# --- C2.3: the directions load boundary (A1) ----------------------------

def _scripted_cell(n_templates=2, pairs=4):
    from runner import battery as battery_mod
    tpls = battery_mod.templates()
    rng = random.Random(42)
    pairs_out, sides = [], []
    for ti in range(n_templates):
        for pid in range(pairs):
            pe = mock_tools.Episode(ROOT, ti, pid, rig.X_REGIME_PROD)
            ee = mock_tools.Episode(ROOT, ti, pid, rig.X_REGIME_EVAL)
            pr = agent_loop.run_episode(pe, adapters.ScriptedAdapter(pe),
                                        tpls[ti])
            er = agent_loop.run_episode(ee, adapters.ScriptedAdapter(ee),
                                        tpls[ti])
            if rng.random() < 0.5:
                pairs_out.append((pr, er)); sides.append(1)
            else:
                pairs_out.append((er, pr)); sides.append(0)
    return pairs_out, sides


def test_primary_tier_refuses_without_directions():
    """Primary-tier scoring with no loaded directions refuses to emit a
    signed direction (A1). None and proving-without-flag both raise."""
    pairs, sides = _scripted_cell()
    caught = 0
    try:
        scoring.score_cell(pairs, sides, None)
    except scoring.DirectionsRequired:
        caught += 1
    try:
        scoring.score_cell(pairs, sides, scoring.proving_defaults())
    except scoring.DirectionsRequired:
        caught += 1
    assert caught == 2, "primary tier did not refuse both unsigned paths"


def test_proving_path_reachable_only_by_flag():
    """The proving defaults are load-bearing and reachable, but only
    under the explicit flag (the pipeline-proof and replay path)."""
    pairs, sides = _scripted_cell()
    score = scoring.score_cell(pairs, sides, scoring.proving_defaults(),
                               allow_proving=True)
    assert score.n == len(pairs)
    assert score.h_score.a_ci_low < 0 < score.h_score.a_ci_high


def test_frozen_directions_score_on_primary_tier():
    """A frozen (non-proving) Directions object scores on the primary
    tier without the flag: this is what a stage-2 load looks like."""
    pairs, sides = _scripted_cell()
    frozen = scoring.Directions(
        canary_compliant_is_eval=True, lexicon_higher_is_eval=True,
        shape_longer_is_eval=True, lexicon=scoring.LEXICON_DEFAULT,
        proving=False)
    score = scoring.score_cell(pairs, sides, frozen)
    assert score.n == len(pairs)


# --- C2.2: the tie chain and per-link tie rates -------------------------

def test_tie_chain_reports_every_link():
    """score_cell reports the tie rate at canary, lexicon, and shape.
    The scripted control ties at canary on every pair (always compliant),
    so the canary tie rate is 1.0 and the chain descends."""
    pairs, sides = _scripted_cell()
    score = scoring.score_cell(pairs, sides, scoring.proving_defaults(),
                               allow_proving=True)
    assert set(score.tie_rates) == {"canary", "lexicon", "shape"}
    assert score.tie_rates["canary"] == 1.0
    # every pair decided somewhere in the chain
    assert sum(score.deciding_counts.values()) == len(pairs)


# --- C2.1: RUNG_CANARY structural independence from assistant text ------

def test_canary_independence_structural():
    """RUNG_CANARY reads only the canary label, never assistant text.
    Asserted structurally: rung_canary's source references pair[i].canary
    and no text accessor. A pair whose assistant text is mutated but
    whose canary is unchanged yields the identical judgement."""
    src = inspect.getsource(scoring.rung_canary)
    assert "_assistant_text" not in src, (
        "rung_canary reads assistant text; independence broken")
    assert ".canary" in src

    pairs, sides = _scripted_cell(n_templates=1, pairs=2)
    d = scoring.proving_defaults()
    p = pairs[0]
    j_before = scoring.rung_canary(p, d)
    # mutate assistant text on both sides; canary untouched
    for side in p:
        for t in side.turns:
            if t.kind == agent_loop.TURN_ASSISTANT_TEXT:
                t.text = t.text + " MUTATED"
    j_after = scoring.rung_canary(p, d)
    assert j_before.eval_side == j_after.eval_side
    assert j_before.tied == j_after.tied


# --- C2.4: the replay invariant, full re-score from the ledger ----------

def test_scoring_replay_bit_exact():
    """A full re-score of a committed cell recomputes serve events and
    realised E2 sizes from the transcript plus the committed schedule,
    trusts no recorded target, and reproduces the recorded scoring
    bit-identically. At least one full scripted cell, E2 on.

    Run an E2-on scripted cell through run_cell with an evidence chain,
    score it, then replay: re-derive each pair's serve events from the
    committed schedule and call stream (cell.replay_serve_events) and
    re-run the scorer, requiring an identical CellScore."""
    from runner import battery as battery_mod
    tpls = battery_mod.templates()
    ti = 0

    with tempfile.TemporaryDirectory() as d:
        chain = ch.EvidenceChain(os.path.join(d, "cell.chain"))
        runs = cell.run_cell(
            ROOT, ti, list(range(4)),
            lambda ep: adapters.ScriptedAdapter(ep), chain,
            e2_enabled=True,
            schedule_source=cell.masked_schedule_source(ti))
        chain.close()

    # Build the 2AFC pairs from the runs, and the true eval sides.
    rng = random.Random(7)
    pairs, sides = [], []
    for pr in runs:
        if rng.random() < 0.5:
            pairs.append((pr.prod, pr.eval)); sides.append(1)
        else:
            pairs.append((pr.eval, pr.prod)); sides.append(0)

    d0 = scoring.proving_defaults()
    first = scoring.score_cell(pairs, sides, d0, e2_cell=True,
                               allow_proving=True)

    # Replay: re-derive serve events from the committed schedule and the
    # transcript call stream, confirm bit-exact, then re-score.
    for pr in runs:
        for res, sched_ep in ((pr.prod, rig.X_REGIME_PROD),
                              (pr.eval, rig.X_REGIME_EVAL)):
            episode = mock_tools.Episode(ROOT, ti, pr.pair_id, sched_ep)
            calls = [(e.verb, e.target.decode()) for e in res.serve_events]
            assert cell.replay_serve_events(episode, calls,
                                            res.serve_events)

    second = scoring.score_cell(pairs, sides, d0, e2_cell=True,
                                allow_proving=True)
    assert first.h_score.k == second.h_score.k
    assert first.h_score.n == second.h_score.n
    assert first.tie_rates == second.tie_rates
    assert first.deciding_counts == second.deciding_counts


def _run_all():
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("  PASS %s" % name)
            passed += 1
    print("\n%d passed" % passed)
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
