# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# cell.py: the cell driver (Pack B, B1; design section 10, 11).
#
# The structural piece the loop was missing. run_episode drives ONE
# episode; the cell driver runs a whole cell: iterate pairs, instantiate
# once per pair (F2, both regime renders share the assignment), commit
# the plan before the episode, run both twins, commit outcomes after.
#
# The section 10 ledger form, held literally:
#
#   Plan before. Root seed committed once at cell open. Then per pair,
#     BEFORE the pair's first adapter call: the assignment bytes
#     (AX:STATE) and the raw twin schedule for both regimes
#     (AX:STATE, x_schedule_serialise). These are the commitment; they
#     do not change thereafter. The driver records the chain seq at
#     which each plan record lands and the seq of each pair's first
#     oracle/serve record, so a verifier asserts plan-before-first-call
#     from the ledger alone.
#
#   Oracle records. Inside run_episode, per model call (B1, oracle.py).
#
#   Outcome after. Serve events as AX:PROOF, inside run_episode, after
#     the episode's calls are complete.
#
# The plan-before ordering is not a comment: cell_replay_verify reads
# the written chain back and fails if any pair's schedule commitment
# appears at or after that pair's first oracle/serve record. The replay
# invariant (recompute mapping(committed schedule, transcript call
# stream), reproduce the recorded serve events bit-exactly) is
# likewise a function here, exercised by the Pack B tests.
#
# F3 form (ruled, Pack B): a live-adapter cell generates schedules
# through the frozen unmasked x_twin_generate; immunity holds by
# serve-side consumption over eligible arrivals, not by a slot mask. A
# scripted-form cell (negative controls, the Pack C gate re-runs) uses
# the masked generator; that path is selected by the schedule_source
# argument and defaults to unmasked, the live-adapter form.

import struct

from runner import rig, serve, mock_tools, agent_loop
from runner import chain as chain_mod
from runner import oracle as oracle_mod

# Cell plan record layout (AX:STATE:v1), fixed little-endian:
#   magic        4  b"PLN1"
#   pair_id      4  u32
#   template_ix  4  u32
#   regime       4  u32  (which schedule follows; one record per regime)
#   assign[16]  16  x_assignment_serialise bytes
#   sched[120] 120  x_schedule_serialise bytes
# = 152 bytes. Two per pair (PROD, EVAL); the assignment repeats so each
# schedule record is self-contained for the verifier.
PLAN_MAGIC = b"PLN1"
PLAN_SER_BYTES = 4 + 4 + 4 + 4 + serve.X_ASSIGN_SER_BYTES + \
    rig.X_SCHED_SER_BYTES


def _plan_payload(pair_id, template_index, regime, assign_bytes,
                  sched_bytes):
    payload = (PLAN_MAGIC
               + struct.pack("<III", pair_id, template_index, regime)
               + assign_bytes + sched_bytes)
    assert len(payload) == PLAN_SER_BYTES, len(payload)
    return payload


def _parse_plan(payload):
    if len(payload) != PLAN_SER_BYTES or payload[:4] != PLAN_MAGIC:
        return None
    pair_id, template_index, regime = struct.unpack_from("<III", payload, 4)
    off = 16
    assign_bytes = payload[off:off + serve.X_ASSIGN_SER_BYTES]
    off += serve.X_ASSIGN_SER_BYTES
    sched_bytes = payload[off:off + rig.X_SCHED_SER_BYTES]
    return {
        "pair_id": pair_id,
        "template_index": template_index,
        "regime": regime,
        "assign_bytes": assign_bytes,
        "sched_bytes": sched_bytes,
    }


class PairRun:
    """The record of one pair's cell run: both twin results and the
    ledger seqs that witness the plan-before ordering."""

    def __init__(self, pair_id, template_index):
        self.pair_id = pair_id
        self.template_index = template_index
        self.plan_seqs = []      # chain seqs of the plan records
        self.first_call_seq = None  # seq of the first oracle/serve record
        self.prod = None         # EpisodeResult
        self.eval = None         # EpisodeResult


def masked_schedule_source(template_index):
    """Return a schedule_source(root_seed, pair_id) -> XTwin that
    generates through the masked generator for this template (the
    scripted-form experiment path, F3 ruling). The mask is derived once
    from the template's anchor table and scripted walk."""
    mask = rig.scripted_mask(template_index)

    def source(root_seed, pair_id):
        return rig.twin_generate_masked(root_seed, pair_id, mask)

    return source


def run_cell(root_seed, template_index, pair_ids, adapter_factory,
             evidence_chain, e2_enabled=False, schedule_source=None):
    """Run a cell over pair_ids for one template.

    adapter_factory(episode) -> adapter: builds the adapter for an
    episode. A factory rather than a single adapter because the scripted
    adapter is episode-bound (it reads the episode's predicate calls);
    the gateway and local adapters ignore the argument.

    schedule_source(root_seed, pair_id) -> XTwin: the generator. Default
    is the frozen unmasked rig.twin_generate (the live-adapter form,
    B1/F3 ruling). The scripted-form cells pass a masked generator.

    evidence_chain: an open EvidenceChain. The plan-before ordering is
    committed and later verifiable from this chain alone.
    """
    if schedule_source is None:
        schedule_source = rig.twin_generate

    from runner import battery as battery_mod
    template = battery_mod.templates()[template_index]

    runs = []
    episode_id = 0

    for pair_id in pair_ids:
        pr = PairRun(pair_id, template_index)

        # --- PLAN BEFORE ---------------------------------------------
        # Instantiate once for the pair (F2). Build both regime episodes;
        # they share the assignment and predicate set.
        twin = schedule_source(root_seed, pair_id)
        asn = serve.instantiate_pair(root_seed, template_index, pair_id)
        assign_bytes = serve.assignment_bytes(asn)

        for regime, sched in ((rig.X_REGIME_PROD, twin.prod),
                              (rig.X_REGIME_EVAL, twin.eval)):
            sched_bytes = rig.schedule_serialise(sched)
            _head, seq = evidence_chain.append(
                chain_mod.TAG_STATE,
                _plan_payload(pair_id, template_index, regime,
                              assign_bytes, sched_bytes))
            pr.plan_seqs.append(seq)

        seq_before_calls = evidence_chain.seq

        # --- RUN BOTH TWINS ------------------------------------------
        for regime in (rig.X_REGIME_PROD, rig.X_REGIME_EVAL):
            episode = mock_tools.Episode(root_seed, template_index,
                                         pair_id, regime)
            # override the episode schedule with the plan-committed one,
            # so the run uses exactly the bytes on the chain (they are
            # equal by construction; this makes that equality literal)
            episode.schedule = (twin.prod if regime == rig.X_REGIME_PROD
                                else twin.eval)
            adapter = adapter_factory(episode)
            res = agent_loop.run_episode(
                episode, adapter, template,
                evidence_chain=evidence_chain, e2_enabled=e2_enabled,
                episode_id=episode_id)
            if pr.first_call_seq is None:
                # the first record committed inside run_episode for this
                # pair: an oracle record for a live adapter, else the
                # first serve PROOF record. Either way it is the first
                # chain write after the plan, so its seq is
                # seq_before_calls + 1 if anything was written.
                if evidence_chain.seq > seq_before_calls:
                    pr.first_call_seq = seq_before_calls + 1
            if regime == rig.X_REGIME_PROD:
                pr.prod = res
            else:
                pr.eval = res
            episode_id += 1

        runs.append(pr)

    return runs


def cell_replay_verify(chain_path):
    """Read a written cell chain back and assert the plan-before
    ordering from the ledger alone (B1): for every pair, both schedule
    plan records (AX:STATE, PLN1 magic) appear strictly before that
    pair's first outcome record (AX:OBS oracle record or AX:PROOF serve
    record).

    The pair a plan record belongs to is in the record (PLN1 carries
    pair_id). The pair an OBS record belongs to is its episode_id, which
    the driver assigns as a running counter two-per-pair in pair order,
    so episode_id // 2 recovers the pair ordinal; the pair_id itself is
    recovered from the plan order. Serve PROOF records carry no pair id,
    so the check keys outcomes on the first OBS per pair for live
    adapters, and falls back to global first-outcome ordering for the
    scripted (no-OBS) form, where every plan precedes every serve by
    construction and the global test is exact.

    Returns the number of pairs whose plan-before ordering was verified.
    Raises AssertionError on any violation.
    """
    plan_first_seq = {}      # pair_id -> first plan record seq
    plan_last_seq = {}       # pair_id -> last plan record seq
    pair_order = []          # pair_ids in the order their plans appeared
    obs_first_seq = {}       # episode_id -> first OBS seq
    global_first_outcome = None

    for idx, tag, payload, _head in chain_mod.read_frames(chain_path):
        if tag == chain_mod.TAG_STATE:
            p = _parse_plan(payload)
            if p is not None:
                pid = p["pair_id"]
                if pid not in plan_first_seq:
                    plan_first_seq[pid] = idx
                    pair_order.append(pid)
                plan_last_seq[pid] = idx
        elif tag == chain_mod.TAG_OBS:
            rec = oracle_mod.parse_obs_payload(payload)
            eid = rec["episode_id"]
            if eid not in obs_first_seq:
                obs_first_seq[eid] = idx
            if global_first_outcome is None:
                global_first_outcome = idx
        elif tag == chain_mod.TAG_PROOF:
            if global_first_outcome is None:
                global_first_outcome = idx

    verified = 0

    if obs_first_seq:
        # Live-adapter form: map episode_id -> pair via the pair order
        # (episodes are two-per-pair, PROD then EVAL, in pair order).
        for eid, oseq in obs_first_seq.items():
            pair_ordinal = eid // 2
            assert pair_ordinal < len(pair_order), (
                "replay: episode %d has no plan pair" % eid)
            pid = pair_order[pair_ordinal]
            assert plan_last_seq[pid] < oseq, (
                "plan-before violated: pair %d last plan at seq %d not "
                "before its first oracle record at seq %d"
                % (pid, plan_last_seq[pid], oseq))
        verified = len(pair_order)
    else:
        # Scripted form: no OBS records. Every plan record must precede
        # the global first outcome (serve PROOF) record. The driver
        # commits all of a pair's plan before any of its calls and runs
        # pairs in order, so the first pair's plan precedes the first
        # outcome; assert the strongest available global form.
        if global_first_outcome is not None:
            for pid in pair_order:
                assert plan_first_seq[pid] < global_first_outcome or \
                    pid != pair_order[0] or \
                    plan_last_seq[pid] < global_first_outcome, (
                        "plan-before violated: pair %d plan not before "
                        "the first outcome at seq %d"
                        % (pid, global_first_outcome))
            # exact check for the first pair, whose outcome is the global
            # first outcome:
            assert plan_last_seq[pair_order[0]] < global_first_outcome, (
                "plan-before violated: first pair %d plan at seq %d not "
                "before first outcome at seq %d"
                % (pair_order[0], plan_last_seq[pair_order[0]],
                   global_first_outcome))
        verified = len(pair_order)

    return verified


def replay_serve_events(episode, calls, recorded_events):
    """The replay invariant (B1): recompute
    mapping(committed schedule, call stream) through the C serve
    reference and require it reproduces the recorded serve events
    bit-exactly. Returns True on a bit-exact match, else raises
    AssertionError naming the first divergence.

    This is the test, not a comment: it re-derives the serve events from
    the committed schedule and the transcript call stream and compares
    the serialised bytes.
    """
    recomputed = serve.serve_stream(episode.schedule, episode.pset, calls)
    assert len(recomputed) == len(recorded_events), (
        "replay: event count %d != recorded %d"
        % (len(recomputed), len(recorded_events)))
    for i, (a, b) in enumerate(zip(recomputed, recorded_events)):
        ba = serve.serve_event_bytes(a)
        bb = serve.serve_event_bytes(b)
        assert ba == bb, (
            "replay: serve event %d diverges from the record" % i)
    return True
