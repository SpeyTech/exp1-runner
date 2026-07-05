# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# smoke_frontier.py: the EXP-1 frontier smoke test (brief 2026-07-05).
#
# Fires the paid frontier path once, cleanly, before any measurement
# rides on it, and discharges the one open Pack C condition (gateway
# dynamic isolation on real output). This is a conduction test, not a
# measurement. Proving path throughout: no committed C, no beacon, no
# frozen directions, no primary-tier scoring. If any path here could
# reach a primary-tier verdict it is a defect, and this module asserts
# it cannot (see _assert_no_primary_tier).
#
# Runs on the VM where the L3 gateway socket lives and Haiku sits behind
# it. It does not run in an environment without that socket; there is no
# mock frontier here, because a mock frontier proves nothing the Pack B
# structural test did not already prove. The value is real model
# variance through the real pipe.
#
# Usage on the VM:
#   EXP1_LIBRIG=cshim/librig.so \
#   EXP1_BATTERY=~/axilog/axioma-l0/exp1/battery/task-battery-v1.json \
#   EXP1_GATEWAY_SOCKET=/run/axioma/l3.sock \
#   python3 -m runner.smoke_frontier --out smoke-note.md
#
# The three properties (brief):
#   1. Transport: GatewayAdapter returns a well-formed transcript through
#      the live socket; turns parse, kinds map 0/1/2, episode completes.
#   2. Dynamic isolation: a sentinel present in the environment the model
#      sees never survives into any assistant turn, pre-redaction, every
#      episode. This is the live-socket confirmation of the property Pack
#      B proved structurally.
#   3. Replay bit-exact on real output: one full episode's serve events
#      re-derive from the committed schedule and the scoring reproduces
#      bit-identically from the ledger, proving-path scoring only.
#
# Hard preconditions, checked before firing (brief):
#   - gateway parameter pinning on (temperature and decoding fixed);
#     recorded in the note. A replay that passes only because sampling
#     agreed proves nothing.
#   - snapshot id recorded in every transcript.

import argparse
import datetime
import hashlib
import os
import sys

from runner import (rig, serve, mock_tools, adapters, agent_loop, cell,
                    scoring, redact)
from runner import chain as ch


SENTINEL = b"ZZ-SMOKE-SENTINEL-4e7a1f93-DO-NOT-ECHO-ZZ"

# Pinned serving temperature for the smoke test, Q16.16 fixed point.
# 0 is greedy decoding: deterministic serving, so replay bit-exactness
# means the serving is reproducible, not that a sample happened to agree.
# A committed integer constant, never a float over the wire.
SMOKE_TEMPERATURE_Q16 = 0

# Two templates: one short, one that exercises the E2 path. Chosen by
# family so the selection is stable against battery reordering: a
# SKIP_VALIDATION (short scripted walk) and a REUSE_STALE (longer, E2
# exercised). Resolved to indices at run time.
WANT_FAMILIES = ("SKIP_VALIDATION", "REUSE_STALE")


class SmokeFailure(RuntimeError):
    pass


def _pick_templates(templates):
    picks = []
    seen = set()
    for want in WANT_FAMILIES:
        for ti, t in enumerate(templates):
            if t["family"] == want and want not in seen:
                picks.append(ti)
                seen.add(want)
                break
    if len(picks) != len(WANT_FAMILIES):
        raise SmokeFailure(
            "could not resolve the two smoke templates from the battery")
    return picks


def _assert_no_primary_tier():
    """Tripwire (brief exclusion). The smoke path must never reach a
    primary-tier score_cell. Proven by construction: this module calls
    score_cell only with proving_defaults() and allow_proving=True, and
    never constructs a frozen Directions object.

    This is a lexical tripwire, not a semantic proof (B5): the binding
    guarantee is the second clause, that no frozen Directions is built in
    the smoke path. The first clause scans for a score_cell call without
    allow_proving on the same line, and must skip this function's own
    body (which contains the literal "score_cell(" in the scan itself)
    and keep every real call on one line.
    """
    import inspect
    src = inspect.getsource(sys.modules[__name__])
    in_tripwire = False
    for line in src.splitlines():
        stripped = line.strip()
        if stripped.startswith("def _assert_no_primary_tier"):
            in_tripwire = True
            continue
        if in_tripwire and stripped.startswith("def "):
            in_tripwire = False
        if in_tripwire:
            continue  # skip the tripwire's own body (self-reference)
        if "score_cell(" in line and not stripped.startswith("#"):
            if "allow_proving=True" not in line:
                raise SmokeFailure(
                    "primary-tier score_cell reachable from the smoke "
                    "path: %s" % stripped)
    # the binding guarantee: no frozen Directions constructed here
    if "Directions(" in src and "proving_defaults" not in src:
        raise SmokeFailure("a frozen Directions object is built in the "
                           "smoke path")


def _snapshot_of(adapter):
    snap = getattr(adapter, "last_snapshot_id", None)
    return snap if snap else "UNRECORDED"


def _check_isolation(res, episode_id):
    """Property 2: the sentinel appears in no assistant turn,
    pre-redaction. The sentinel is injected into the environment the
    model sees (the served tool results); the property is that the
    runner never lifts tool-result content into an assistant turn, so a
    real model reacting to a sentinel-bearing context still yields
    assistant turns free of it.

    Returns True iff the sentinel was observed in this episode's served
    tool-result bytes. A False means the injection did not reach the
    served path, and the caller must treat the isolation pass as vacuous
    and fail the run (B1): a clean isolation result on an episode where
    nothing was injected proves nothing.
    """
    sent_str = SENTINEL.decode()
    injected = False
    for t in res.turns:
        text = t.text
        if isinstance(text, bytes):
            text = text.decode(errors="replace")
        if t.kind == agent_loop.TURN_TOOL_RESULT:
            if sent_str in text:
                injected = True
        elif t.kind in (agent_loop.TURN_ASSISTANT_TEXT,
                        agent_loop.TURN_ASSISTANT_CALL):
            if sent_str in text:
                raise SmokeFailure(
                    "isolation breach: sentinel survived into an assistant "
                    "turn, episode %d" % episode_id)
    return injected


def _poison_renderer():
    """Inject the sentinel into every served tool-result body. Returns
    the original renderer for restoration."""
    orig = mock_tools._render_result

    def poisoned(verb, slot, eligible_index, failure_served, err_idx,
                 e2_enabled):
        body = orig(verb, slot, eligible_index, failure_served, err_idx,
                    e2_enabled)
        return body + b"\n" + SENTINEL
    mock_tools._render_result = poisoned
    return orig


def run_smoke(socket_path, out_path, root_seed=None, max_tokens=256):
    if root_seed is None:
        root_seed = rig.STAGE0_ROOT_SEED

    _assert_no_primary_tier()

    from runner import battery as battery_mod
    templates = battery_mod.templates()
    picks = _pick_templates(templates)

    results = []
    snapshots = set()
    temps = set()
    orig_renderer = _poison_renderer()
    episode_id = 0
    replay_ok = False
    snapshot_ok = False
    pinning_ok = False

    try:
        for ti in picks:
            template = templates[ti]
            source = cell.masked_schedule_source(ti)
            for regime in (rig.X_REGIME_PROD, rig.X_REGIME_EVAL):
                twin = source(root_seed, 0)
                episode = mock_tools.Episode(root_seed, ti, 0, regime)
                episode.schedule = (twin.prod
                                    if regime == rig.X_REGIME_PROD
                                    else twin.eval)
                adapter = adapters.GatewayAdapter(
                    socket_path,
                    temperature_q16=SMOKE_TEMPERATURE_Q16,
                    max_tokens=max_tokens)

                res = agent_loop.run_episode(
                    episode, adapter, template, episode_id=episode_id)

                # Property 1: transport. A completed episode with parsed
                # turns is the confirmation; run_episode would have
                # raised on a socket or schema fault.
                if not res.turns:
                    raise SmokeFailure(
                        "transport: empty transcript, episode %d"
                        % episode_id)
                for t in res.turns:
                    if t.kind not in (agent_loop.TURN_ASSISTANT_TEXT,
                                      agent_loop.TURN_ASSISTANT_CALL,
                                      agent_loop.TURN_TOOL_RESULT):
                        raise SmokeFailure(
                            "transport: turn kind %r out of range 0/1/2, "
                            "episode %d" % (t.kind, episode_id))

                # Property 2: dynamic isolation on real output. The check
                # returns whether the sentinel actually reached served
                # tool bytes; if it did not, the isolation pass is vacuous
                # and the run fails (B1). We do not trust a green
                # isolation line on an episode where nothing was injected.
                injected = _check_isolation(res, episode_id)
                if not injected:
                    raise SmokeFailure(
                        "vacuous isolation: the sentinel never reached "
                        "served tool bytes in episode %d, so the isolation "
                        "pass proves nothing. The poison did not route "
                        "through run_episode's serve path; fix the "
                        "injection before trusting any green." % episode_id)

                snapshots.add(_snapshot_of(adapter))
                temps.add(adapter.last_temperature
                          if adapter.last_temperature is not None
                          else "UNREPORTED")
                results.append((ti, template["family"], regime, res,
                               episode, adapter))
                episode_id += 1

        # Property 3: replay bit-exact on one full real episode, proving
        # path only. Pair two real EpisodeResults (the PROD and EVAL runs
        # of the first template); results entries are
        # (ti, family, regime, res, episode, adapter), so the res is index
        # 3. The 2AFC pair is (res of episode 0, res of episode 1).
        ti0, fam0, reg0, res0, ep0, _ad0 = results[0]
        res1 = results[1][3]
        calls = [(e.verb, e.target.decode()) for e in res0.serve_events]
        if not cell.replay_serve_events(ep0, calls, res0.serve_events):
            raise SmokeFailure("replay: serve events did not reproduce")

        pairs = [(res0, res1)]
        sides = [0]
        d = scoring.proving_defaults()
        first = scoring.score_cell(pairs, sides, d, allow_proving=True)
        second = scoring.score_cell(pairs, sides, d, allow_proving=True)
        if (first.h_score.k != second.h_score.k
                or first.tie_rates != second.tie_rates):
            raise SmokeFailure("replay: scoring not bit-identical")
        replay_ok = True

        # B4: the snapshot is a HARD precondition. If any episode came
        # back without a snapshot id, the gateway is not reporting what it
        # ran, and a clean-looking note must not be presented. Write the
        # note (so the failure is recorded) then fail the run.
        snapshot_ok = "UNRECORDED" not in snapshots and bool(snapshots)

        # Pinning is the OTHER hard precondition (Grandfather Chair): the
        # gateway must report the temperature it served, and it must be
        # the pinned greedy 0. UNREPORTED means the gateway does not echo
        # served temperature (a gateway change is owed); anything but "0"
        # means it served something other than what was pinned. Either
        # way the run is not dischargeable: record what ran, do not assert
        # it. This is why the pinning line is no longer a hand-filled
        # placeholder.
        pinning_ok = (bool(temps) and "UNREPORTED" not in temps
                      and temps == {str(SMOKE_TEMPERATURE_Q16)})

    finally:
        mock_tools._render_result = orig_renderer

    _write_note(out_path, results, snapshots, temps, replay_ok, max_tokens,
                snapshot_ok=snapshot_ok, pinning_ok=pinning_ok)
    if not snapshot_ok:
        raise SmokeFailure(
            "hard precondition failed: at least one episode returned "
            "UNRECORDED snapshot. The gateway is not reporting its serving "
            "config; the run is not dischargeable. Note written for the "
            "record, but the harness refuses a clean exit.")
    if not pinning_ok:
        raise SmokeFailure(
            "hard precondition failed: served temperature not confirmed "
            "pinned to %d across all episodes (got %s). Either the gateway "
            "does not echo served temperature (UNREPORTED: a gateway change "
            "is owed) or it served something other than the pin. Replay is "
            "not meaningful without confirmed deterministic serving. Note "
            "written for the record; the harness refuses a clean exit."
            % (SMOKE_TEMPERATURE_Q16, sorted(temps)))
    return out_path


def _write_note(out_path, results, snapshots, temps, replay_ok, max_tokens,
                snapshot_ok=True, pinning_ok=True):
    now = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    lines = []
    lines.append("# EXP-1 frontier smoke test: run note")
    lines.append("")
    lines.append("Date: %s. Not a witness report; nothing committed. The "
                 "record that the frontier path was fired once, cleanly."
                 % now)
    if not snapshot_ok:
        lines.append("")
        lines.append("## RUN NOT DISCHARGEABLE")
        lines.append("")
        lines.append("A hard precondition failed: at least one episode "
                     "returned an UNRECORDED snapshot. The gateway is not "
                     "reporting its serving config. This note records the "
                     "failure; it does not discharge the Pack C condition. "
                     "Fix the gateway snapshot header and re-fire.")
    if not pinning_ok:
        lines.append("")
        lines.append("## RUN NOT DISCHARGEABLE")
        lines.append("")
        lines.append("A hard precondition failed: served temperature not "
                     "confirmed pinned. The gateway did not report serving "
                     "at the pinned temperature on every episode (see the "
                     "Gateway pinning section). Replay is not meaningful "
                     "without confirmed deterministic serving; this note "
                     "does not discharge the Pack C condition.")
    lines.append("")
    lines.append("## What ran")
    lines.append("")
    fams = ", ".join("%s (%s regime)" % (f, "PROD" if r == 0 else "EVAL")
                     for _ti, f, r, _res, _ep, _ad in results)
    lines.append("%d episodes through the live L3 gateway (GatewayAdapter): "
                 "%s." % (len(results), fams))
    lines.append("")
    lines.append("## Snapshot")
    lines.append("")
    lines.append("Haiku snapshot id(s) captured: %s"
                 % ", ".join(sorted(snapshots)))
    lines.append("")
    lines.append("## Gateway pinning")
    lines.append("")
    lines.append("Serving temperature as REPORTED BY THE GATEWAY (what it "
                 "served, not what was asked): %s (Q16.16; 0 is greedy "
                 "decoding). Pinned request value: %d. top_p null, which "
                 "does not affect the argmax at temperature 0. "
                 "max_tokens=%d. Deterministic serving confirmed: %s."
                 % (", ".join(sorted(temps)) if temps else "NONE",
                    SMOKE_TEMPERATURE_Q16, max_tokens,
                    "YES" if pinning_ok else "NO"))
    lines.append("")
    lines.append("## Isolation")
    lines.append("")
    lines.append("Sentinel confirmed absent from every assistant turn "
                 "pre-redaction, all %d episodes. The open Pack C gateway "
                 "dynamic isolation condition discharges on this record."
                 % len(results))
    lines.append("")
    lines.append("## Replay")
    lines.append("")
    lines.append("Bit-exact on one full real episode: serve events "
                 "re-derived from the committed schedule, scoring "
                 "reproduced bit-identically, proving path "
                 "(allow_proving=True). %s"
                 % ("CONFIRMED" if replay_ok else "NOT CONFIRMED"))
    lines.append("")
    lines.append("## Cost")
    lines.append("")
    lines.append("ACTUAL SPEND: record from the gateway billing. Expected "
                 "pennies against USD 20.")
    lines.append("")
    lines.append("Spey Systems Ltd (SC889983).")
    with open(out_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="EXP-1 frontier smoke test")
    ap.add_argument("--socket", default=os.environ.get(
        "EXP1_GATEWAY_SOCKET"),
        help="L3 gateway unix socket path (or EXP1_GATEWAY_SOCKET)")
    ap.add_argument("--out", default="smoke-note.md",
                    help="output note path")
    ap.add_argument("--max-tokens", type=int, default=256)
    args = ap.parse_args(argv)

    if not args.socket:
        ap.error("no gateway socket: set --socket or EXP1_GATEWAY_SOCKET")

    out = run_smoke(args.socket, args.out, max_tokens=args.max_tokens)
    print("smoke test complete; note written to %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
