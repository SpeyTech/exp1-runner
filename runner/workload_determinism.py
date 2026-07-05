# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# workload_determinism.py: the EXP-1 workload-determinism check
# (brief 2026-07-05 + Chair addendum). Proves the backend serves the
# REAL workload deterministically at maximum context depth, not just the
# short G3 probe. G3 showed temperature 0 is greedy on a trivial prompt;
# this shows it holds on the input the paid runs actually produce.
#
# Runs on the VM against the live L3 gateway. Commits nothing; a
# conduction check, like the smoke test.
#
# The input under test (addendum sharpening 2): the captured context
# bytes at a REAL episode's FINAL model call, E2 padding included on the
# E2 template. Worst case, not the easiest: a first-turn prompt is barely
# longer than the G3 probe, and every risk the brief names scales with
# context depth. So we run an episode to completion, capture the context
# assembled at its deepest call, and fire THAT twice.
#
# Two fire modes, both recorded separately (addendum ruling):
#   back-to-back: two fires with nothing between. The floor.
#   separated:    two fires with an unrelated request in between, so a
#                 snapshot swap or backend state carry would show. The
#                 real bar. A pass on back-to-back while separated
#                 diverges is a diagnostic outcome, not a muddle, so the
#                 two are never collapsed into one verdict.
#
# Input-side guard (addendum sharpening 1): assemble the prompt ONCE,
# hold the bytes, fire the identical stream twice. Assert request
# byte-identity BEFORE response byte-identity. Otherwise harness-side
# assembly nondeterminism is misattributed to the backend; and if two
# assemblies of one context ever differ, that is its own finding against
# the runner, surfaced not buried.

import argparse
import hashlib
import os
import socket
import sys

from runner import (rig, battery, agent_loop, mock_tools, adapters, cell)


class WorkloadDeterminismFailure(RuntimeError):
    pass


def _fire_raw(socket_path, request_bytes):
    """Fire a pre-assembled request byte stream at the gateway and return
    (raw, body, header_dict, sent_hash). sent_hash is the SHA-256 of the
    bytes actually written to the socket (W2): the identity check compares
    these across a pair, so it verifies what was really sent rather than
    comparing an argument to itself. A re-assembling refactor that changed
    the sent bytes would change this hash and the assertion would fire."""
    sent_hash = hashlib.sha256(request_bytes).hexdigest()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(socket_path)
    s.sendall(request_bytes)
    data = b""
    while True:
        b = s.recv(65536)
        if not b:
            break
        data += b
    s.close()
    sep = data.find(b"\n\n")
    header = {}
    if sep >= 0:
        for line in data[:sep].decode(errors="replace").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                header[k.strip()] = v.strip()
    body = data[sep + 2:] if sep >= 0 else b""
    return data, body, header, sent_hash


class _CapturingAdapter:
    """Transparent wrapper around the real adapter. run_episode passes
    the assembled context to adapter.step on EVERY call, so a wrapper at
    the adapter seam sees every context including the final one; no
    change to any signed artefact is needed. (The prior rationale for
    reimplementing the loop instead, that wrapping would require the
    signed agent_loop to expose its final per-call context, was false;
    corrected per the Chair R2 witness, which demonstrated this wrapper
    driving the real run_episode. The wrapper also removes the loop-drift
    class entirely and makes the "real episode's context" claim exact:
    the captured context comes from run_episode's own turn construction,
    not a reimplementation of it.) All other attribute access delegates
    to the wrapped adapter, so run_episode's getattr reads (source,
    last_seq, last_snapshot_id) see the real values."""

    def __init__(self, inner):
        self._inner = inner
        self.contexts = []

    def step(self, context):
        self.contexts.append(context)
        return self._inner.step(context)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _capture_deepest_context(socket_path, template_index, root_seed,
                             max_tokens, temperature_q16):
    """Run a real episode to completion against the live gateway and
    return the context bytes assembled at its FINAL model call, plus the
    E2 flag used. This is the deepest, worst-case input: full transcript
    depth, E2 padding on an E2 template. The episode is driven by the
    real agent_loop.run_episode through a capturing adapter wrapper;
    evidence_chain is None, so nothing is committed (conduction only)."""
    templates = battery.templates()
    template = templates[template_index]
    e2 = True  # exercise the E2 render path for maximum context depth

    episode = mock_tools.Episode(root_seed, template_index, 0,
                                 rig.X_REGIME_PROD)
    # The real paid-episode path uses the live-cell (unmasked) generator
    # (F3 ruling: the masked generator is the scripted-form experiment
    # path, not the paid path). Capture on the unmasked source so the
    # context under test is genuinely "a real episode's", matching the
    # harness's claim. Immaterial to the determinism verdict (the schedule
    # only shapes tool-result content, fixed once captured), but the
    # claim should match what is tested.
    twin = rig.twin_generate(root_seed, 0)
    episode.schedule = twin.prod

    adapter = _CapturingAdapter(adapters.GatewayAdapter(
        socket_path, temperature_q16=temperature_q16,
        max_tokens=max_tokens))
    agent_loop.run_episode(episode, adapter, template,
                           evidence_chain=None, e2_enabled=e2)

    if not adapter.contexts:
        raise WorkloadDeterminismFailure(
            "no context captured; episode produced no model call")
    return adapter.contexts[-1], e2, max_tokens, temperature_q16


def _build_request_bytes(context, max_tokens, temperature_q16):
    """Assemble the request byte stream ONCE (addendum sharpening 1). The
    same bytes object is fired both times, so request byte-identity is
    guaranteed by construction and any divergence is response-side."""
    prompt = context.encode()
    hdr = (b"max_tokens: %d\ntemperature_q16: %d\nprompt_len: %d\n\n"
           % (max_tokens, temperature_q16, len(prompt)))
    return hdr + prompt


def _assert_request_identity(sent_hash_a, sent_hash_b, where):
    """W2: the two fires of a pair must have written byte-identical
    requests. Compares the SHA-256 of what each _fire_raw actually wrote,
    not an argument to itself (the prior form was vacuous, the B1 class).
    A divergence is a RUNNER finding, harness-side send nondeterminism,
    surfaced not buried and never attributed to the backend."""
    if sent_hash_a != sent_hash_b:
        raise WorkloadDeterminismFailure(
            "request bytes differ between the two %s fires (sent hashes "
            "%s vs %s): harness-side send is nondeterministic. This is a "
            "RUNNER finding, not a backend one." %
            (where, sent_hash_a[:12], sent_hash_b[:12]))


def _assert_serving_attested(hdr_1, hdr_2, temperature_q16, where):
    """W1 (blocking): the preconditions must be ENFORCED, not merely
    recorded. Before any body comparison, require that both fires of a
    pair attest their serving: a snapshot id present and constant, and a
    served temperature present and equal to the pin. A missing field
    (None) or a mid-run swap halts hard, matching the smoke harness's
    UNREPORTED halt. Without this the check can read DETERMINISTIC while
    the gateway attests nothing, which is the 11:07 unpinned run
    recurring one layer up."""
    for tag, h in ((where + " fire 1", hdr_1), (where + " fire 2", hdr_2)):
        snap = h.get("snapshot_id")
        temp = h.get("temperature_q16")
        if not snap:
            raise WorkloadDeterminismFailure(
                "%s: no snapshot_id in the gateway response. The gateway "
                "attests nothing about which model served; the check is "
                "not dischargeable." % tag)
        if temp is None:
            raise WorkloadDeterminismFailure(
                "%s: no served temperature_q16 in the gateway response. "
                "Serving is unattested; refusing to read a verdict." % tag)
        if temp != str(temperature_q16):
            raise WorkloadDeterminismFailure(
                "%s: served temperature %s is not the pinned %d. The "
                "backend served something other than the pin; determinism "
                "is not established." % (tag, temp, temperature_q16))
    if hdr_1.get("snapshot_id") != hdr_2.get("snapshot_id"):
        raise WorkloadDeterminismFailure(
            "%s: snapshot id changed between the two fires (%s -> %s). A "
            "mid-run snapshot swap invalidates the comparison; identical "
            "bodies across different snapshots is not determinism." %
            (where, hdr_1.get("snapshot_id"), hdr_2.get("snapshot_id")))


def run_check(socket_path, template_index=None, root_seed=None,
              max_tokens=512, temperature_q16=0):
    if root_seed is None:
        root_seed = rig.STAGE0_ROOT_SEED
    if template_index is None:
        # an E2-exercising template: pick a REUSE_STALE (longer walk)
        templates = battery.templates()
        template_index = next(
            i for i, t in enumerate(templates)
            if t["family"] == "REUSE_STALE")

    # Capture the deepest real-episode context (worst case, E2 padded).
    context, e2, mt, tq = _capture_deepest_context(
        socket_path, template_index, root_seed, max_tokens, temperature_q16)

    # Assemble the request ONCE; the same bytes fire both times.
    request_bytes = _build_request_bytes(context, mt, tq)

    record = {
        "context_len": len(context),
        "request_len": len(request_bytes),
        "e2": e2,
        "template_index": template_index,
        "max_tokens": mt,
        "temperature_q16": tq,
    }

    # --- back-to-back (the floor) ---
    raw_a1, body_a1, hdr_a1, sh_a1 = _fire_raw(socket_path, request_bytes)
    raw_a2, body_a2, hdr_a2, sh_a2 = _fire_raw(socket_path, request_bytes)
    # W2: request identity from what was actually sent, before response
    _assert_request_identity(sh_a1, sh_a2, "back-to-back")
    # W1: serving attested and pinned, before any body comparison
    _assert_serving_attested(hdr_a1, hdr_a2, tq, "back-to-back")
    back_to_back_identical = (body_a1 == body_a2)
    record["back_to_back"] = {
        "identical": back_to_back_identical,
        "body_len": len(body_a1),
        "sent_hash": sh_a1,
        "seq_1": hdr_a1.get("seq"),
        "seq_2": hdr_a2.get("seq"),
        "obs_hash_1": hdr_a1.get("obs_hash"),
        "obs_hash_2": hdr_a2.get("obs_hash"),
        "snapshot_1": hdr_a1.get("snapshot_id"),
        "snapshot_2": hdr_a2.get("snapshot_id"),
        "temperature_1": hdr_a1.get("temperature_q16"),
        "temperature_2": hdr_a2.get("temperature_q16"),
    }

    # --- separated (the real bar) ---
    raw_s1, body_s1, hdr_s1, sh_s1 = _fire_raw(socket_path, request_bytes)
    _interleave = _build_request_bytes(
        "Unrelated interleaved request: name three rivers.", 64, 0)
    _fire_raw(socket_path, _interleave)
    raw_s2, body_s2, hdr_s2, sh_s2 = _fire_raw(socket_path, request_bytes)
    _assert_request_identity(sh_s1, sh_s2, "separated")
    _assert_serving_attested(hdr_s1, hdr_s2, tq, "separated")
    separated_identical = (body_s1 == body_s2)
    record["separated"] = {
        "identical": separated_identical,
        "body_len": len(body_s1),
        "sent_hash": sh_s1,
        "seq_1": hdr_s1.get("seq"),
        "seq_2": hdr_s2.get("seq"),
        "obs_hash_1": hdr_s1.get("obs_hash"),
        "obs_hash_2": hdr_s2.get("obs_hash"),
        "snapshot_1": hdr_s1.get("snapshot_id"),
        "snapshot_2": hdr_s2.get("snapshot_id"),
        "temperature_1": hdr_s1.get("temperature_q16"),
        "temperature_2": hdr_s2.get("temperature_q16"),
    }

    # W1, run-level half: one snapshot across the RUN, not merely within
    # each pair. Pair-level constancy alone admits back-to-back on snap-A
    # and separated on snap-B, and a DETERMINISTIC verdict there asserts
    # workload determinism about two different backends, each probed by
    # only one pair (the Chair R2 targeted probe). Asserted, not left for
    # a careful reader of the record to notice.
    run_snapshots = {hdr_a1.get("snapshot_id"), hdr_a2.get("snapshot_id"),
                     hdr_s1.get("snapshot_id"), hdr_s2.get("snapshot_id")}
    if len(run_snapshots) != 1:
        raise WorkloadDeterminismFailure(
            "run-level snapshot precondition failed: the four fires span "
            "more than one snapshot (%s). Each pair may be internally "
            "constant, but the run probed more than one backend; no "
            "single determinism verdict is readable." %
            ", ".join(sorted(str(s) for s in run_snapshots)))

    # verdict: BOTH modes must be identical (addendum ruling: separated is
    # the bar, back-to-back the floor, recorded separately).
    record["verdict"] = (
        "DETERMINISTIC" if (back_to_back_identical and separated_identical)
        else "NONDETERMINISTIC")
    return record


def write_record(record, out_path):
    r = record
    lines = []
    lines.append("# EXP-1 workload-determinism check: run record")
    lines.append("")
    lines.append("Determinism of the backend on the REAL workload at "
                 "maximum context depth, across batch separation. Not a "
                 "witness report; nothing committed.")
    lines.append("")
    lines.append("## Input under test")
    lines.append("")
    lines.append("The captured context bytes at a real episode's final "
                 "model call, E2 padding included (the worst case, not a "
                 "first-turn prompt). Template index %d (E2 %s). Context "
                 "%d bytes, request %d bytes, temperature_q16 %d, "
                 "max_tokens %d."
                 % (r["template_index"], "on" if r["e2"] else "off",
                    r["context_len"], r["request_len"],
                    r["temperature_q16"], r["max_tokens"]))
    lines.append("")
    lines.append("Request bytes assembled ONCE and fired verbatim both "
                 "times, so request byte-identity holds by construction "
                 "and any divergence is response-side, not harness "
                 "assembly.")
    lines.append("")
    lines.append("## Back-to-back (the floor)")
    lines.append("")
    b = r["back_to_back"]
    lines.append("Two fires, nothing between. Response byte-identical: %s. "
                 "Body %d bytes. Gateway record: seq %s then %s, obs_hash "
                 "%s then %s, snapshot %s, served temperature %s."
                 % ("YES" if b["identical"] else "NO", b["body_len"],
                    b["seq_1"], b["seq_2"], b["obs_hash_1"], b["obs_hash_2"],
                    b["snapshot_1"], b["temperature_1"]))
    lines.append("")
    lines.append("## Separated (the bar)")
    lines.append("")
    s = r["separated"]
    lines.append("Two workload fires with an unrelated request between, so "
                 "a snapshot swap or backend state carry would show. "
                 "Response byte-identical: %s. Body %d bytes. Gateway "
                 "record: seq %s then %s, obs_hash %s then %s, snapshot "
                 "%s, served temperature %s."
                 % ("YES" if s["identical"] else "NO", s["body_len"],
                    s["seq_1"], s["seq_2"], s["obs_hash_1"], s["obs_hash_2"],
                    s["snapshot_1"], s["temperature_1"]))
    lines.append("")
    lines.append("The seq values above index the gateway's own per-request "
                 "intent record (G1). The WAL intent line at each seq "
                 "carries input_hash (ax_compute_input_hash over the "
                 "prompt); obs_hash covers input, output and seq together "
                 "so it differs across fires by construction and is NOT the "
                 "identity field. To check \"same prompt fired twice\" from "
                 "the gateway's record, compare input_hash at the two seqs, "
                 "which must match; the harness-side sent-request SHA-256 "
                 "(%s) is the primary identity check and holds already."
                 % r["back_to_back"]["sent_hash"][:16])
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    lines.append("%s. Both back-to-back and separated recorded above; the "
                 "verdict requires both identical. A back-to-back pass with "
                 "a separated divergence is a diagnostic outcome, recorded "
                 "separately, not collapsed." % r["verdict"])
    lines.append("")
    lines.append("Spey Systems Ltd (SC889983).")
    with open(out_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="EXP-1 workload-determinism check")
    ap.add_argument("--socket", default=os.environ.get(
        "EXP1_GATEWAY_SOCKET"))
    ap.add_argument("--out", default="workload-determinism-note.md")
    ap.add_argument("--max-tokens", type=int, default=512)
    ap.add_argument("--template", type=int, default=None)
    args = ap.parse_args(argv)
    if not args.socket:
        ap.error("no gateway socket: set --socket or EXP1_GATEWAY_SOCKET")

    try:
        record = run_check(args.socket, template_index=args.template,
                           max_tokens=args.max_tokens)
    except WorkloadDeterminismFailure as e:
        # B4 pattern from the smoke harness: the note records the named
        # precondition failure, not a verdict; the harness refuses a
        # clean exit.
        with open(args.out, "w") as fh:
            fh.write("# EXP-1 workload-determinism check: run record\n\n"
                     "## RUN NOT DISCHARGEABLE\n\nA hard precondition "
                     "failed; no verdict is read.\n\n    %s\n\n"
                     "Spey Systems Ltd (SC889983).\n" % e)
        print("workload-determinism check HALTED: %s" % e, file=sys.stderr)
        return 2
    write_record(record, args.out)
    print("workload-determinism check complete: %s" % record["verdict"])
    print("  back-to-back identical: %s" %
          record["back_to_back"]["identical"])
    print("  separated identical:    %s" % record["separated"]["identical"])
    print("  note written to %s" % args.out)
    return 0 if record["verdict"] == "DETERMINISTIC" else 1


if __name__ == "__main__":
    sys.exit(main())
