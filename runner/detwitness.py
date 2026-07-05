# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Spey Systems Ltd (SC889983)
"""Serving-determinism witness checker (Chair brief and final ruling,
2026-07-05). D1-class conduction code: Python 3 stdlib only, pure over
its inputs, no float anywhere, verdicts and never exceptions on hostile
input.

The witness form is recorded-prompt refire (Chair ruling): for each
witnessed call, the request is reconstructed from committed evidence and
refired under the same pin and snapshot; this checker adjudicates the
result from the gateway's export ledger plus the runner-side committed
hashes and transcript bodies. Two assertions per call, in order:

  1   reconstruction: the refire's gateway input_hash equals the
      recorded call's input_hash. A miss is a RUNNER finding
      (reconstruction fault), NOT-DISCHARGEABLE, never a serving verdict.
  2a  raw layer: the refire's wire body equals the recorded transcript's
      body (runner-witnessed route).
  2b  attested layer: gateway obs output equality across the recorded
      and refire records (gateway-witnessed route).

Determinism semantics, cited (F2, validate.c SRS-004-SHALL-042/043):
UTF-8 validity, forbidden control characters, and NFC are all
validate-and-reject, byte-preserving; line-ending normalisation is the
single transform. Obs-record equality therefore proves serving
determinism modulo exactly that transform.

Derived note on the 2a/2b relationship (ratified by the Chair witness of
2026-07-05 at gw_main.c:508, superseding the ruling's line-endings
diagnostic, defect ten): the wire body the gateway serves IS the normalised output (the
same bytes committed to the obs record; gw_main.c writes `output`), so
2a and 2b are two independent evidence routes to the same normalised
bytes, runner-witnessed and gateway-witnessed respectively. Consequence:
2b divergence is a serving-determinism failure (VOID); 2a divergence
with 2b equality means a committed transcript disagrees with the
gateway's attested serve, which is evidence-path corruption, not line
endings, and verdicts NOT-DISCHARGEABLE with the reason named.

Dual attestation (cross-bind): for the recorded call, the wire response
is reconstructed from the export record (the response header is a fixed
format, gw_main.c) and its SHA-256 must equal the runner chain's
committed response_hash. Neither party can unilaterally misreport what
was served. A mismatch is NOT-DISCHARGEABLE and halts loudly.

Export trust: the export is a checkable projection of the primary. This
checker replays its full chain (recomputing every frame commit and every
link from genesis) and verifies the head at each cited seq against the
serve-time chain_head echo. An unreadable, stale, torn, or
integrity-failing export is NOT-DISCHARGEABLE.

Verdicts:
  DETERMINISTIC       every witnessed call passes 1, 2a, 2b
  VOID                2b fails under matched snapshot and pin
  NOT-DISCHARGEABLE   the witness cannot run or cannot be trusted
Precedence: NOT-DISCHARGEABLE > VOID > DETERMINISTIC.
"""

import hashlib
import json
import struct

# Frame and chain constants, cited from gw_ledger.h (frame form) and
# DVEC-001 v1.4 section 4.4 (registry, chain tag). This is the checker's
# own narrow reader; it deliberately does not import runner.chain.
_CHAIN_TAG = b"AX:LEDGER:v1"
_GENESIS_TAG = b"AX:STATE:v1"
_GENESIS_PAYLOAD = (
    b'{"component":"axilog-core",'
    b'"evidence_type":"AX:STATE:v1",'
    b'"is_terminal":false,'
    b'"platform":"universal",'
    b'"state_hash":"' + b"0" * 64 + b'"}'
)
_TAG_MAX = 32
_PAYLOAD_MAX = 256 * 1024
_REGISTERED = frozenset({
    b"AX:STATE:v1", b"AX:TRANS:v1", b"AX:OBS:v1", b"AX:POLICY:v1",
    b"AX:PROOF:v1", b"AX:FCC:C:v1", b"AX:FCC:TS:v1", b"AX:FCC:DEV:v1",
    b"AX:FCC:REG:v1", b"AX:FCC:VERDICT:v1"})

_OBS_KEYS = ("completion_state", "failure_type", "input_hash",
             "ledger_seq", "model_id", "obs_hash", "oracle_id", "output",
             "output_size", "params", "schema_version")
_PARAM_KEYS = ("max_tokens", "seed", "temperature", "top_p")

VERDICT_DET = "DETERMINISTIC"
VERDICT_VOID = "VOID"
VERDICT_ND = "NOT-DISCHARGEABLE"

_PRECEDENCE = {VERDICT_ND: 2, VERDICT_VOID: 1, VERDICT_DET: 0}


def _commit(tag: bytes, payload: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(tag)
    h.update(struct.pack("<Q", len(payload)))
    h.update(payload)
    return h.digest()


def _genesis_head() -> bytes:
    e0 = _commit(_GENESIS_TAG, _GENESIS_PAYLOAD)
    return hashlib.sha256(_CHAIN_TAG + e0).digest()


def _extend(prev: bytes, cmt: bytes) -> bytes:
    return hashlib.sha256(_CHAIN_TAG + prev + cmt).digest()


def read_export(data: bytes):
    """Replay the export bytes from genesis. Returns (frames, heads,
    None) on success where frames is a list of (tag, payload) and
    heads[i] is the chain head AFTER frame i (seq i+1), or
    (None, None, reason) on any integrity failure. Never raises on
    hostile bytes."""
    frames = []
    heads = []
    head = _genesis_head()
    off = 0
    n = len(data)
    while off < n:
        start = off
        if n - off < 4:
            return None, None, "torn frame header at %d" % start
        (tag_len,) = struct.unpack_from("<I", data, off)
        off += 4
        if tag_len == 0 or tag_len > _TAG_MAX:
            return None, None, "bad tag_len %d at %d" % (tag_len, start)
        if n - off < tag_len:
            return None, None, "torn tag at %d" % start
        tag = data[off:off + tag_len]
        off += tag_len
        if tag not in _REGISTERED:
            return None, None, "unregistered tag at %d" % start
        if n - off < 8:
            return None, None, "torn payload_len at %d" % start
        (plen,) = struct.unpack_from("<Q", data, off)
        off += 8
        if plen == 0 or plen > _PAYLOAD_MAX:
            return None, None, "bad payload_len %d at %d" % (plen, start)
        if n - off < plen:
            return None, None, "torn payload at %d" % start
        payload = data[off:off + plen]
        off += plen
        if n - off < 32:
            return None, None, "torn commit at %d" % start
        stored = data[off:off + 32]
        off += 32
        computed = _commit(tag, payload)
        if computed != stored:
            return None, None, "commit mismatch at %d (tampered)" % start
        head = _extend(head, computed)
        frames.append((tag, payload))
        heads.append(head)
    return frames, heads, None


def parse_obs(payload: bytes):
    """Strict-shape parse of a canonical AX:OBS:v1 gateway record.
    Returns (record_dict, None) or (None, reason). The canonical form is
    JCS and therefore JSON; the shape is enforced against the emitter of
    record, ax_obs_canonicalise, field for field (W-D2a fold, Chair
    witness 2026-07-05):

      failure_type is string-or-null: canonical.c:315 writes null for
      the no-failure case and one of TIMEOUT, INVALID_OUTPUT,
      TRANSPORT_ERROR otherwise. A "NULL" string is a byte sequence the
      emitter cannot produce and is rejected here.

      every params field is number-or-null: canonical.c:250 to 278
      write null for unset and an integer otherwise. In particular a
      null temperature is a VALID record shape (an unpinned serve) and
      must reach the pin precondition, which verdicts it
      NOT-DISCHARGEABLE; it must never be a parse crash.

      completion_state is one of COMPLETE, TRUNCATED, ERROR
      (write_completion_state emits only these).

    Hostile shapes get a reason, never an exception."""
    try:
        rec = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, "obs payload is not valid JSON"
    if not isinstance(rec, dict):
        return None, "obs payload is not an object"
    if tuple(sorted(rec.keys())) != _OBS_KEYS:
        return None, "obs keys do not match AX:OBS:v1 schema"
    if rec["schema_version"] != "AX:OBS:v1":
        return None, "schema_version is not AX:OBS:v1"
    for k in ("input_hash", "model_id", "obs_hash", "oracle_id",
              "output"):
        if not isinstance(rec[k], str):
            return None, "obs field %s is not a string" % k
    if rec["completion_state"] not in ("COMPLETE", "TRUNCATED", "ERROR"):
        return None, "completion_state outside the emitter's enum"
    if rec["failure_type"] is not None and rec["failure_type"] not in (
            "TIMEOUT", "INVALID_OUTPUT", "TRANSPORT_ERROR"):
        return None, ("failure_type is neither null nor an emitter "
                      "failure string (canonical.c:315)")
    for k in ("ledger_seq", "output_size"):
        if not isinstance(rec[k], int) or isinstance(rec[k], bool):
            return None, "obs field %s is not an integer" % k
    p = rec["params"]
    if not isinstance(p, dict) or tuple(sorted(p.keys())) != _PARAM_KEYS:
        return None, "obs params do not match schema"
    for k in _PARAM_KEYS:
        if p[k] is not None and (not isinstance(p[k], int)
                                 or isinstance(p[k], bool)):
            return None, ("obs param %s is neither null nor integer "
                          "(canonical.c:250-278)" % k)
    if len(rec["input_hash"]) != 64:
        return None, "input_hash is not 64 hex chars"
    if rec["output_size"] != len(rec["output"].encode("utf-8")):
        return None, "output_size disagrees with output"
    return rec, None


def reconstruct_wire_response(rec: dict, chain_head_hex: str) -> bytes:
    """The exact bytes the gateway wrote to the socket for this record:
    the fixed header format from gw_main.c (status, completion_state,
    failure_type, obs_hash, chain_head, seq, snapshot_id,
    temperature_q16, output_len, blank line) followed by the output.
    snapshot_id echoes model_id; temperature echoes params.temperature,
    "null" when unpinned; status is ok iff completion COMPLETE. Note the
    value-domain seam (W-D2a): the RECORD carries failure_type null for
    the no-failure case (canonical.c:315), but the WIRE header prints
    the enum string NULL (gw_main.c format ternary); this function maps
    between them."""
    temp = rec["params"]["temperature"]
    temp_str = "null" if temp is None else str(temp)
    status = "ok" if rec["completion_state"] == "COMPLETE" else "error"
    ftype = "NULL" if rec["failure_type"] is None else rec["failure_type"]
    body = rec["output"].encode("utf-8")
    hdr = ("status: %s\ncompletion_state: %s\nfailure_type: %s\n"
           "obs_hash: %s\nchain_head: %s\nseq: %d\n"
           "snapshot_id: %s\ntemperature_q16: %s\noutput_len: %d\n\n"
           % (status, rec["completion_state"], ftype,
              rec["obs_hash"], chain_head_hex, rec["ledger_seq"],
              rec["model_id"], temp_str, len(body)))
    return hdr.encode("utf-8") + body


def _nd(reasons, call_id, msg):
    reasons.append("call %s: %s" % (call_id, msg))
    return VERDICT_ND


def check_witness(export_bytes: bytes, calls, pinned_temperature_q16: int):
    """Adjudicate a witness run.

    calls: iterable of dicts, one per witnessed call:
      call_id                        str, for the report
      recorded_seq, refire_seq       int, gateway ledger seqs
      recorded_chain_head            hex str, serve-time echo, recorded run
      refire_chain_head              hex str, serve-time echo, refire
      runner_response_hash           hex str, the runner chain's committed
                                     SHA-256 of the recorded wire response
      recorded_body                  bytes, the recorded transcript body
      refire_body                    bytes, the refire's wire body

    Returns a report dict; report["verdict"] is the run verdict. Pure:
    same inputs, same bytes out (render_report)."""
    report = {"verdict": VERDICT_DET, "calls": [], "reasons": []}
    reasons = report["reasons"]

    frames, heads, why = read_export(export_bytes)
    if why is not None:
        report["verdict"] = VERDICT_ND
        reasons.append("export: %s" % why)
        return report

    # obs records by ledger seq (frame i carries seq i+1)
    obs_by_seq = {}
    for i, (tag, payload) in enumerate(frames):
        if tag == b"AX:OBS:v1":
            obs_by_seq[i + 1] = (payload, heads[i])

    worst = VERDICT_DET
    for c in calls:
        cid = str(c.get("call_id", "?"))
        entry = {"call_id": cid, "verdict": VERDICT_DET, "notes": []}
        v = VERDICT_DET

        def fail(kind, msg, entry=entry, cid=cid):
            entry["verdict"] = kind
            entry["notes"].append(msg)
            reasons.append("call %s: %s" % (cid, msg))
            return kind

        recs = {}
        for role, key in (("recorded", "recorded_seq"),
                          ("refire", "refire_seq")):
            seq = c.get(key)
            if not isinstance(seq, int) or seq not in obs_by_seq:
                v = fail(VERDICT_ND, "no obs record at %s seq %r"
                         % (role, seq))
                break
            payload, head = obs_by_seq[seq]
            rec, why = parse_obs(payload)
            if rec is None:
                v = fail(VERDICT_ND, "%s obs unparseable: %s" % (role, why))
                break
            echo = c.get(role + "_chain_head")
            if not isinstance(echo, str) or echo != head.hex():
                v = fail(VERDICT_ND,
                         "%s chain_head echo does not match export head "
                         "at seq %d" % (role, seq))
                break
            recs[role] = (rec, head)
        if v != VERDICT_DET:
            report["calls"].append(entry)
            worst = max(worst, v, key=lambda x: _PRECEDENCE[x])
            continue

        rec_r, head_r = recs["recorded"]
        rec_f, head_f = recs["refire"]

        # preconditions: snapshot matched, pin served, both fires COMPLETE
        if rec_r["model_id"] != rec_f["model_id"]:
            v = fail(VERDICT_ND, "snapshot changed between run and witness"
                     " (%s -> %s)" % (rec_r["model_id"], rec_f["model_id"]))
        elif rec_r["completion_state"] != "COMPLETE" \
                or rec_f["completion_state"] != "COMPLETE":
            v = fail(VERDICT_ND, "a witnessed record is not COMPLETE")
        elif rec_r["params"]["temperature"] != pinned_temperature_q16 \
                or rec_f["params"]["temperature"] != pinned_temperature_q16:
            v = fail(VERDICT_ND, "served temperature does not equal the "
                     "pin on both records")
        # dual attestation: reconstruct the recorded wire response and
        # cross-bind against the runner chain's committed hash
        elif not isinstance(c.get("runner_response_hash"), str) \
                or hashlib.sha256(
                    reconstruct_wire_response(rec_r, head_r.hex())
                ).hexdigest() != c["runner_response_hash"]:
            v = fail(VERDICT_ND, "cross-bind mismatch: runner-committed "
                     "response hash does not match the gateway record "
                     "(evidence-path corruption)")
        # assertion 1: reconstruction byte-exact per gateway testimony
        elif rec_r["input_hash"] != rec_f["input_hash"]:
            v = fail(VERDICT_ND, "assertion 1: refire input_hash differs "
                     "from recorded (RUNNER reconstruction fault, not a "
                     "serving verdict)")
        else:
            # assertion 2b first in the derivation order of trust: the
            # attested layer decides VOID; 2a then binds the transcripts.
            b2b_equal = rec_r["output"] == rec_f["output"]
            raw_equal = (c.get("recorded_body") == c.get("refire_body"))
            if not b2b_equal:
                v = fail(VERDICT_VOID, "assertion 2b: gateway-attested "
                         "outputs differ under matched snapshot and pin")
            elif not raw_equal:
                v = fail(VERDICT_ND, "assertion 2a diverged with 2b equal:"
                         " a committed transcript disagrees with the "
                         "gateway's attested serve (evidence-path "
                         "corruption, not line endings; the wire body is "
                         "the normalised output)")
            elif c.get("recorded_body") != rec_r["output"].encode("utf-8"):
                v = fail(VERDICT_ND, "recorded transcript body does not "
                         "match the recorded obs output")
        report["calls"].append(entry)
        worst = max(worst, v, key=lambda x: _PRECEDENCE[x])

    report["verdict"] = worst
    return report


def render_report(report: dict) -> bytes:
    """Deterministic byte rendering: same report, same bytes."""
    return json.dumps(report, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
