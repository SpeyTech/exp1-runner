# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Spey Systems Ltd (SC889983)
"""Golden vectors for the serving-determinism witness checker. Every
enforced check earns one; the negative cases are not optional. Fixtures
are written through runner.chain (the independent implementation of the
same construction), so a green run also cross-validates the checker's
own narrow reader against chain.py frame for frame and head for head."""

import hashlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from runner import chain as chain_mod           # noqa: E402
from runner import detwitness as dw             # noqa: E402

PIN = 0
MODEL = "claude-haiku-4-5-20251001"

failures = 0


def check(cond, name):
    global failures
    print("  %-58s %s" % (name, "PASS" if cond else "FAIL"))
    if not cond:
        failures += 1


def obs_payload(seq, input_hash, output, model=MODEL, temp=PIN,
                completion="COMPLETE", failure=None):
    """Fixture in the emitter of record's value domain (W-D2a):
    failure_type is null for the no-failure case, never the string
    "NULL" (canonical.c:315); params fields are number-or-null."""
    body = output.encode("utf-8")
    rec = {
        "completion_state": completion,
        "failure_type": failure,
        "input_hash": input_hash,
        "ledger_seq": seq,
        "model_id": model,
        "obs_hash": hashlib.sha256(
            (input_hash + output + str(seq)).encode()).hexdigest(),
        "oracle_id": "anthropic-messages-api",
        "output": output,
        "output_size": len(body),
        "params": {"max_tokens": 512, "seed": None,
                   "temperature": temp, "top_p": None},
        "schema_version": "AX:OBS:v1",
    }
    # canonical (JCS over these value types) form: sorted keys, minimal
    # separators, matching ax_obs_canonicalise field order
    return json.dumps(rec, sort_keys=True,
                      separators=(",", ":")).encode("utf-8"), rec


def build_export(records):
    """records: list of (seq, payload_bytes) in seq order starting at 1.
    Returns (export_bytes, heads_by_seq)."""
    path = tempfile.mktemp(prefix="dw-vec-")
    c = chain_mod.EvidenceChain(path)
    heads = {}
    for seq, payload in records:
        head, got_seq = c.append(chain_mod.TAG_OBS, payload)
        assert got_seq == seq, (got_seq, seq)
        heads[seq] = head.hex()
    with open(path, "rb") as fh:
        data = fh.read()
    os.unlink(path)
    return data, heads


IH = hashlib.sha256(b"the deepest context").hexdigest()
OUT = "call ticket_read(fired-workload-output)"


def clean_pair(out_recorded=OUT, out_refire=OUT, model_refire=MODEL,
               temp_refire=PIN):
    p1, r1 = obs_payload(1, IH, out_recorded)
    p2, r2 = obs_payload(2, IH, out_refire, model=model_refire,
                         temp=temp_refire)
    export, heads = build_export([(1, p1), (2, p2)])
    wire = dw.reconstruct_wire_response(r1, heads[1])
    call = {
        "call_id": "c0",
        "recorded_seq": 1, "refire_seq": 2,
        "recorded_chain_head": heads[1], "refire_chain_head": heads[2],
        "runner_response_hash": hashlib.sha256(wire).hexdigest(),
        "recorded_body": out_recorded.encode("utf-8"),
        "refire_body": out_refire.encode("utf-8"),
    }
    return export, call


print("runner: test_detwitness")

# 1. golden positive: clean pair verdicts DETERMINISTIC
export, call = clean_pair()
rep = dw.check_witness(export, [call], PIN)
check(rep["verdict"] == dw.VERDICT_DET, "clean pair: DETERMINISTIC")

# 2. byte-determinism: two runs render identical bytes
rep2 = dw.check_witness(export, [call], PIN)
check(dw.render_report(rep) == dw.render_report(rep2),
      "byte-determinism across two runs")

# 3. divergent attested output: VOID
export, call = clean_pair(out_refire=OUT + "?")
call["refire_body"] = (OUT + "?").encode("utf-8")
rep = dw.check_witness(export, [call], PIN)
check(rep["verdict"] == dw.VERDICT_VOID
      and "assertion 2b" in rep["reasons"][0],
      "divergent output: VOID via 2b")

# 4. swapped snapshot between run and witness: NOT-DISCHARGEABLE
export, call = clean_pair(model_refire="claude-haiku-4-6-newer")
rep = dw.check_witness(export, [call], PIN)
check(rep["verdict"] == dw.VERDICT_ND
      and "snapshot changed" in rep["reasons"][0],
      "swapped snapshot: NOT-DISCHARGEABLE")

# 5. served temperature off the pin: NOT-DISCHARGEABLE
export, call = clean_pair(temp_refire=6554)
rep = dw.check_witness(export, [call], PIN)
check(rep["verdict"] == dw.VERDICT_ND
      and "temperature" in rep["reasons"][0],
      "off-pin temperature: NOT-DISCHARGEABLE")

# 6. doctored export byte: NOT-DISCHARGEABLE at the reader
export, call = clean_pair()
doctored = bytearray(export)
doctored[len(doctored) // 2] ^= 0x01
rep = dw.check_witness(bytes(doctored), [call], PIN)
check(rep["verdict"] == dw.VERDICT_ND and "export:" in rep["reasons"][0],
      "doctored export frame: NOT-DISCHARGEABLE (tamper gate)")

# 7. truncated export (torn tail): NOT-DISCHARGEABLE
rep = dw.check_witness(export[:-7], [call], PIN)
check(rep["verdict"] == dw.VERDICT_ND, "torn export tail: NOT-DISCHARGEABLE")

# 8. missing obs at cited seq: NOT-DISCHARGEABLE
export, call = clean_pair()
call["refire_seq"] = 9
rep = dw.check_witness(export, [call], PIN)
check(rep["verdict"] == dw.VERDICT_ND and "no obs record" in rep["reasons"][0],
      "missing obs at seq: NOT-DISCHARGEABLE")

# 9. chain_head echo mismatch: NOT-DISCHARGEABLE (stale or wrong export)
export, call = clean_pair()
call["recorded_chain_head"] = "00" * 32
rep = dw.check_witness(export, [call], PIN)
check(rep["verdict"] == dw.VERDICT_ND and "echo" in rep["reasons"][0],
      "chain_head echo mismatch: NOT-DISCHARGEABLE")

# 10. cross-bind mismatch: NOT-DISCHARGEABLE, named as evidence-path
export, call = clean_pair()
call["runner_response_hash"] = "11" * 32
rep = dw.check_witness(export, [call], PIN)
check(rep["verdict"] == dw.VERDICT_ND
      and "cross-bind" in rep["reasons"][0],
      "cross-bind mismatch: NOT-DISCHARGEABLE")

# 11. assertion 1 miss (reconstruction fault): NOT-DISCHARGEABLE, runner
p1, r1 = obs_payload(1, IH, OUT)
p2, _ = obs_payload(2, hashlib.sha256(b"other").hexdigest(), OUT)
export, heads = build_export([(1, p1), (2, p2)])
wire = dw.reconstruct_wire_response(r1, heads[1])
call = {"call_id": "c0", "recorded_seq": 1, "refire_seq": 2,
        "recorded_chain_head": heads[1], "refire_chain_head": heads[2],
        "runner_response_hash": hashlib.sha256(wire).hexdigest(),
        "recorded_body": OUT.encode(), "refire_body": OUT.encode()}
rep = dw.check_witness(export, [call], PIN)
check(rep["verdict"] == dw.VERDICT_ND
      and "RUNNER" in rep["reasons"][0],
      "assertion 1 miss: NOT-DISCHARGEABLE, runner-attributed")

# 12. 2a diverges with 2b equal: NOT-DISCHARGEABLE, named (derived
#     semantics; wire body is the normalised output, so this is
#     evidence-path disagreement, not line endings)
export, call = clean_pair()
call["refire_body"] = (OUT + "!").encode("utf-8")
rep = dw.check_witness(export, [call], PIN)
check(rep["verdict"] == dw.VERDICT_ND
      and "2a diverged with 2b equal" in rep["reasons"][0],
      "2a/2b split: NOT-DISCHARGEABLE, named")

# 13. transcript body disagrees with recorded obs output: ND
export, call = clean_pair()
call["recorded_body"] = b"something else entirely"
call["refire_body"] = b"something else entirely"
rep = dw.check_witness(export, [call], PIN)
check(rep["verdict"] == dw.VERDICT_ND, "transcript vs obs disagreement: ND")

# 14. hostile obs payload shapes: reason, never an exception
for hostile in (b"not json", b"[1,2,3]", b'{"a":1}',
                json.dumps({k: "" for k in
                            ("completion_state", "failure_type",
                             "input_hash", "ledger_seq", "model_id",
                             "obs_hash", "oracle_id", "output",
                             "output_size", "params",
                             "schema_version")}).encode()):
    rec, why = dw.parse_obs(hostile)
    if not (rec is None and isinstance(why, str)):
        check(False, "hostile obs shape rejected with reason")
        break
else:
    check(True, "hostile obs shapes rejected with reasons, no exception")

# 15. hostile export bytes: reason, never an exception
for hostile in (b"", b"\x00" * 40, os.urandom(200)):
    frames, heads, why = dw.read_export(hostile)
    if hostile == b"":
        if not (frames == [] and why is None):
            check(False, "empty export reads as empty chain")
            break
    elif not (frames is None and isinstance(why, str)):
        check(False, "hostile export rejected with reason")
        break
else:
    check(True, "hostile export bytes handled, no exception")

# 16. multi-call precedence: one VOID call plus one clean call -> VOID;
#     one ND call dominates VOID
e1, c1 = clean_pair()
_, c_void = clean_pair(out_refire=OUT + "?")
# rebuild a single export carrying all four records
p1, r1 = obs_payload(1, IH, OUT)
p2, _ = obs_payload(2, IH, OUT)
p3, r3 = obs_payload(3, IH, OUT)
p4, _ = obs_payload(4, IH, OUT + "?")
export, heads = build_export([(1, p1), (2, p2), (3, p3), (4, p4)])
mk = lambda cid, a, b, rec, out_a, out_b: {
    "call_id": cid, "recorded_seq": a, "refire_seq": b,
    "recorded_chain_head": heads[a], "refire_chain_head": heads[b],
    "runner_response_hash": hashlib.sha256(
        dw.reconstruct_wire_response(rec, heads[a])).hexdigest(),
    "recorded_body": out_a.encode(), "refire_body": out_b.encode()}
clean = mk("clean", 1, 2, r1, OUT, OUT)
void = mk("void", 3, 4, r3, OUT, OUT + "?")
rep = dw.check_witness(export, [clean, void], PIN)
check(rep["verdict"] == dw.VERDICT_VOID, "precedence: VOID over clean")
nd = dict(void)
nd["runner_response_hash"] = "22" * 32
rep = dw.check_witness(export, [clean, void, nd], PIN)
check(rep["verdict"] == dw.VERDICT_ND, "precedence: ND over VOID")

# 17. W-D2a item 4: a null served temperature is a VALID record shape
#     (an unpinned serve, canonical.c:266) and must verdict
#     NOT-DISCHARGEABLE at the pin precondition, never crash and never
#     pass. This is the G1 unpinned-serving class arriving through the
#     record rather than the header.
export, call = clean_pair(temp_refire=None)
rep = dw.check_witness(export, [call], PIN)
check(rep["verdict"] == dw.VERDICT_ND
      and "temperature" in rep["reasons"][0],
      "null served temperature: NOT-DISCHARGEABLE at the pin")

# 18. the phantom form: failure_type as the string "NULL" is a byte
#     sequence the emitter of record cannot produce (canonical.c:315)
#     and must be rejected at parse, with a reason
p_bad, _ = obs_payload(1, IH, OUT)
p_bad = p_bad.replace(b'"failure_type":null', b'"failure_type":"NULL"')
rec, why = dw.parse_obs(p_bad)
check(rec is None and "canonical.c:315" in why,
      "failure_type string NULL rejected as non-emitter form")

# 19. a real failure string parses (the emitter's other branch), and a
#     non-COMPLETE record verdicts ND at the precondition
p1, r1 = obs_payload(1, IH, OUT)
p2, _ = obs_payload(2, IH, "x", completion="ERROR", failure="TIMEOUT")
export, heads = build_export([(1, p1), (2, p2)])
wire = dw.reconstruct_wire_response(r1, heads[1])
call = {"call_id": "c0", "recorded_seq": 1, "refire_seq": 2,
        "recorded_chain_head": heads[1], "refire_chain_head": heads[2],
        "runner_response_hash": hashlib.sha256(wire).hexdigest(),
        "recorded_body": OUT.encode(), "refire_body": b"x"}
rep = dw.check_witness(export, [call], PIN)
check(rep["verdict"] == dw.VERDICT_ND
      and "COMPLETE" in rep["reasons"][0],
      "TIMEOUT/ERROR refire: ND at completion precondition")

# 20. W-D2a item 3: the real-emitter golden vector. Runs when a real
#     export exists (the Chair's session artefact or the VM's deployed
#     export via EXP1_REAL_EXPORT); every frame must replay, every obs
#     record must parse under the emitter-domain shapes above. Reported
#     NOT-RUN, never silently green, when the artefact is absent.
real = os.environ.get("EXP1_REAL_EXPORT")
if real and os.path.exists(real):
    with open(real, "rb") as fh:
        data = fh.read()
    frames, heads_l, why = dw.read_export(data)
    ok = frames is not None
    parsed = 0
    if ok:
        for tag, payload in frames:
            if tag == b"AX:OBS:v1":
                rec, why = dw.parse_obs(payload)
                if rec is None:
                    ok = False
                    break
                parsed += 1
    check(ok and parsed > 0,
          "real-emitter export: %d obs records parse (%s)"
          % (parsed, why or "clean"))
else:
    print("  %-58s %s" % (
        "real-emitter export vector (EXP1_REAL_EXPORT unset)", "NOT-RUN"))

print()
if failures:
    print("FAILURES: %d" % failures)
    sys.exit(1)
print("all detwitness vectors pass")
