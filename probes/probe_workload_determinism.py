# Conduction-only probe harness for runner/workload_determinism.py.
# Not part of the deliverable tree. Re-runs the Chair's five mock-gateway
# cases, the R2 targeted sixth case (across-pair snapshot swap, the
# acceptance vector for the run-level W1 fold), and the CapturingAdapter
# demonstration (the acceptance vector for the wrapper fold).
#
# Expected: cases 1-3 verdict as before; cases 4-6 HALT with the named
# precondition; case 7 captures every context of a real run_episode
# through the wrapper with no signed file touched.

import os
import sys
import socket
import threading

REPO = os.path.expanduser("~/axilog/exp1-runner")
os.environ["EXP1_LIBRIG"] = os.path.join(REPO, "cshim/librig.so")
os.environ["EXP1_BATTERY"] = os.path.expanduser(
    "~/axilog/axioma-l0/exp1/battery/task-battery-v1.json")

sys.path.insert(0, REPO)

from runner import rig, battery, mock_tools, adapters, agent_loop  # noqa: E402
from runner import workload_determinism as wd  # noqa: E402


def compliant_plan(template_index):
    """The ScriptedAdapter walk for this episode: filler read before each
    predicate call, in order, then stop. The known-good compliant stream
    that passes the immunity gate."""
    ep = mock_tools.Episode(rig.STAGE0_ROOT_SEED, template_index, 0,
                            rig.X_REGIME_PROD)
    plan = []
    for verb_name, target in ep.predicate_calls():
        plan.append("call file_read(manifest.yaml)")
        plan.append("call %s(%s)" % (verb_name, target))
    return plan


class MockGateway(threading.Thread):
    """Speaks the gateway line protocol on a unix socket. Phase 1 plays
    the compliant scripted-model plan for the capture episode, then
    'stop'. Phase 2 classifies each request: the interleave probe (by its
    prompt content) gets a generic attested reply; workload fires are
    numbered 0..3 (b2b fire 1, b2b fire 2, separated fire 1, separated
    fire 2) and answered per the case's fire_behaviour(n) -> (body,
    snapshot_or_None, temp_or_None). None omits the header entirely."""

    def __init__(self, path, plan, fire_behaviour):
        super().__init__(daemon=True)
        self.path = path
        self.plan = list(plan)
        self.fire_behaviour = fire_behaviour
        self.plan_i = 0
        self.stop_served = False
        self.fire_i = 0
        self.seq = 0
        if os.path.exists(path):
            os.unlink(path)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        self.sock.listen(8)

    def run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                self.handle(conn)
            finally:
                conn.close()

    def read_request(self, conn):
        data = b""
        while b"\n\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                return None
            data += chunk
        head, rest = data.split(b"\n\n", 1)
        hdrs = {}
        for line in head.decode().splitlines():
            k, v = line.split(":", 1)
            hdrs[k.strip()] = v.strip()
        plen = int(hdrs["prompt_len"])
        while len(rest) < plen:
            chunk = conn.recv(65536)
            if not chunk:
                break
            rest += chunk
        return rest[:plen]

    def respond(self, conn, body, snapshot="mocksnap-A", temp="0"):
        self.seq += 1
        hdr = ["seq: %d" % self.seq,
               "obs_hash: obs%04d" % self.seq,
               "chain_head: head%04d" % self.seq]
        if snapshot is not None:
            hdr.append("snapshot_id: %s" % snapshot)
        if temp is not None:
            hdr.append("temperature_q16: %s" % temp)
        conn.sendall(("\n".join(hdr) + "\n\n").encode() + body.encode())

    def handle(self, conn):
        prompt = self.read_request(conn)
        if prompt is None:
            return
        if not self.stop_served:
            if self.plan_i < len(self.plan):
                body = self.plan[self.plan_i]
                self.plan_i += 1
            else:
                body = "stop"
                self.stop_served = True
            self.respond(conn, body)
            return
        if b"name three rivers" in prompt:
            self.respond(conn, "interleave reply")
            return
        n = self.fire_i
        self.fire_i += 1
        body, snapshot, temp = self.fire_behaviour(n)
        self.respond(conn, body, snapshot=snapshot, temp=temp)

    def close(self):
        self.sock.close()
        if os.path.exists(self.path):
            os.unlink(self.path)


TEMPLATE_INDEX = 7  # first REUSE_STALE, the harness default
PLAN = compliant_plan(TEMPLATE_INDEX)
CONST_BODY = "call ticket_read(fired-workload-output)"


def run_case(name, fire_behaviour, expect):
    path = "/tmp/wd-probe-%s.sock" % name
    gw = MockGateway(path, PLAN, fire_behaviour)
    gw.start()
    outcome = None
    err = None
    try:
        record = wd.run_check(path, template_index=TEMPLATE_INDEX,
                              max_tokens=512)
        outcome = ("VERDICT", record["verdict"],
                   record["back_to_back"]["identical"],
                   record["separated"]["identical"])
    except wd.WorkloadDeterminismFailure as e:
        outcome = ("HALT",)
        err = str(e)
    finally:
        gw.close()
    ok = outcome[0] == expect[0] and (
        expect[0] != "VERDICT" or outcome[1:] == expect[1:]) and (
        expect[0] != "HALT" or expect[1] in (err or ""))
    print("case %-18s -> %s%s   [%s]"
          % (name, outcome, (" :: " + err.split(".")[0]) if err else "",
             "PASS" if ok else "FAIL"))
    return ok


results = []

# 1. deterministic backend -> DETERMINISTIC
results.append(run_case(
    "deterministic",
    lambda n: (CONST_BODY, "mocksnap-A", "0"),
    ("VERDICT", "DETERMINISTIC", True, True)))

# 2. sampling backend -> NONDETERMINISTIC (both modes diverge)
results.append(run_case(
    "sampling",
    lambda n: ("sample-output-%d" % n, "mocksnap-A", "0"),
    ("VERDICT", "NONDETERMINISTIC", False, False)))

# 3. state carry: back-to-back identical, separated diverges ->
#    NONDETERMINISTIC with the two modes recorded separately
results.append(run_case(
    "state-carry",
    lambda n: (CONST_BODY if n < 3 else "carried-state-output",
               "mocksnap-A", "0"),
    ("VERDICT", "NONDETERMINISTIC", True, False)))

# 4. within-pair snapshot swap, bodies identical -> HALT (pair-level W1)
results.append(run_case(
    "within-pair-swap",
    lambda n: (CONST_BODY, "mocksnap-A" if n == 0 else "mocksnap-B", "0"),
    ("HALT", "snapshot id changed between the two fires")))

# 5. omitted snapshot/temperature headers on fires -> HALT (W1b)
results.append(run_case(
    "omitted-headers",
    lambda n: (CONST_BODY, None, None),
    ("HALT", "no snapshot_id in the gateway response")))

# 6. R2 targeted probe, fold 1's acceptance vector: within-pair constant,
#    back-to-back entirely on snap-A, separated entirely on snap-B,
#    bodies identical -> MUST HALT (previously read DETERMINISTIC)
results.append(run_case(
    "across-pair-swap",
    lambda n: (CONST_BODY, "mocksnap-A" if n < 2 else "mocksnap-B", "0"),
    ("HALT", "run-level snapshot precondition failed")))

# 7. Fold 2's acceptance vector: the CapturingAdapter drives the REAL
#    run_episode; every per-call context is seen at the adapter seam,
#    the last one is the final-call context, and no signed file is
#    touched (the probe only imports).
path = "/tmp/wd-probe-wrapper.sock"
gw = MockGateway(path, PLAN, lambda n: (CONST_BODY, "mocksnap-A", "0"))
gw.start()
try:
    templates = battery.templates()
    template = templates[TEMPLATE_INDEX]
    episode = mock_tools.Episode(rig.STAGE0_ROOT_SEED, TEMPLATE_INDEX, 0,
                                 rig.X_REGIME_PROD)
    cap = wd._CapturingAdapter(adapters.GatewayAdapter(
        path, temperature_q16=0, max_tokens=512))
    result = agent_loop.run_episode(episode, cap, template,
                                    evidence_chain=None, e2_enabled=True)
    n_calls = len(cap.contexts)
    lengths = [len(c) for c in cap.contexts]
    monotonic = all(a < b for a, b in zip(lengths, lengths[1:]))
    # the final context is exactly what run_episode's own turn
    # construction assembled at the last call
    exact = (cap.contexts[-1]
             == agent_loop._assemble_context(template, result.turns))
    ok = (n_calls == len(PLAN) + 1 and monotonic and exact
          and result.stopped_reason == "adapter_stop")
    print("case wrapper-capture   -> %d model calls, final context %d "
          "bytes, depths strictly increasing: %s, final context exact "
          "against run_episode's own assembly: %s   [%s]"
          % (n_calls, lengths[-1], monotonic, exact,
             "PASS" if ok else "FAIL"))
    results.append(ok)
finally:
    gw.close()

# 8. The B4 halt-note path through main(): a run-level snapshot swap
#    exits non-zero AND leaves a NOT-DISCHARGEABLE note naming the
#    failure, never a verdict.
path = "/tmp/wd-probe-haltnote.sock"
gw = MockGateway(path, PLAN,
                 lambda n: (CONST_BODY,
                            "mocksnap-A" if n < 2 else "mocksnap-B", "0"))
gw.start()
try:
    out = "/tmp/wd-halt-note.md"
    rc = wd.main(["--socket", path, "--out", out,
                  "--template", str(TEMPLATE_INDEX)])
    note = open(out).read()
    ok = (rc == 2
          and "RUN NOT DISCHARGEABLE" in note
          and "run-level snapshot precondition failed" in note
          and "Verdict" not in note)
    print("case halt-note         -> exit %d, note NOT-DISCHARGEABLE: %s, "
          "names the failure: %s, no verdict: %s   [%s]"
          % (rc, "RUN NOT DISCHARGEABLE" in note,
             "run-level snapshot precondition failed" in note,
             "Verdict" not in note, "PASS" if ok else "FAIL"))
    results.append(ok)
finally:
    gw.close()

print()
print("probes: %d/%d PASS" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
