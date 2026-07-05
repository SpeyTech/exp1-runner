# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# adapters.py: the model adapter seam. Two implementations share one
# interface so both tiers replay the same way:
#
#   ScriptedAdapter  local, no cost, deterministic. Emits a fixed tool
#                    sequence. Stage 0/proving; the negative-control
#                    ground truth. Replaces the torch model at stage 1.
#   GatewayAdapter   the L3 gateway over its unix socket. The gateway's
#                    own chain carries the AX:OBS records; the runner's
#                    evidence file carries the episode records and
#                    cross-references the gateway seq.
#
# An adapter takes an assembled prompt and returns a decision: the next
# tool call (verb, target) or a stop. The agent loop owns context
# assembly and the call budget; the adapter owns only "given this
# context, what does the subject do next".

import socket

from runner import serve


class Decision:
    """One adapter step: either a tool call or a stop.

    Oracle-record fields (Pack B, B1). An adapter that crosses the
    oracle boundary fills request_bytes and response_bytes with the
    exact wire bytes, so the driver commits an AX:OBS:v1 record whose
    hashes are over what actually crossed. gateway_seq is set by the
    gateway adapter (its own chain's seq for this call); it stays None
    for a local adapter, whose driver-side record is self-authored.
    The scripted adapter leaves all of these None: it is not a model
    and crosses no oracle boundary, so it emits no oracle record."""
    def __init__(self, verb=None, target=None, stop=False, raw=None,
                 request_bytes=None, response_bytes=None,
                 gateway_seq=None):
        self.verb = verb
        self.target = target
        self.stop = stop
        self.raw = raw  # adapter-native response, for the transcript
        self.request_bytes = request_bytes
        self.response_bytes = response_bytes
        self.gateway_seq = gateway_seq


class ScriptedAdapter:
    """Deterministic local adapter. Walks a fixed compliant plan for the
    episode's template: it makes each of the template's predicate calls
    in order, interleaved with a filler, and stops. Always compliant
    (takes every mandated call), so it is the negative-control ground
    truth: canary C = 0, and its twin transcripts must redact identical.

    At stage 1 the torch model replaces this behind the same interface;
    the runner's evidence file carries everything either way."""

    name = "scripted-local"
    source = "scripted"  # not a model; crosses no oracle boundary

    def __init__(self, episode):
        self.episode = episode
        # Build the compliant plan: the predicate calls in order, each
        # preceded by a filler read, then stop. Compliant by
        # construction (every predicate call present, in order).
        pc = episode.predicate_calls()
        self._plan = []
        for verb_name, target in pc:
            self._plan.append((serve.X_VERB_FILE_READ, "manifest.yaml"))
            self._plan.append((serve.VERB_ID[verb_name], target))
        self._i = 0

    def step(self, context):
        if self._i >= len(self._plan):
            return Decision(stop=True, raw="stop")
        verb, target = self._plan[self._i]
        self._i += 1
        return Decision(verb=verb, target=target,
                        raw="call %s(%s)" % (serve.VERB_NAME[verb], target))


class GatewayAdapter:
    """L3 gateway adapter over the unix socket. Speaks the gateway line
    protocol unchanged: 'key: value' header lines, blank line, then the
    prompt bytes; response is header lines, blank line, output bytes.

    The gateway commits its own AX:OBS record per call to its durable
    chain; this adapter parses the response header (seq, obs_hash,
    chain_head) so the runner's episode record cross-references the
    gateway seq. The runner never changes the gateway protocol; a hard
    blocker is reported, not worked around.

    Response parsing extracts the next tool call from the model output.
    The output-to-call parse is deliberately strict: the model is
    instructed to emit one 'call verb(target)' line; anything else is a
    stop, so a malformed or refusing turn ends the episode cleanly rather
    than guessing."""

    name = "gateway-socket"

    # A gateway model crosses the oracle boundary; the driver commits a
    # runner-side AX:OBS record cross-referencing the gateway seq. The
    # snapshot id is the gateway-reported model snapshot (parsed from
    # the response header when present), exposed here for the driver.
    source = "gateway"

    def __init__(self, socket_path, temperature_q16, max_tokens=256):
        """temperature_q16 is MANDATORY and has no default (Grandfather
        Chair ruling): a request that goes out with no pin is a run that
        looks pinned and isn't, the same silent-precondition failure the
        harness refuses on UNRECORDED snapshot. Pass integer 0 for greedy
        decoding (Q16.16 fixed point, so 0 is 0.0), which is what makes
        replay bit-exact mean deterministic serving rather than a sample
        that happened to agree. A nonzero temperature must be a committed
        Q16.16 integer constant, never a float over the wire: float
        round-trip on the gateway side reintroduces the non-determinism
        the pin exists to remove."""
        if temperature_q16 is None:
            raise ValueError(
                "GatewayAdapter requires temperature_q16 (no default): an "
                "unpinned request serves at the provider default and makes "
                "replay meaningless. Pass 0 for greedy decoding.")
        if not isinstance(temperature_q16, int):
            raise TypeError(
                "temperature_q16 must be an integer (Q16.16 fixed point), "
                "not a float: a float over the wire is a reproducibility "
                "hole. 0 is greedy; a nonzero pin is a committed constant.")
        self.socket_path = socket_path
        self.temperature_q16 = temperature_q16
        self.max_tokens = max_tokens
        self.last_seq = None
        self.last_obs_hash = None
        self.last_chain_head = None
        self.last_snapshot_id = None
        self.last_temperature = None  # what the gateway reports it served

    def step(self, context):
        prompt = context.encode()
        # Hard precondition, re-asserted at the point of the socket write
        # (B4 lesson one layer down): a pin you can't enforce structurally
        # fails silently on a tired day. No request leaves without it.
        assert self.temperature_q16 is not None, \
            "temperature pin lost before socket write; refusing to serve"
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.socket_path)
        hdr = (b"max_tokens: %d\ntemperature_q16: %d\nprompt_len: %d\n\n"
               % (self.max_tokens, self.temperature_q16, len(prompt)))
        request_bytes = hdr + prompt
        s.sendall(request_bytes)
        data = b""
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
        s.close()

        # Split header and body on the blank line.
        sep = data.find(b"\n\n")
        if sep < 0:
            return Decision(stop=True, raw=data.decode(errors="replace"),
                            request_bytes=request_bytes,
                            response_bytes=data)
        header = data[:sep].decode(errors="replace")
        body = data[sep + 2:].decode(errors="replace")

        for line in header.splitlines():
            if line.startswith("seq:"):
                self.last_seq = int(line.split(":", 1)[1].strip())
            elif line.startswith("obs_hash:"):
                self.last_obs_hash = line.split(":", 1)[1].strip()
            elif line.startswith("chain_head:"):
                self.last_chain_head = line.split(":", 1)[1].strip()
            elif line.startswith("snapshot_id:"):
                self.last_snapshot_id = line.split(":", 1)[1].strip()
            elif line.startswith("temperature_q16:"):
                # what the gateway reports it SERVED, recorded alongside
                # the snapshot: record what ran, do not assert it. If this
                # diverges from what was sent, it belongs on the record.
                self.last_temperature = line.split(":", 1)[1].strip()

        verb, target = _parse_call(body)
        if verb is None:
            return Decision(stop=True, raw=body,
                            request_bytes=request_bytes,
                            response_bytes=data,
                            gateway_seq=self.last_seq)
        return Decision(verb=verb, target=target, raw=body,
                        request_bytes=request_bytes,
                        response_bytes=data,
                        gateway_seq=self.last_seq)


def _parse_call(text):
    """Extract the first 'call verb(target)' from model output. Returns
    (verb_id, target) or (None, None). Strict: the verb must be in the
    six-verb vocabulary."""
    import re
    m = re.search(r"call\s+([a-z_]+)\s*\(\s*([^)]*)\s*\)", text)
    if not m:
        return None, None
    verb_name = m.group(1)
    if verb_name not in serve.VERB_ID:
        return None, None
    target = m.group(2).strip()
    return serve.VERB_ID[verb_name], target


class LocalAdapter:
    """Stage-1 local open-weights adapter (Pack B, B2). Drives a
    quantised local model behind the same Decision seam ScriptedAdapter
    and GatewayAdapter occupy (design section 11: the same adapter
    interface as the scripted negative control). Adapter selection is
    configuration; the episode loop never branches on adapter identity.

    Determinism, stated honestly: a sampled model is D3. No determinism
    claim is made for the model itself. What makes a local call evidence
    is the AX:OBS record the driver commits: the exact request and
    response bytes are hashed into the ledger, and snapshot_id is the
    SHA-256 of the model file (oracle.snapshot_id_of_file), the honest
    local analogue of a provider snapshot id. Re-running the model may
    produce different bytes; the ledger records which bytes THIS run
    produced under WHICH weights, and that is the replayable claim.

    The model backend is injected as a callable `generate(prompt: str)
    -> str`, so the harness drives a deterministic stub and axioma
    drives the real quantised model behind the identical seam. The
    production wiring (the torch/llama.cpp loader, the quantisation, the
    sampler seed) lives in the injected callable, not in the episode
    path; the adapter is backend-agnostic by construction. `source` is
    local, so the driver self-authors the five-field oracle record.
    """

    name = "local-openweights"
    source = "local"

    def __init__(self, generate, snapshot_id, max_tokens=256):
        """generate: callable prompt->text (the model backend).
        snapshot_id: 32-byte SHA-256 of the model file
        (oracle.snapshot_id_of_file); the driver stamps it into every
        oracle record for this adapter."""
        self._generate = generate
        self.snapshot_id = snapshot_id
        self.max_tokens = max_tokens
        self.last_snapshot_id = snapshot_id

    def step(self, context):
        request_bytes = context.encode()
        output = self._generate(context)
        response_bytes = output.encode()
        verb, target = _parse_call(output)
        if verb is None:
            return Decision(stop=True, raw=output,
                            request_bytes=request_bytes,
                            response_bytes=response_bytes)
        return Decision(verb=verb, target=target, raw=output,
                        request_bytes=request_bytes,
                        response_bytes=response_bytes)
