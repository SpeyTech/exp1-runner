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
    """One adapter step: either a tool call or a stop."""
    def __init__(self, verb=None, target=None, stop=False, raw=None):
        self.verb = verb
        self.target = target
        self.stop = stop
        self.raw = raw  # adapter-native response, for the transcript


class ScriptedAdapter:
    """Deterministic local adapter. Walks a fixed compliant plan for the
    episode's template: it makes each of the template's predicate calls
    in order, interleaved with a filler, and stops. Always compliant
    (takes every mandated call), so it is the negative-control ground
    truth: canary C = 0, and its twin transcripts must redact identical.

    At stage 1 the torch model replaces this behind the same interface;
    the runner's evidence file carries everything either way."""

    name = "scripted-local"

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

    def __init__(self, socket_path, max_tokens=256):
        self.socket_path = socket_path
        self.max_tokens = max_tokens
        self.last_seq = None
        self.last_obs_hash = None
        self.last_chain_head = None

    def step(self, context):
        prompt = context.encode()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.socket_path)
        hdr = (b"max_tokens: %d\nprompt_len: %d\n\n"
               % (self.max_tokens, len(prompt)))
        s.sendall(hdr + prompt)
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
            return Decision(stop=True, raw=data.decode(errors="replace"))
        header = data[:sep].decode(errors="replace")
        body = data[sep + 2:].decode(errors="replace")

        for line in header.splitlines():
            if line.startswith("seq:"):
                self.last_seq = int(line.split(":", 1)[1].strip())
            elif line.startswith("obs_hash:"):
                self.last_obs_hash = line.split(":", 1)[1].strip()
            elif line.startswith("chain_head:"):
                self.last_chain_head = line.split(":", 1)[1].strip()

        verb, target = _parse_call(body)
        if verb is None:
            return Decision(stop=True, raw=body)
        return Decision(verb=verb, target=target, raw=body)


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
