# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# redact.py: the Python redactor for real model transcripts, carrying
# the same semantics as the C x_redact (exp1/src/x_redact.c): the
# distinguisher sees assistant turns only; tool-result turns are replaced
# by turn-indexed placeholders "[[T<index>:TOOL_RESULT]]". Turns joined
# by LF.
#
# The C redactor is the reference. This Python one exists because real
# model transcripts are Python objects, not the C x_transcript_t. The
# byte-identity gate (redaction_gate) proves the two agree on the
# scripted twins before any model episode runs, per the standing brief:
# if the Python redactor and the C redactor ever diverge on an E1 twin
# pair, every paid run is blocked.

from runner import rig, agent_loop

TURN_ASSISTANT_TEXT = agent_loop.TURN_ASSISTANT_TEXT
TURN_ASSISTANT_CALL = agent_loop.TURN_ASSISTANT_CALL
TURN_TOOL_RESULT = agent_loop.TURN_TOOL_RESULT


def redact_turns(turns):
    """Redact a list of agent_loop.Turn to the flat byte stream. Matches
    x_redact: tool results become placeholders, assistant turns kept,
    joined by LF, no trailing LF."""
    parts = []
    for i, t in enumerate(turns):
        if t.kind == TURN_TOOL_RESULT:
            parts.append("[[T%d:TOOL_RESULT]]" % i)
        else:
            parts.append(t.text)
    return "\n".join(parts).encode()


def redaction_gate(root_seed, template_index, pair_id, template,
                   e2_enabled=False):
    """The blocking E1 redaction gate, runner side.

    Run the scripted agent through both regimes of one twin pair via the
    agent loop, redact both with the Python redactor, and require the two
    redacted transcripts to be byte-identical. The scripted agent is
    deterministic and its behaviour does not condition on the envelope,
    so its two regime transcripts differ only in the injected telemetry
    inside tool results, which redaction removes. If the redacted
    streams differ, the redactor is leaking the manipulation and the run
    is blocked.

    Returns True if the gate passes; raises RedactionLeak if it fails."""
    from runner import mock_tools, adapters

    reds = {}
    for regime in (rig.X_REGIME_PROD, rig.X_REGIME_EVAL):
        ep = mock_tools.Episode(root_seed, template_index, pair_id, regime)
        ad = adapters.ScriptedAdapter(ep)
        res = agent_loop.run_episode(ep, ad, template, e2_enabled=e2_enabled)
        reds[regime] = redact_turns(res.turns)

    if reds[rig.X_REGIME_PROD] != reds[rig.X_REGIME_EVAL]:
        raise RedactionLeak(
            "redaction gate failed at template %d pair %d: the redacted "
            "twin transcripts differ, so the redactor leaks the envelope "
            "manipulation. Every paid run is blocked (C4)."
            % (template_index, pair_id)
        )
    return True


class RedactionLeak(RuntimeError):
    pass
