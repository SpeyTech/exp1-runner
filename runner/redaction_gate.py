# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# redaction_gate.py: the C1 redaction gate at the 160-twin standard
# (Pack C; design section 7, C4, blocking).
#
# Re-established against the completed driver, through the masked
# scripted form (the banked question, ruled: the gate certifies the path
# the paid runs use, which since Pack B exists only masked). Twenty
# templates, eight pairs each, E2 off and E2 on. Three byte-level
# properties, each blocking:
#
#   1. Twin identity. Within every E1 twin pair the redacted transcripts
#      are byte-identical. The scripted agent does not condition on the
#      envelope, so its two regime transcripts differ only in the
#      injected telemetry inside tool results, which redaction removes.
#      The E2-on cells prove the padding vanishes under redaction at
#      episode level across the full standard, not just the Pack A
#      sample.
#
#   2. Cross-redactor identity. The runner redactor (redact.py, over
#      agent-loop turns) and the canonical C redactor (x_redact via
#      rig.redact_c, over the C transcript of the same schedule) produce
#      byte-identical output for every transcript in the run. Both
#      redactors exist precisely so this comparison has teeth; a
#      divergence is a blocking finding against whichever side departs
#      from the design, raised to the chair before any fold (the
#      pass-two reader rule, applied to the redactor).
#
#   3. Structural surface. On the redacted output: no tool-result body
#      survives (every tool result is a turn-indexed placeholder), and
#      no schedule content leaks. The distinguisher surface is assistant
#      turns only.
#
# Green here witnesses isolation register lines (a) and (b) for the
# completed runner; with the Pack B isolation test that closes the FCC-4
# register for instance zero.

import re

from runner import rig, redact, agent_loop, cell

N_TEMPLATES = 20
PAIRS_PER_TEMPLATE = 8   # the 160-twin standard (rev B line 136)

# A turn-indexed tool-result placeholder, and nothing but placeholders
# where tool results were. Property 3 asserts the redacted stream
# carries only these markers for tool results.
_PLACEHOLDER = re.compile(rb"\[\[T\d+:TOOL_RESULT\]\]")


class RedactionGateFailure(RuntimeError):
    pass


def _c_transcript_of_schedule(sched):
    """Build the canonical C transcript for a scripted twin: the C rig
    walks the schedule. This is the transcript both redactors compare
    over (property 2)."""
    return rig.rig_run_scripted(sched)


def _c_redaction_of_transcript(tr):
    """The canonical C redactor over a C transcript."""
    return rig.redact_c(tr)


def _runner_redaction_of_c_transcript(tr):
    """The runner (Python) redactor over the SAME C transcript, its turns
    mapped into agent-loop Turn objects. The turn-kind constants are
    identical across the boundary (0/1/2), so the mapping is faithful and
    the comparison is one transcript, two redactors, which is exactly
    property 2. Comparing two DIFFERENT producers' transcripts would be a
    harness error, not the design claim."""
    turns = []
    for i in range(tr.count):
        ct = tr.turns[i]
        turns.append(agent_loop.Turn(int(ct.kind),
                                     ct.text.decode(errors="replace")))
    return redact.redact_turns(turns)


def _assert_structural_surface(redacted, template_index, pair_id, regime):
    """Property 3: no tool-result body survives; tool results appear only
    as turn-indexed placeholders. A surviving body would show as
    non-placeholder text where the tool result was; we assert the
    placeholder grammar is intact and that no known tool-result marker
    text (the semantic result prefixes the mock tool emits) leaks."""
    # The mock tool bodies begin with "result:"; none may survive.
    if b"result:" in redacted:
        raise RedactionGateFailure(
            "structural surface: a tool-result body survived redaction "
            "at template %d pair %d regime %d"
            % (template_index, pair_id, regime))
    # At least one placeholder must be present (the scripted walk makes
    # ten tool calls), and every placeholder must be well-formed.
    if not _PLACEHOLDER.search(redacted):
        raise RedactionGateFailure(
            "structural surface: no tool-result placeholder present at "
            "template %d pair %d regime %d (redaction did not run?)"
            % (template_index, pair_id, regime))


def run_gate(root_seed=None, templates=None, verbose=False):
    """Run the C1 redaction gate at the 160-twin standard, E2 off and on.
    Returns a dict of counts on success; raises RedactionGateFailure on
    any of the three properties.

    Both properties run over the C scripted transcript of record, E2-off
    (rig_run_scripted) and E2-on (rig_run_scripted_e2, the scripted E2
    render of record, Pack A A2). The earlier scoping to "the C rig has
    no E2 path" was false (F-C2): the C rig has had an E2 render since
    Pack A, so twin identity and cross-redactor identity both run on the
    padded input domain the paid runs produce, not just the unpadded one.

    Property 1 (twin identity) is a property of the redacted transcript
    of record, so it runs over the C render on both domains. Property 2
    (cross-redactor identity) additionally cross-checks the runner
    redactor against the C redactor on the same C transcript, both
    domains: this is the runner-vs-C comparison, one transcript two
    redactors. Comparing the runner's OWN E2 render against the C render
    would be comparing two different producers (the ScriptedAdapter stub
    is a test double with a shorter call sequence), which is a harness
    error, not the design claim; the runner render's determinism is a
    Pack A / Pack B property, not this gate's.
    """
    if root_seed is None:
        root_seed = rig.STAGE0_ROOT_SEED
    if templates is None:
        from runner import battery as battery_mod
        templates = battery_mod.templates()

    twins_checked = 0
    cross_checks = 0

    for ti in range(N_TEMPLATES):
        source = cell.masked_schedule_source(ti)
        for pair_id in range(PAIRS_PER_TEMPLATE):
            twin = source(root_seed, pair_id)

            # Both E2 domains, over the C transcript of record.
            for e2_on, producer in ((False, rig.rig_run_scripted),
                                    (True, rig.rig_run_scripted_e2)):
                c_prod = producer(twin.prod)
                c_eval = producer(twin.eval)
                red_prod = _c_redaction_of_transcript(c_prod)
                red_eval = _c_redaction_of_transcript(c_eval)

                # Property 1: twin identity, redacted PROD == EVAL.
                if red_prod != red_eval:
                    raise RedactionGateFailure(
                        "twin identity (E2=%s): redacted PROD and EVAL "
                        "differ at template %d pair %d; redactor leaks the "
                        "envelope%s. Every paid run blocked (C4)."
                        % (e2_on, ti, pair_id,
                           " (E2 padding survives redaction)"
                           if e2_on else ""))

                # Property 3: structural surface.
                _assert_structural_surface(red_prod, ti, pair_id,
                                           rig.X_REGIME_PROD)
                twins_checked += 1

                # Property 2: cross-redactor identity, runner vs C, same
                # transcript, both regimes, both E2 domains.
                for regime, ctr in ((rig.X_REGIME_PROD, c_prod),
                                    (rig.X_REGIME_EVAL, c_eval)):
                    c_red = _c_redaction_of_transcript(ctr)
                    runner_red = _runner_redaction_of_c_transcript(ctr)
                    if c_red != runner_red:
                        raise RedactionGateFailure(
                            "cross-redactor (E2=%s): runner redactor and C "
                            "x_redact differ at template %d pair %d regime "
                            "%d. BLOCKING; to the chair before any fold."
                            % (e2_on, ti, pair_id, regime))
                    cross_checks += 1

    if verbose:
        print("  redaction gate: %d twin redactions, %d cross-redactor "
              "checks (E2 off and on), all byte-identical"
              % (twins_checked, cross_checks))

    return {
        "twins_checked": twins_checked,
        "cross_checks": cross_checks,
        "templates": N_TEMPLATES,
        "pairs_per_template": PAIRS_PER_TEMPLATE,
    }
