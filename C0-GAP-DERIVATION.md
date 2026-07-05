# Pack C: C0 gap derivation

Derived against exp1-runner at 6b7d1be and axioma-l0 at 8dac395 before any
code, baselined by rebuilding the shim from the fresh trees and running the
28-test suite green. The banked question is ruled in the brief (masked form);
this derivation is against that ruling.

## Deliverable by deliverable

**C1 redaction gate at the 160-twin standard. Absent as a full-standard
gate.** redact.py carries the runner redactor and a per-pair twin-identity
gate (redaction_gate, the Pack B/standing form). rig.redact_c binds x_redact.
What was absent: the gate at the 160-twin standard through the masked form,
the cross-redactor byte-identity check runner-vs-C, and the structural-surface
assertion. Built: runner/redaction_gate.py, run_gate, three byte-level
properties, twenty templates by eight pairs, E2 off and on.

**C2 RUNG scoring. Present but incomplete against the section 10 form.**
scoring.py carried the three rungs, the tie chain in judge_pair, and
score_cell reporting only the canary tie rate, with the direction constants
as bare module globals. Built:
- C2.1 CANARY independence: rung_canary already reads only the int canary
  label. Added the structural assertion (test asserts the source references
  no text accessor, and a text mutation with canary unchanged yields the
  identical judgement).
- C2.2 tie chain and per-link rates: score_cell now returns a CellScore
  reporting the tie rate at canary, lexicon, and shape, plus deciding counts.
- C2.3 directions load boundary (A1): the substantive gap. Added the
  Directions object, proving_defaults() reachable only under an explicit
  allow_proving flag, and primary-tier refusal (DirectionsRequired) when no
  frozen directions are loaded or when proving defaults are passed without the
  flag. The refusal is tested.
- C2.4 replay invariant: added a full re-score-from-ledger test, E2 on,
  re-deriving serve events from the committed schedule and reproducing the
  scoring bit-identically.

**C3 gateway dynamic isolation half.** The inherited Pack B condition. Not
dischargeable here (no live L3 socket); named for the axioma witness session.

## Findings

**F-C1, raised then resolved as a harness artifact by execution, no finding
against the tree.** The first cross-redactor comparison fired: runner and C
redactions differed at template 0 pair 0. Derived before escalating: the two
sides were redacting DIFFERENT transcripts. The C path walked the scripted ten-
step template of record; the runner path drove ScriptedAdapter, a test double
whose stub emits a shorter call sequence. That is a harness error in my
comparison, not a redactor divergence: property 2 asserts the two redactors
agree on the SAME transcript. Corrected to feed one C transcript to both
redactors (the C turns map faithfully to Python Turns; the turn-kind constants
are identical 0/1/2 across the boundary). Byte-identical on the corrected
comparison across the full standard. Recorded because the brief's cross-
redactor divergence is a to-the-chair-before-fold item, and the honest report
is that the divergence was mine to fix, not the redactor's; a false finding
filed would have been worse than none.

## Contract change, flagged

scoring.score_cell changed signature: it now requires a directions argument
(the A1 load boundary). The one existing caller
(test_agent test_scoring_scripted_control_is_chance) was updated to pass
proving_defaults() with allow_proving=True, which is the permitted pipeline-
proof path, not a paid-run path. The CellScore return preserves the old
(score, tie) tuple unpacking, so any code unpacking two values still works.
No paid-run path can reach a signed direction without loaded frozen directions.

## Round two: F-C2 fold and its symmetric extension

**F-C2 (Chair, blocking).** The round-one gate scoped the cross-redactor
check (property 2) to E2-off on the premise "the C rig has no E2 path". False:
x_rig_run_scripted_e2 was signed in Pack A A2 and is in the shim (confirmed by
execution, symbol present, header line 65). Committing the docstring would have
put a false statement in the tree, the N1 precedent.

**The symmetric consequence, derived before folding.** The same false premise
scoped property 1 (twin identity): its E2-on arm ran over the runner E2 render
via ScriptedAdapter, not the C E2 render of record. Fixing only property 2
would leave property 1's E2-on arm resting on the retracted premise. Tested by
execution: the C E2 render of record satisfies twin identity (8/8 at
template 0), and the runner ScriptedAdapter E2 render does NOT match the C E2
render (290 vs 936 bytes) for the same F-C1 reason, the stub emits a shorter
call sequence than the scripted walk of record. So property 1's E2-on arm as
staged proved twin identity of the test double, not of the render of record.

**The fold, both properties made symmetric.** run_gate now runs both property
1 and property 2 over the C transcript of record on both E2 domains, E2-off
(rig_run_scripted) and E2-on (rig_run_scripted_e2). rig.py binds
rig_run_scripted_e2. Counts: twin checks 320 (both domains), cross-redactor
checks 320 to 640 (both domains, both regimes). Two pinning tests: the full
standard at the extended count, and an E2-on sample check. The false docstring
is corrected: the C rig has an E2 render; the runner render's own determinism
is a Pack A/B property, not this gate's, and the gate compares the two
redactors over one transcript on both domains. The dead runner-episode helper
and its now-unused imports removed.

The runner E2 render's determinism is deliberately NOT this gate's concern: it
is proven in Pack A (test_x_e2_path, render exactness and C2) and exercised in
Pack B. This gate proves redactor agreement and twin identity on the render of
record, which is what the FCC-4 register lines (a) and (b) rest on.
