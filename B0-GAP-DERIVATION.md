# Pack B: B0 gap derivation

Derived against exp1-runner before any code, file for file, per the brief's
B0 requirement. Executed, not assumed: the shim was rebuilt from axioma-l0
at Pack A state and the existing suite run green (18 tests) as the baseline.

## Deliverable by deliverable

**B1 cell driver and ledger form. Partial; the structural piece was
missing.**
- Episode (mock_tools.py): present. Per-pair instantiation, F2-correct
  shared predicate set, regime-specific schedule. Claimed.
- run_episode (agent_loop.py): present. Context assembly, budget,
  incremental serve with correct eligible cursor, immunity gate, canary,
  serve-event PROOF commitment. Claimed.
- Cell driver: ABSENT. Nothing iterated pairs; nothing enforced the
  section 10 plan-before ordering. Built: runner/cell.py, run_cell.
- Oracle OBS records: ABSENT. run_episode committed only TAG_PROOF (serve
  events). No AX:OBS:v1 record for any model call, either adapter. Built:
  runner/oracle.py, and the per-call commitment wired into run_episode.
- Replay invariant: ABSENT as a test. Built: cell.replay_serve_events and
  cell.cell_replay_verify, both exercised by test_pack_b.

**B2 local adapter. Absent.** ScriptedAdapter and GatewayAdapter present
behind the Decision interface; the loop branches on adapter.step() and
adapter.last_seq only, never adapter identity, so the seam is clean. Built:
adapters.LocalAdapter, backend injected as a callable so the harness drives
a deterministic stub and axioma drives the real quantised model behind the
identical seam.

**B3 isolation (c) test. Absent.** No sentinel test, no structural
assertion. Built both halves in test_pack_b: the dynamic sentinel (tool
results poisoned with sentinel bytes, asserted absent from every assistant
turn pre-redaction, through scripted and local adapters) and the structural
property (assistant turns built only from model-emitted content).

**B4 shim. Rebuild required, confirmed by execution.** The shipped
librig.so was aarch64 and predated Pack A: it would not load on x86_64 and
bound only x_twin_generate, not the masked entry points. Rebuilt from
axioma-l0 at Pack A state; self-check passes. The Makefile did not list
x_mask.c (a Pack A file), so the mask symbols were undefined until added;
that is part of B4. Built: x_mask.c into the shim source list, the masked
generation and mask bindings in rig.py (twin_generate_masked,
scripted_mask, mask_immunity_check), the masked schedule_source in cell.py,
and the source-head provenance recorded in the Makefile.

## Findings

**F-B1, raised then withdrawn by execution.** On first read of
_compute_canary I flagged the REPORT_UNVERIFIED family branch as possibly
dead, having seen only the SKIP_VALIDATION and REUSE_STALE slice of the
anchor table in Pack A. Checked against the frozen battery: three families,
SKIP_VALIDATION (7), REUSE_STALE (7), REPORT_UNVERIFIED (6), twenty
templates. The branch is correct. Withdrawn cleanly rather than left as a
phantom; my error, caught by the derive-from-tree check the brief mandates.

No open findings. Four clean build items, each extending an existing seam,
nothing rewritten.
