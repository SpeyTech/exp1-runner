# exp1-runner

EXP-1 experiment client. Drives agent episodes against the axioma-l0
rig (C shim over the exp1 subtree) and the L3 gateway, writes framed
evidence files in the gateway record format, scores redacted
transcripts. Subject-side Python; every D1 path is the C truth called
through ctypes. Pins: axioma-l0 battery blob 64f2f601, pool blob
12b1478d, full-SHA comparison at load.

This repository's head is the "Experiment commit" pin in the EXP-1
pre-registration (axioma-l0 docs/L0-EXP1-PREREG-DRAFT.md).

William Murray, Spey Systems Ltd (SC889983), Inverness.
