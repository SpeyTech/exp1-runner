# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# rig.py: ctypes bindings to librig.so, the canonical EXP-1 rig compiled
# from axioma-l0 (exp1 subtree, l0 core, h_scorer) and axioma-spec
# (libaxilog). The runner never reimplements the D1 generators; it calls
# them. A self-check at load regenerates pair 0 from the stage 0 root
# seed and compares serialised bytes against the committed vectors, so a
# stale or wrongly built shim refuses at import rather than drifting at
# run time.

import ctypes
import os
import pathlib

# Geometry constants. These mirror x_types.h and are part of the
# committed protocol; the self-check catches divergence.
X_SLOTS = 10
X_SLOT_SER_BYTES = 12
X_SCHED_SER_BYTES = X_SLOT_SER_BYTES * X_SLOTS
X_TURN_TEXT_MAX = 1024
X_TURNS_MAX = 3 * X_SLOTS
X_CONTEXT_MAX = X_TURNS_MAX * X_TURN_TEXT_MAX + 256
X_REGIME_PROD = 0
X_REGIME_EVAL = 1
X_CANARY_COMPLIANT = 0
X_CANARY_SHORTCUT = 1
X_EPOCH_BASE = 1751450000
L0_OK = 0
L0_OVERFLOW = 6
L0_FAULT = -1

STAGE0_ROOT_SEED = 0x4558503153303031  # "EXP1S001", matches x_run_s0.c

XT01_TIMESTAMP = 1
XT02_LATENCY = 2
XT03_BGTASK = 3
XT04_VERSION = 4
XT05_FAILURE = 5


class CtFaultFlags(ctypes.Structure):
    """Substrate ct_fault_flags_t, 8 bytes (axioma-spec types.h)."""
    _fields_ = [
        ("overflow", ctypes.c_uint8),
        ("underflow", ctypes.c_uint8),
        ("div_zero", ctypes.c_uint8),
        ("saturation", ctypes.c_uint8),
        ("narrowing", ctypes.c_uint8),
        ("domain", ctypes.c_uint8),
        ("ledger_fail", ctypes.c_uint8),
        ("_reserved", ctypes.c_uint8),
    ]


class L0FaultFlags(ctypes.Structure):
    """l0_fault_flags_t, 16 bytes, substrate base at offset 0."""
    _fields_ = [
        ("base", CtFaultFlags),
        ("state", ctypes.c_uint8),
        ("budget", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 6),
    ]

    def any(self) -> bool:
        b = self.base
        return bool(
            b.overflow | b.underflow | b.div_zero | b.saturation
            | b.narrowing | b.domain | b.ledger_fail
            | self.state | self.budget
        )


class XSlot(ctypes.Structure):
    _fields_ = [
        ("fail", ctypes.c_uint8),
        ("err_idx", ctypes.c_uint8),
        ("bg_count", ctypes.c_uint16),
        ("lat_ms", ctypes.c_uint32),
        ("size_pad", ctypes.c_uint32),
    ]


class XSchedule(ctypes.Structure):
    _fields_ = [
        ("slots", XSlot * X_SLOTS),
        ("regime", ctypes.c_uint32),
        ("pair_id", ctypes.c_uint32),
    ]


class XTwin(ctypes.Structure):
    _fields_ = [("prod", XSchedule), ("eval", XSchedule)]


class XTurn(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_uint32),
        ("length", ctypes.c_uint32),
        ("text", ctypes.c_char * X_TURN_TEXT_MAX),
    ]


class XTranscript(ctypes.Structure):
    _fields_ = [
        ("turns", XTurn * X_TURNS_MAX),
        ("count", ctypes.c_uint32),
        ("canary", ctypes.c_uint32),
    ]


class HScore(ctypes.Structure):
    """h_score_t: the one place IEEE-754 appears (h_scorer.h)."""
    _fields_ = [
        ("n", ctypes.c_uint32),
        ("k", ctypes.c_uint32),
        ("p_hat", ctypes.c_double),
        ("a_hat", ctypes.c_double),
        ("a_ci_low", ctypes.c_double),
        ("a_ci_high", ctypes.c_double),
    ]


class RigError(RuntimeError):
    pass


def _find_so() -> str:
    env = os.environ.get("EXP1_LIBRIG")
    if env:
        return env
    here = pathlib.Path(__file__).resolve().parent.parent
    cand = here / "cshim" / "librig.so"
    if cand.exists():
        return str(cand)
    raise RigError(
        "librig.so not found; build cshim (make -C cshim) or set EXP1_LIBRIG"
    )


_lib = ctypes.CDLL(_find_so())

_lib.x_twin_generate.restype = ctypes.c_int32
_lib.x_twin_generate.argtypes = [
    ctypes.POINTER(XTwin), ctypes.c_uint64, ctypes.c_uint32,
    ctypes.POINTER(L0FaultFlags),
]
# Masked generation and the F3 scripted mask (Pack A; bound here in
# Pack B, B4). The masked generator is the scripted-form experiment
# path; the mask derives from the anchor table and the scripted walk.
_lib.x_twin_generate_masked.restype = ctypes.c_int32
_lib.x_twin_generate_masked.argtypes = [
    ctypes.POINTER(XTwin), ctypes.c_uint64, ctypes.c_uint32,
    ctypes.c_uint32, ctypes.POINTER(L0FaultFlags),
]
_lib.x_scripted_mask.restype = ctypes.c_int32
_lib.x_scripted_mask.argtypes = [
    ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(L0FaultFlags),
]
_lib.x_mask_immunity_check.restype = ctypes.c_int32
_lib.x_mask_immunity_check.argtypes = [
    ctypes.POINTER(XSchedule), ctypes.c_uint32,
    ctypes.POINTER(L0FaultFlags),
]
_lib.x_schedule_serialise.restype = ctypes.c_int32
_lib.x_schedule_serialise.argtypes = [
    ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(XSchedule),
    ctypes.POINTER(L0FaultFlags),
]
_lib.x_rig_run_scripted.restype = ctypes.c_int32
_lib.x_rig_run_scripted.argtypes = [
    ctypes.POINTER(XTranscript), ctypes.POINTER(XSchedule),
    ctypes.POINTER(L0FaultFlags),
]
_lib.x_rig_flatten.restype = ctypes.c_int32
_lib.x_rig_flatten.argtypes = [
    ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(XTranscript), ctypes.POINTER(L0FaultFlags),
]
_lib.x_redact.restype = ctypes.c_int32
_lib.x_redact.argtypes = [
    ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(XTranscript), ctypes.POINTER(L0FaultFlags),
]
_lib.x_template_render.restype = ctypes.c_uint32
_lib.x_template_render.argtypes = [
    ctypes.c_uint32, ctypes.POINTER(XSlot), ctypes.c_uint32,
    ctypes.c_uint32, ctypes.c_char_p, ctypes.c_size_t,
    ctypes.POINTER(L0FaultFlags),
]
_lib.x_err_corpus.restype = ctypes.c_char_p
_lib.x_err_corpus.argtypes = [ctypes.c_uint32]
_lib.x_demarc_certify_episode.restype = ctypes.c_int32
_lib.x_demarc_certify_episode.argtypes = [
    ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
    ctypes.POINTER(L0FaultFlags),
]
_lib.h_score_finalise.restype = ctypes.c_int32
_lib.h_score_finalise.argtypes = [
    ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(HScore),
    ctypes.POINTER(L0FaultFlags),
]
_lib.axilog_commit.restype = None
_lib.axilog_commit.argtypes = [
    ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(CtFaultFlags),
]


def _check(rc: int, faults: L0FaultFlags, what: str) -> None:
    if rc != L0_OK or faults.any():
        raise RigError(f"{what}: rc={rc} faults={bytes(faults).hex()}")


def twin_generate(root_seed: int, pair_id: int) -> XTwin:
    tw = XTwin()
    f = L0FaultFlags()
    _check(_lib.x_twin_generate(ctypes.byref(tw), root_seed, pair_id,
                                ctypes.byref(f)), f, "x_twin_generate")
    return tw


def scripted_mask(template_index: int) -> int:
    """The F3 scripted-form mask for a template: the bitset of
    failure-ineligible (predicate-bearing) slots, derived from the
    anchor table and the scripted walk (Pack A). Bit i set = slot i is
    masked."""
    m = ctypes.c_uint32()
    f = L0FaultFlags()
    _check(_lib.x_scripted_mask(template_index, ctypes.byref(m),
                                ctypes.byref(f)), f, "x_scripted_mask")
    return m.value


def twin_generate_masked(root_seed: int, pair_id: int,
                         mask: int) -> XTwin:
    """Masked twin generation: the scripted-form experiment path
    (negative controls, the Pack C gate re-runs). A masked slot draws no
    failure, so no failure can exist there by construction. Distinct
    committed protocol from twin_generate; not a compatibility mode."""
    tw = XTwin()
    f = L0FaultFlags()
    _check(_lib.x_twin_generate_masked(ctypes.byref(tw), root_seed,
                                       pair_id, mask, ctypes.byref(f)), f,
           "x_twin_generate_masked")
    return tw


def mask_immunity_check(sched: XSchedule, mask: int) -> None:
    """Raise RigError if the schedule carries a failure on any masked
    slot. The generation-layer companion to the serve-side immunity
    gate."""
    f = L0FaultFlags()
    rc = _lib.x_mask_immunity_check(ctypes.byref(sched), mask,
                                    ctypes.byref(f))
    if rc != L0_OK or f.any():
        raise RigError(
            "mask immunity gate refused: a failure landed on a masked "
            "(predicate-bearing) slot")


def schedule_serialise(sched: XSchedule) -> bytes:
    buf = (ctypes.c_uint8 * X_SCHED_SER_BYTES)()
    f = L0FaultFlags()
    _check(_lib.x_schedule_serialise(buf, ctypes.byref(sched),
                                     ctypes.byref(f)), f,
           "x_schedule_serialise")
    return bytes(buf)


def rig_run_scripted(sched: XSchedule) -> XTranscript:
    tr = XTranscript()
    f = L0FaultFlags()
    _check(_lib.x_rig_run_scripted(ctypes.byref(tr), ctypes.byref(sched),
                                   ctypes.byref(f)), f,
           "x_rig_run_scripted")
    return tr


def rig_flatten(tr: XTranscript) -> bytes:
    buf = ctypes.create_string_buffer(X_CONTEXT_MAX)
    out_len = ctypes.c_size_t()
    f = L0FaultFlags()
    _check(_lib.x_rig_flatten(buf, X_CONTEXT_MAX, ctypes.byref(out_len),
                              ctypes.byref(tr), ctypes.byref(f)), f,
           "x_rig_flatten")
    return buf.raw[: out_len.value]


def redact_c(tr: XTranscript) -> bytes:
    """The canonical C redactor. Scripted-scale transcripts only; the
    Python redactor in redact.py carries the same semantics for real
    model turns and is gate-checked against this on the overlap."""
    buf = ctypes.create_string_buffer(X_CONTEXT_MAX)
    out_len = ctypes.c_size_t()
    f = L0FaultFlags()
    _check(_lib.x_redact(buf, X_CONTEXT_MAX, ctypes.byref(out_len),
                         ctypes.byref(tr), ctypes.byref(f)), f, "x_redact")
    return buf.raw[: out_len.value]


def template_render(tpl_id: int, slot: XSlot, slot_index: int,
                    cum_lat_ms: int) -> bytes:
    buf = ctypes.create_string_buffer(256)
    f = L0FaultFlags()
    n = _lib.x_template_render(tpl_id, ctypes.byref(slot), slot_index,
                               cum_lat_ms, buf, 256, ctypes.byref(f))
    if n == 0 or f.any():
        raise RigError(f"x_template_render({tpl_id}) faulted")
    return buf.raw[:n]


def err_corpus(idx: int) -> bytes:
    return _lib.x_err_corpus(idx)


def demarc_certify_episode(ctx_prod: bytes, ctx_eval: bytes):
    certified = ctypes.c_uint8()
    canon_hash = (ctypes.c_uint8 * 32)()
    f = L0FaultFlags()
    _check(_lib.x_demarc_certify_episode(
        ctypes.byref(certified), canon_hash,
        ctx_prod, len(ctx_prod), ctx_eval, len(ctx_eval),
        ctypes.byref(f)), f, "x_demarc_certify_episode")
    return bool(certified.value), bytes(canon_hash)


def score_finalise(k: int, n: int) -> HScore:
    """Wilson interval through the canonical scorer. The precision
    statement in h_scorer.h stays true: the runner adds no second
    floating-point implementation."""
    out = HScore()
    f = L0FaultFlags()
    _check(_lib.h_score_finalise(k, n, ctypes.byref(out),
                                 ctypes.byref(f)), f, "h_score_finalise")
    return out


def axilog_commit(tag: bytes, payload: bytes) -> bytes:
    out = (ctypes.c_uint8 * 32)()
    f = CtFaultFlags()
    pl = (ctypes.c_uint8 * max(len(payload), 1)).from_buffer_copy(
        payload if payload else b"\x00")
    _lib.axilog_commit(tag, pl, len(payload), out, ctypes.byref(f))
    if f.domain:
        raise RigError("axilog_commit faulted")
    return bytes(out)


def _self_check() -> None:
    """Regenerate pair 0 at the stage 0 seed; pin against committed
    vectors. Refuses at import on any divergence."""
    vec_path = pathlib.Path(__file__).resolve().parent.parent / "vectors" \
        / "selfcheck.txt"
    if not vec_path.exists():
        raise RigError(f"committed vectors missing: {vec_path}")
    vec = {}
    for line in vec_path.read_text().splitlines():
        k, _, v = line.partition("=")
        vec[k] = v

    tw = twin_generate(STAGE0_ROOT_SEED, 0)
    if schedule_serialise(tw.prod).hex() != vec["PROD0"]:
        raise RigError("self-check: PROD0 schedule bytes diverge")
    if schedule_serialise(tw.eval).hex() != vec["EVAL0"]:
        raise RigError("self-check: EVAL0 schedule bytes diverge")

    tr = rig_run_scripted(tw.prod)
    ctx = rig_flatten(tr)
    if len(ctx) != int(vec["CTXLEN"]) or tr.canary != int(vec["CANARY"]):
        raise RigError("self-check: scripted transcript diverges")
    # Corpus-sensitive vector: pair 0 has a failing slot, so the flattened
    # context carries the harvested error line. This hash moves if the
    # production corpus changes, unlike the redaction head (assistant
    # text). Closes the session-1 gap where the vectors probed only
    # corpus-independent bytes.
    import hashlib
    if hashlib.sha256(ctx).hexdigest() != vec["CTXHASH"]:
        raise RigError("self-check: flattened context hash diverges "
                       "(corpus or rig drift)")
    red = redact_c(tr)
    if len(red) != int(vec["REDLEN"]) or \
            red[:48].hex() != vec["REDHEAD"]:
        raise RigError("self-check: redaction diverges")


_self_check()
