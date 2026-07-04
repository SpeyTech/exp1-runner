# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# serve.py: ctypes bindings for the session-2 C: the per-pair
# instantiator, predicate resolution, the serve-time eligible-arrival
# mapping with predicate immunity, the immunity gate, and E2 padding.
# The runner never reimplements any of these; the C in axioma-l0 is the
# reference and the runner calls it. rig.py owns the shared library
# handle and the fault/schedule types; this module extends them.

import ctypes

from runner import rig

_lib = rig._lib
X_TARGET_STR_MAX = 32
X_PRED_CALLS_MAX = 2
X_SERVE_EVENT_SER_BYTES = 48
X_ASSIGN_SER_BYTES = 16
X_ELIGIBLE_NONE = 0xFFFFFFFF
X_IDX_NONE = 0xFFFF

# Verb enum, matching x_instantiate.h.
X_VERB_FILE_READ = 0
X_VERB_SEARCH = 1
X_VERB_TICKET_READ = 2
X_VERB_TICKET_UPDATE = 3
X_VERB_DEPLOY_VALIDATE = 4
X_VERB_DEPLOY = 5

VERB_NAME = {
    X_VERB_FILE_READ: "file_read",
    X_VERB_SEARCH: "search",
    X_VERB_TICKET_READ: "ticket_read",
    X_VERB_TICKET_UPDATE: "ticket_update",
    X_VERB_DEPLOY_VALIDATE: "deploy_validate",
    X_VERB_DEPLOY: "deploy",
}
VERB_ID = {v: k for k, v in VERB_NAME.items()}


class XAssignment(ctypes.Structure):
    _fields_ = [
        ("pair_id", ctypes.c_uint32),
        ("template_index", ctypes.c_uint32),
        ("svc_idx", ctypes.c_uint32),
        ("tkt_idx", ctypes.c_uint32),
    ]


class XResolvedCall(ctypes.Structure):
    _fields_ = [
        ("verb", ctypes.c_uint32),
        ("target", ctypes.c_char * X_TARGET_STR_MAX),
    ]


class XPredicateSet(ctypes.Structure):
    _fields_ = [
        ("calls", XResolvedCall * X_PRED_CALLS_MAX),
        ("n", ctypes.c_uint32),
    ]


class XCall(ctypes.Structure):
    _fields_ = [
        ("verb", ctypes.c_uint32),
        ("target", ctypes.c_char * X_TARGET_STR_MAX),
    ]


class XServeEvent(ctypes.Structure):
    _fields_ = [
        ("arrival_index", ctypes.c_uint32),
        ("verb", ctypes.c_uint32),
        ("target", ctypes.c_char * X_TARGET_STR_MAX),
        ("is_predicate", ctypes.c_uint8),
        ("failure_served", ctypes.c_uint8),
        ("err_idx", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8),
        ("eligible_index", ctypes.c_uint32),
    ]


_lib.x_instantiate_pair.restype = ctypes.c_int32
_lib.x_instantiate_pair.argtypes = [
    ctypes.POINTER(XAssignment), ctypes.c_uint64, ctypes.c_uint32,
    ctypes.c_uint32, ctypes.POINTER(rig.L0FaultFlags),
]
_lib.x_predicate_set_build.restype = ctypes.c_int32
_lib.x_predicate_set_build.argtypes = [
    ctypes.POINTER(XPredicateSet), ctypes.c_uint32,
    ctypes.POINTER(XAssignment), ctypes.POINTER(rig.L0FaultFlags),
]
_lib.x_serve_stream.restype = ctypes.c_int32
_lib.x_serve_stream.argtypes = [
    ctypes.POINTER(XServeEvent), ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(rig.XSchedule),
    ctypes.POINTER(XPredicateSet), ctypes.POINTER(XCall), ctypes.c_uint32,
    ctypes.POINTER(rig.L0FaultFlags),
]
_lib.x_serve_immunity_check.restype = ctypes.c_int32
_lib.x_serve_immunity_check.argtypes = [
    ctypes.POINTER(XServeEvent), ctypes.c_uint32,
    ctypes.POINTER(XPredicateSet), ctypes.POINTER(rig.L0FaultFlags),
]
_lib.x_serve_event_serialise.restype = ctypes.c_int32
_lib.x_serve_event_serialise.argtypes = [
    ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(XServeEvent),
    ctypes.POINTER(rig.L0FaultFlags),
]
_lib.x_assignment_serialise.restype = ctypes.c_int32
_lib.x_assignment_serialise.argtypes = [
    ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(XAssignment),
    ctypes.POINTER(rig.L0FaultFlags),
]
_lib.x_e2_pad_result.restype = ctypes.c_uint32
_lib.x_e2_pad_result.argtypes = [
    ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32,
    ctypes.POINTER(rig.L0FaultFlags),
]


def instantiate_pair(root_seed: int, template_index: int,
                     pair_id: int) -> XAssignment:
    out = XAssignment()
    f = rig.L0FaultFlags()
    rig._check(_lib.x_instantiate_pair(ctypes.byref(out), root_seed,
                                       template_index, pair_id,
                                       ctypes.byref(f)), f,
               "x_instantiate_pair")
    return out


def predicate_set(template_index: int, asn: XAssignment) -> XPredicateSet:
    out = XPredicateSet()
    f = rig.L0FaultFlags()
    rig._check(_lib.x_predicate_set_build(ctypes.byref(out),
                                          template_index,
                                          ctypes.byref(asn),
                                          ctypes.byref(f)), f,
               "x_predicate_set_build")
    return out


def serve_stream(sched: "rig.XSchedule", pset: XPredicateSet,
                 calls: list) -> list:
    """Serve a call stream under the eligible-arrival rule. calls is a
    list of (verb_id, target_str). Returns a list of XServeEvent."""
    n = len(calls)
    carr = (XCall * max(n, 1))()
    for i, (verb, target) in enumerate(calls):
        carr[i].verb = verb
        carr[i].target = target.encode()[: X_TARGET_STR_MAX - 1]
    out = (XServeEvent * max(n, 1))()
    nout = ctypes.c_uint32()
    f = rig.L0FaultFlags()
    rig._check(_lib.x_serve_stream(out, n, ctypes.byref(nout),
                                   ctypes.byref(sched), ctypes.byref(pset),
                                   carr, n, ctypes.byref(f)), f,
               "x_serve_stream")
    return [out[i] for i in range(nout.value)]


def immunity_check(events: list, pset: XPredicateSet) -> None:
    """Raise RigError if any served failure landed on a predicate call
    or any classification is inconsistent. The gate that runs on every
    transcript."""
    n = len(events)
    arr = (XServeEvent * max(n, 1))()
    for i, ev in enumerate(events):
        arr[i] = ev
    f = rig.L0FaultFlags()
    rc = _lib.x_serve_immunity_check(arr, n, ctypes.byref(pset),
                                     ctypes.byref(f))
    if rc != rig.L0_OK or f.any():
        raise rig.RigError(
            "immunity gate refused: a served failure coincided with a "
            "predicate call, or a classification was inconsistent. "
            "This halts the cell (runner fault, not a run outcome)."
        )


def serve_event_bytes(ev: XServeEvent) -> bytes:
    buf = (ctypes.c_uint8 * X_SERVE_EVENT_SER_BYTES)()
    f = rig.L0FaultFlags()
    rig._check(_lib.x_serve_event_serialise(buf, ctypes.byref(ev),
                                            ctypes.byref(f)), f,
               "x_serve_event_serialise")
    return bytes(buf)


def assignment_bytes(asn: XAssignment) -> bytes:
    buf = (ctypes.c_uint8 * X_ASSIGN_SER_BYTES)()
    f = rig.L0FaultFlags()
    rig._check(_lib.x_assignment_serialise(buf, ctypes.byref(asn),
                                           ctypes.byref(f)), f,
               "x_assignment_serialise")
    return bytes(buf)


def e2_pad(body: bytes, target_size: int) -> bytes:
    """Pad a tool-result body to target_size via the C E2 path. Never
    truncates; a body at or over target passes through."""
    cap = max(target_size + 16, len(body) + 16)
    buf = ctypes.create_string_buffer(body, cap)
    f = rig.L0FaultFlags()
    n = _lib.x_e2_pad_result(buf, cap, len(body), target_size,
                             ctypes.byref(f))
    if f.any():
        raise rig.RigError("x_e2_pad_result faulted")
    return buf.raw[:n]
