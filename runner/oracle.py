# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# oracle.py: the AX:OBS:v1 oracle record (Pack B, B1, design section 10).
#
# Every model call that crosses the oracle boundary commits one record
# with the five fields the design names: episode id, call index, model
# snapshot id, request hash, response hash. The record is the thing that
# makes a sampled (D3) model call evidence: the model is not
# deterministic, but the exact bytes in and out, and which snapshot
# produced them, are committed and replayable.
#
# Adapter split (ruled, B1):
#   Gateway adapter. The gateway commits its OWN AX:OBS record to its
#     durable chain. The runner's record cross-references the gateway
#     seq (and its obs_hash and chain_head, when the adapter parsed
#     them), so the two chains are tied without the runner duplicating
#     the gateway's authority. snapshot_id is the gateway-reported model
#     snapshot.
#   Local adapter. No gateway, so the runner IS the oracle authority: it
#     commits the five-field record itself, request and response hashes
#     over the exact bytes sent to and returned from the local model,
#     and snapshot_id ruled as the SHA-256 of the local model file (the
#     honest local analogue of a provider snapshot id).
#
# The record is a fixed-layout binary payload so the serialisation is a
# committed protocol, not a JSON whim: an independent reader recomputes
# it byte for byte. Hashes are SHA-256 (32 bytes) via the substrate
# commit primitive's hash, so no second hash implementation enters.

import hashlib
import struct

from runner import chain as chain_mod

# AX:OBS:v1 oracle payload layout (fixed, little-endian):
#   magic          4  b"OBS1"
#   episode_id     8  u64
#   call_index     4  u32
#   source         1  u8   (0 local, 1 gateway)
#   _pad           3
#   gateway_seq    8  u64  (X_SEQ_NONE if local)
#   snapshot_id   32  SHA-256
#   request_hash  32  SHA-256
#   response_hash 32  SHA-256
# = 124 bytes.
OBS_MAGIC = b"OBS1"
OBS_SER_BYTES = 124
X_SEQ_NONE = 0xFFFFFFFFFFFFFFFF

SOURCE_LOCAL = 0
SOURCE_GATEWAY = 1


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def snapshot_id_of_file(path: str) -> bytes:
    """The local snapshot id: SHA-256 of the model file. The honest
    local analogue of a provider snapshot id (B1 ruling). Read in
    chunks so a multi-GB weight file does not land in memory."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


def build_obs_payload(episode_id: int, call_index: int, source: int,
                      snapshot_id: bytes, request_bytes: bytes,
                      response_bytes: bytes,
                      gateway_seq: int = X_SEQ_NONE) -> bytes:
    """Assemble one AX:OBS:v1 oracle payload. request_bytes and
    response_bytes are the EXACT bytes on the wire; their hashes go in
    the record, not the bytes themselves (the transcript carries the
    content, the ledger carries the commitment)."""
    if len(snapshot_id) != 32:
        raise ValueError("snapshot_id must be 32 bytes (SHA-256)")
    payload = (
        OBS_MAGIC
        + struct.pack("<Q", episode_id)
        + struct.pack("<I", call_index)
        + struct.pack("<B", source)
        + b"\x00\x00\x00"
        + struct.pack("<Q", gateway_seq)
        + snapshot_id
        + _sha256(request_bytes)
        + _sha256(response_bytes)
    )
    assert len(payload) == OBS_SER_BYTES, len(payload)
    return payload


def parse_obs_payload(payload: bytes) -> dict:
    """Inverse of build_obs_payload, for the replay/verify path and
    tests. Raises on a malformed record."""
    if len(payload) != OBS_SER_BYTES or payload[:4] != OBS_MAGIC:
        raise ValueError("not an AX:OBS:v1 oracle payload")
    episode_id, = struct.unpack_from("<Q", payload, 4)
    call_index, = struct.unpack_from("<I", payload, 12)
    source, = struct.unpack_from("<B", payload, 16)
    gateway_seq, = struct.unpack_from("<Q", payload, 20)
    snapshot_id = payload[28:60]
    request_hash = payload[60:92]
    response_hash = payload[92:124]
    return {
        "episode_id": episode_id,
        "call_index": call_index,
        "source": source,
        "gateway_seq": gateway_seq,
        "snapshot_id": snapshot_id,
        "request_hash": request_hash,
        "response_hash": response_hash,
    }


def commit_obs(evidence_chain, episode_id: int, call_index: int,
               source: int, snapshot_id: bytes, request_bytes: bytes,
               response_bytes: bytes,
               gateway_seq: int = X_SEQ_NONE) -> bytes:
    """Commit one oracle record to the evidence chain under AX:OBS:v1.
    Returns the payload committed."""
    payload = build_obs_payload(episode_id, call_index, source,
                                snapshot_id, request_bytes,
                                response_bytes, gateway_seq)
    evidence_chain.append(chain_mod.TAG_OBS, payload)
    return payload
