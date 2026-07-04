# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# chain.py: the framed evidence file in the gateway's record format
# (gw_ledger.c), so both adapter tiers replay the same way.
#
# Frame:   u32le tag_len | tag | u64le payload_len | payload | commit[32]
# Commit:  SHA-256(tag || LE64(payload_len) || payload)
# Genesis: e0 = commit("AX:STATE:v1", AX_GENESIS_PAYLOAD)
#          L0 = SHA-256("AX:LEDGER:v1" || e0)
# Extend:  Ln = SHA-256("AX:LEDGER:v1" || Ln-1 || commit)
#
# The construction is pinned by axioma-audit (audit.h, SRS-006) and the
# commit primitive is cross-checked against the substrate's
# axilog_commit through the shim in tests. Replay recomputes every
# commit and every link; a divergent stored commit refuses, same as the
# gateway.

import hashlib
import os
import struct

CHAIN_TAG = b"AX:LEDGER:v1"
TAG_STATE = b"AX:STATE:v1"
TAG_TRANS = b"AX:TRANS:v1"
TAG_OBS = b"AX:OBS:v1"
TAG_POLICY = b"AX:POLICY:v1"
TAG_PROOF = b"AX:PROOF:v1"
REGISTERED_TAGS = frozenset({TAG_STATE, TAG_TRANS, TAG_OBS,
                             TAG_POLICY, TAG_PROOF})

# Byte-identical to AX_GENESIS_PAYLOAD in axioma-audit audit.h.
GENESIS_PAYLOAD = (
    b'{"component":"axilog-core",'
    b'"evidence_type":"AX:STATE:v1",'
    b'"is_terminal":false,'
    b'"platform":"universal",'
    b'"state_hash":"'
    + b"0" * 64 +
    b'"}'
)

GWL_TAG_MAX = 32
GWL_PAYLOAD_MAX = 1 << 20  # generous; gateway bound is config-side


class ChainError(RuntimeError):
    pass


def commit(tag: bytes, payload: bytes) -> bytes:
    """axilog_commit construction (SRS-007): domain-separated SHA-256."""
    h = hashlib.sha256()
    h.update(tag)
    h.update(struct.pack("<Q", len(payload)))
    h.update(payload)
    return h.digest()


def genesis_head() -> bytes:
    e0 = commit(TAG_STATE, GENESIS_PAYLOAD)
    return hashlib.sha256(CHAIN_TAG + e0).digest()


def extend(prev_head: bytes, cmt: bytes) -> bytes:
    return hashlib.sha256(CHAIN_TAG + prev_head + cmt).digest()


class EvidenceChain:
    """Append-only framed evidence file. Open replays from genesis,
    recomputing every commit and every link; the file is the truth."""

    def __init__(self, path: str):
        self.path = path
        self.head = genesis_head()
        self.seq = 0
        self._fd = None
        self._replay_open()

    def _replay_open(self) -> None:
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o640)
        try:
            off = 0
            size = os.fstat(fd).st_size
            while off < size:
                frame_start = off
                hdr = os.pread(fd, 4, off)
                if len(hdr) < 4:
                    raise ChainError(f"torn frame header at {frame_start}")
                (tag_len,) = struct.unpack("<I", hdr)
                if tag_len == 0 or tag_len > GWL_TAG_MAX:
                    raise ChainError(f"bad tag_len {tag_len} at {frame_start}")
                off += 4
                tag = os.pread(fd, tag_len, off)
                if len(tag) < tag_len:
                    raise ChainError(f"torn tag at {frame_start}")
                off += tag_len
                p8 = os.pread(fd, 8, off)
                if len(p8) < 8:
                    raise ChainError(f"torn payload_len at {frame_start}")
                (plen,) = struct.unpack("<Q", p8)
                if plen == 0 or plen > GWL_PAYLOAD_MAX:
                    raise ChainError(f"bad payload_len {plen} at {frame_start}")
                off += 8
                payload = os.pread(fd, plen, off)
                if len(payload) < plen:
                    raise ChainError(f"torn payload at {frame_start}")
                off += plen
                stored = os.pread(fd, 32, off)
                if len(stored) < 32:
                    raise ChainError(f"torn commit at {frame_start}")
                off += 32

                computed = commit(tag, payload)
                if computed != stored:
                    raise ChainError(
                        f"commit mismatch at frame {self.seq}: tamper or "
                        f"corruption; refusing"
                    )
                self.head = extend(self.head, computed)
                self.seq += 1
            os.lseek(fd, 0, os.SEEK_END)
            self._fd = fd
        except Exception:
            os.close(fd)
            raise

    def append(self, tag: bytes, payload: bytes) -> tuple:
        """Commit and append one frame; fsync before extending state.
        Returns (head, seq) after the append."""
        if self._fd is None:
            raise ChainError("chain not open")
        if tag not in REGISTERED_TAGS:
            raise ChainError(f"unregistered tag {tag!r}")
        if not payload or len(payload) > GWL_PAYLOAD_MAX:
            raise ChainError("payload empty or over bound")
        cmt = commit(tag, payload)
        frame = (
            struct.pack("<I", len(tag)) + tag
            + struct.pack("<Q", len(payload)) + payload + cmt
        )
        n = os.write(self._fd, frame)
        if n != len(frame):
            raise ChainError("short write")
        os.fsync(self._fd)
        self.head = extend(self.head, cmt)
        self.seq += 1
        return self.head, self.seq

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


def read_frames(path: str):
    """Verifying reader: yields (index, tag, payload, head_after).
    Raises on any commit or link divergence."""
    head = genesis_head()
    idx = 0
    with open(path, "rb") as fh:
        data = fh.read()
    off = 0
    while off < len(data):
        if off + 4 > len(data):
            raise ChainError("torn frame header")
        (tag_len,) = struct.unpack_from("<I", data, off)
        off += 4
        if tag_len == 0 or tag_len > GWL_TAG_MAX or off + tag_len > len(data):
            raise ChainError("bad tag")
        tag = data[off:off + tag_len]
        off += tag_len
        if off + 8 > len(data):
            raise ChainError("torn payload_len")
        (plen,) = struct.unpack_from("<Q", data, off)
        off += 8
        if plen == 0 or off + plen + 32 > len(data):
            raise ChainError("torn payload or commit")
        payload = data[off:off + plen]
        off += plen
        stored = data[off:off + 32]
        off += 32
        computed = commit(tag, payload)
        if computed != stored:
            raise ChainError(f"commit mismatch at frame {idx}")
        head = extend(head, computed)
        yield idx, tag, payload, head
        idx += 1
