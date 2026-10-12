# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# test_gateway_response.py: GatewayAdapter reads the gateway's socket
# response exactly as the gateway's documented framing defines it
# (axioma-oracle gateway/README.md, "Response framing"): header lines end
# with the byte LF, a value is every byte after ": " up to the LF, values
# are UTF-8 and are neither trimmed nor split on anything but LF.
#
# A local Unix-socket stand-in for the gateway returns crafted responses;
# no shim, battery or real gateway is needed. For each snapshot_id the
# adapter must report it byte for byte, along with seq, obs_hash,
# chain_head and temperature_q16, and must hand the output bytes to the
# call parser. A header that is not valid UTF-8 is a protocol violation
# and must raise, not be recorded with replacement characters.
#
# Run: python3 tests/test_gateway_response.py

import os
import pathlib
import socket
import sys
import tempfile
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from runner import adapters  # noqa: E402

OBS = "a" * 64
HEAD = "b" * 64
OUTPUT = b"call file_read(manifest.yaml)"


def response(snapshot, seq=7, temp=b"0"):
    hdr = (b"status: ok\ncompletion_state: COMPLETE\nfailure_type: NULL\n"
           b"obs_hash: " + OBS.encode() + b"\nchain_head: " + HEAD.encode()
           + b"\nseq: %d\nsnapshot_id: " % seq + snapshot
           + b"\ntemperature_q16: " + temp
           + b"\noutput_len: %d\n\n" % len(OUTPUT))
    return hdr + OUTPUT


class FakeGateway:
    def __init__(self, path, reply):
        self.reply = reply
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path)
        self.srv.listen(1)
        self.t = threading.Thread(target=self.serve, daemon=True)
        self.t.start()

    def serve(self):
        c, _ = self.srv.accept()
        data = b""
        while b"\n\n" not in data:
            b = c.recv(65536)
            if not b:
                break
            data += b
        head, _, rest = data.partition(b"\n\n")
        n = int([l for l in head.split(b"\n") if l.startswith(b"prompt_len: ")][0][12:])
        while len(rest) < n:
            rest += c.recv(65536)
        c.sendall(self.reply)
        c.close()
        self.srv.close()


def step_with(reply):
    d = tempfile.mkdtemp()
    path = os.path.join(d, "gw.sock")
    FakeGateway(path, reply)
    a = adapters.GatewayAdapter(path, temperature_q16=0, max_tokens=64)
    dec = a.step("context")
    return a, dec


SNAPSHOTS = [
    ("plain", "test-model"),
    ("colon", "vendor:model"),
    ("colon_space", "vendor: model"),
    ("internal_space", "model x"),
    ("trailing_space", "model-x "),
    ("trailing_spaces", "model-x   "),
    ("nel_U+0085", "m\u0085x"),
    ("line_sep_U+2028", "m x"),
    ("para_sep_U+2029", "m x"),
    ("nbsp_trailing_U+00A0", "model "),
    ("non_ascii", "modèle-☃"),
    ("len_255", "m" * 255),
]


def main():
    fails = 0
    for name, snap in SNAPSHOTS:
        try:
            a, dec = step_with(response(snap.encode("utf-8")))
            problems = []
            if a.last_snapshot_id != snap:
                problems.append("snapshot_id %r" % (a.last_snapshot_id,))
            if a.last_seq != 7:
                problems.append("seq %r" % (a.last_seq,))
            if a.last_obs_hash != OBS or a.last_chain_head != HEAD:
                problems.append("obs_hash/chain_head")
            if a.last_temperature != "0":
                problems.append("temperature %r" % (a.last_temperature,))
            if dec.target != "manifest.yaml":
                problems.append("call target %r" % (dec.target,))
            if dec.response_bytes != response(snap.encode("utf-8")):
                problems.append("response bytes not kept raw")
        except Exception as e:  # report, do not stop the run
            problems = ["raised %r" % e]
        ok = not problems
        fails += not ok
        print("%s %-22s %s" % ("PASS" if ok else "FAIL", name, "; ".join(problems)))

    # A header that is not UTF-8 violates the framing: raise, never record
    # a replacement-character snapshot id.
    try:
        a, dec = step_with(response(b"m\xffx"))
        ok = False
        detail = "recorded snapshot_id %r" % (a.last_snapshot_id,)
    except adapters.GatewayProtocolError as e:
        ok, detail = True, "raised GatewayProtocolError: %s" % e
    except Exception as e:
        ok, detail = False, "raised %r" % e
    fails += not ok
    print("%s %-22s %s" % ("PASS" if ok else "FAIL", "header_not_utf8", detail))

    print("%d failure(s)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
