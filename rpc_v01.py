"""Minimal JSON-RPC client for a BSV node (standard library only)."""

import base64
import json
import os
import urllib.error
import urllib.request

URL = os.environ.get("BSV_RPC_URL", "http://127.0.0.1:18432")
USER = os.environ.get("BSV_RPC_USER", "prover")
PASS = os.environ.get("BSV_RPC_PASS", "prover")


class RPCError(Exception):
    def __init__(self, code, message):
        super().__init__("%s: %s" % (code, message))
        self.code, self.message = code, message


def call(method, *params):
    body = json.dumps({"jsonrpc": "1.0", "id": "x", "method": method,
                       "params": list(params)}).encode()
    req = urllib.request.Request(URL, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": "Basic " + base64.b64encode(("%s:%s" % (USER, PASS)).encode()).decode()})
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            out = json.load(r)
    except urllib.error.HTTPError as e:
        out = json.loads(e.read().decode())
    if out.get("error"):
        raise RPCError(out["error"].get("code"), out["error"].get("message"))
    return out["result"]
