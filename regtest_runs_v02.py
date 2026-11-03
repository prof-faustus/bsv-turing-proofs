"""Run the constructions on a real BSV node (bitcoin-sv 1.2.3, regtest, Chronicle active).

Every construction is placed in a funded output, spent by a transaction submitted to the node
with sendrawtransaction, and mined. Every test also submits a tampered spend that the node must
refuse. Before the node is used, the Chronicle dialect of the covenant is checked in the 0.1.5
model.

    python regtest_runs_v02.py      (node RPC at BSV_RPC_URL, default http://127.0.0.1:18432)
Writes regtest_results_v02.json and regtest_results_v02.txt.

v02 (3 November 2026): the covenants use covenant_v02 / chronicle_v02, whose CODE requires the
five fixed transaction fields to have their serialised widths. Added node controls: two forged
spends of each covenant (a second output; a successor carrying substituted code), built by
cutting the real preimage into the fields CODE concatenates, must be refused; the same two
forged spends of a covenant built with covenant_v01 are accepted and mined, and the hijacked
successor is then spent with an empty unlocking script, so the controls can fail.
"""

import hashlib
import itertools
import json
import os
import struct
import sys
import time

import script015_v01 as V1
import script015_v02 as M
import tx015_v01 as TX
import secp256k1_v01 as EC
import constructions_v01 as C
import covenant_v01 as CV1
import chronicle_v01 as CH1
import covenant_v02 as CV
import chronicle_v02 as CH
import rpc_v01 as R

HERE = os.path.dirname(os.path.abspath(__file__))
out = {"node": {}, "checks": [], "records": [], "files": {}}
failures = 0
VALUE = 1_000_000
FEE = 2_000
D_B = 0xBEEF


def check(name, cond, detail=""):
    global failures
    out["checks"].append({"name": name, "pass": bool(cond), "detail": detail})
    if not cond:
        failures += 1
    print(("PASS " if cond else "FAIL ") + name + (" | " + detail if detail else ""), flush=True)


def successor(tm, st, k):
    for _ in range(k):
        st = tm.step(st)
    return st


# ------------------------------------------------------------------ 0. dialect in the model
abc = CV.abc_machine()
code015 = CH.build_code_015(abc, 2, EC.pubkey_bytes(D_B))
st = (b"", b"abbcc", b"a", abc.q0)
prev = TX.Tx(2, [TX.TxIn(b"\x00" * 32, 0xFFFFFFFF, b"\x01\x01")],
             [TX.TxOut(VALUE, CV.locking_script(st, code015))])
value, ok, n = VALUE, True, 0
while st[3] not in abc.halting:
    nxt = successor(abc, st, 2)
    value -= FEE
    tx = TX.Tx(2, [TX.TxIn(TX.txid(prev), 0)], [TX.TxOut(value, CV.locking_script(nxt, code015))])
    tx.vin[0].script_sig = CV.unlocking_covenant(2, TX.txid(prev) + struct.pack("<I", 0),
                                                 0xFFFFFFFF, value, 0, code015)
    ok &= M.verify_signature(prev, tx, 0)
    prev, st, n = tx, nxt, n + 1
check("model: Chronicle-dialect covenant (hash type 0x61, guarded reversal, version 2) carries "
      "a^k b^k c^k on aabbcc to acceptance", ok and st[3] == abc.acc, "%d transactions" % n)
code_chr = CH.translate(code015)
ops015, opschr = [], []
for s, acc in ((code015, ops015), (code_chr, opschr)):
    pc = 0
    while pc < len(s):
        _ok, opc, _v, pc = V1.get_op(s, pc)
        acc.append(opc)
changed = [(a, b) for a, b in zip(ops015, opschr) if a != b]
check("translation changes only OP_SUBSTR/OP_LEFT/OP_RIGHT and preserves every push",
      len(ops015) == len(opschr) and all(a in CH.MAP_015_TO_CHRONICLE and
                                         CH.MAP_015_TO_CHRONICLE[a] == b for a, b in changed),
      "%d operations, %d remapped" % (len(ops015), len(changed)))

# ------------------------------------------------------------------ 1. node
net = R.call("getnetworkinfo")
chain = R.call("getblockchaininfo")
out["node"] = {"subversion": net["subversion"], "version": net["version"],
               "chain": chain["chain"]}
check("node is bitcoin-sv 1.2.3 on regtest", net["subversion"] == "/Bitcoin SV:1.2.3/"
      and chain["chain"] == "regtest", net["subversion"])
ADDR = R.call("getnewaddress")
R.call("generatetoaddress", 101, ADDR)
SPK_WALLET = bytes.fromhex(R.call("validateaddress", ADDR)["scriptPubKey"])


def mine():
    return R.call("generatetoaddress", 1, ADDR)[0]


def fund(script, value=VALUE):
    raw = TX.ser_tx(TX.Tx(2, [], [TX.TxOut(value, script)], 0)).hex()
    funded = R.call("fundrawtransaction", raw)
    signed = R.call("signrawtransaction", funded["hex"])
    if not signed.get("complete"):
        raise RuntimeError("wallet could not sign funding transaction")
    txid = R.call("sendrawtransaction", signed["hex"])
    blk = mine()
    t = R.call("getrawtransaction", txid, True)
    vout = [o["n"] for o in t["vout"] if o["scriptPubKey"]["hex"] == script.hex()][0]
    return txid, vout, blk


def spend_tx(txid, vout, unlocking, outputs, version=2):
    return TX.Tx(version, [TX.TxIn(bytes.fromhex(txid)[::-1], vout, unlocking, 0xFFFFFFFF)],
                 outputs, 0)


def submit(tx):
    try:
        return True, R.call("sendrawtransaction", TX.ser_tx(tx).hex())
    except R.RPCError as e:
        return False, e.message


def mined(txid):
    blk = mine()
    t = R.call("getrawtransaction", txid, True)
    return t.get("confirmations", 0) >= 1 and t.get("blockhash") == blk, blk


def record(**kw):
    out["records"].append(kw)


# ------------------------------------------------------------------ 2. Turing machines
tm, sigma, member = C.tm_abc()
tm2, sigma2, member2 = C.tm_pow2()
a, b, c = sigma
cases = [
    ("a^k b^k c^k", tm, 6, [a, a, b, b, c, c], [a, a, b, b, b, c], sigma),
    ("a^k b^k c^k", tm, 9, [a] * 3 + [b] * 3 + [c] * 3, [a] * 3 + [b] * 3 + [c] * 2 + [a], sigma),
    ("0^(2^k)", tm2, 64, [1] * 64, None, sigma2),
    ("0^(2^k)", tm2, 48, None, [1] * 48, sigma2),
]
for name, m, n, good, bad, alphabet in cases:
    inputs = [list(w) for w in itertools.product(alphabet, repeat=n)] if len(alphabet) ** n <= 20000 \
        else [w for w in (good, bad) if w is not None]
    T = max(m.run(w)[1] for w in inputs)
    lock = C.compile_tm(m, n, T)
    t0 = time.time()
    txid, vout, fblk = fund(lock)
    outs = [TX.TxOut(VALUE - FEE, SPK_WALLET)]
    if bad is not None:
        okb, msg = submit(spend_tx(txid, vout, C.unlock_tm(bad), outs))
        check("node refuses %s n=%d on a non-member" % (name, n), not okb, msg)
    if good is not None:
        okg, sid = submit(spend_tx(txid, vout, C.unlock_tm(good), outs))
        conf, blk = mined(sid) if okg else (False, None)
        check("node accepts and mines %s n=%d on a member" % (name, n), okg and conf,
              "script %d bytes, T=%d, spend %s" % (len(lock), T, sid if okg else sid))
    record(kind="turing", machine=name, n=n, T=T, script_bytes=len(lock), funding_txid=txid,
           seconds=round(time.time() - t0, 1))

# ------------------------------------------------------------------ 3. Ackermann
for (m_, n_) in ((2, 3), (3, 3), (3, 4)):
    val, steps = C.ackermann(m_, n_)
    lock = C.ackermann_lock(steps)
    txid, vout, fblk = fund(lock)
    outs = [TX.TxOut(VALUE - FEE, SPK_WALLET)]
    okb, msg = submit(spend_tx(txid, vout, C.ackermann_unlock(val + 1, m_, n_), outs))
    check("node refuses A(%d,%d) claimed as %d" % (m_, n_, val + 1), not okb, msg)
    okg, sid = submit(spend_tx(txid, vout, C.ackermann_unlock(val, m_, n_), outs))
    conf, blk = mined(sid) if okg else (False, None)
    check("node accepts and mines A(%d,%d)=%d (%d iterations)" % (m_, n_, val, steps),
          okg and conf, "script %d bytes, spend %s" % (len(lock), sid))
    record(kind="ackermann", m=m_, n=n_, A=val, iterations=steps, script_bytes=len(lock),
           funding_txid=txid, spend_txid=sid if okg else None)


# ------------------------------------------------------------------ 4. covenant chains
def chronicle_payout(prev_txid, prev_vout, value_in, lock, d_sign):
    pay = spend_tx(prev_txid, prev_vout, b"", [TX.TxOut(value_in - FEE, SPK_WALLET)])
    h = TX.signature_hash(lock, pay, 0, CH.SIGHASH_ALL_CHRONICLE_FORKID)
    sig = CH.low_s_sign(d_sign, int.from_bytes(h, "big"), 0x5EED) + bytes(
        [CH.SIGHASH_ALL_CHRONICLE_FORKID])
    pay.vin[0].script_sig = V1.Script().data(sig).bytes()
    return pay


def covenant_tx(prev_txid, prev_vout, nxt, value_out, code, extra=None, code_supplied=None,
                value_field=None):
    tx = spend_tx(prev_txid, prev_vout, b"", [TX.TxOut(value_out, CV.locking_script(nxt, code))])
    if extra is not None:
        tx.vout.append(extra)
    tx.vin[0].script_sig = CV.unlocking_covenant(
        2, bytes.fromhex(prev_txid)[::-1] + struct.pack("<I", prev_vout), 0xFFFFFFFF,
        value_field if value_field is not None else value_out, 0,
        code_supplied if code_supplied is not None else code)
    return tx


def at(m, i, x):
    return m[i:i + len(x)] == x


def cuts(m, sc, spk, widths):
    """Every cut of the preimage m into ver' 01 out' cs(sc) sc seq' 01 val' cs(spk) spk lt' HT;
    with widths=True only cuts whose five free fields are 4, 36, 4, 8 and 4 bytes."""
    A, B = TX.ser_vec(sc), TX.ser_vec(spk)
    found = []
    for i in range(len(m) - len(A) + 1):
        if not at(m, i, A):
            continue
        for j in range(i + len(A), len(m) - len(B) - 4 + 1):
            if not at(m, j, B):
                continue
            for p in range(0, i):
                if m[p] != 1:
                    continue
                for r in range(i + len(A), j):
                    if m[r] != 1:
                        continue
                    f = (m[:p], m[p + 1:i], m[i + len(A):r], m[r + 1:j], m[j + len(B):len(m) - 4])
                    if widths and tuple(len(x) for x in f) != (4, 36, 4, 8, 4):
                        continue
                    found.append(f)
    return found


def node_forgeries(txid, vout, value_out, lock, nxt, code, cvmod):
    """The two forged spends of a covenant output (second output; substituted code OP_1),
    each filled with the first cut of its real preimage under hash type 0x61. Returns
    [(name, tx, cuts, cuts with serialised widths, successor script of the hijack)]."""
    enc_old = lock[:len(lock) - len(code)]
    enc_new = cvmod.locking_script(nxt, b"")
    prevout = bytes.fromhex(txid)[::-1]
    ta = TX.Tx(2, [TX.TxIn(prevout, vout, b"", 0xFFFFFF01)],
               [TX.TxOut(value_out - 1000, cvmod.locking_script(nxt, code)),
                TX.TxOut(1000, SPK_WALLET)], 0)
    code_s = bytes([V1.OP_1])
    v1 = ((value_out - 1000 - 256) & ~0xFF) | 0x01
    tb = TX.Tx(2, [TX.TxIn(prevout, vout, b"", 0xFFFFFFFF)],
               [TX.TxOut(1000, enc_old + code_s), TX.TxOut(v1, enc_new + code_s)], 0)
    res = []
    for name, tx, cs_ in (("a second output", ta, code), ("substituted code", tb, code_s)):
        m = TX.preimage(lock, tx, 0, TX.SIGHASH_ALL)[:-4] + struct.pack(
            "<i", CH.SIGHASH_ALL_CHRONICLE_FORKID)
        c = cuts(m, enc_old + cs_, enc_new + cs_, False)
        if c:
            ver, outp, seq, val, lt = c[0]
            tx.vin[0].script_sig = V1.Script().data(ver).data(outp).data(seq).data(val) \
                .data(lt).data(cs_).bytes()
        res.append((name, tx, len(c), len(cuts(m, enc_old + cs_, enc_new + cs_, True))))
    return res


def run_covenant(machine, state, k, max_tx, label, controls):
    code = CH.translate(CH.build_code_015(machine, k, EC.pubkey_bytes(D_B)))
    lock = CV.locking_script(state, code)
    txid, vout, _ = fund(lock)
    value, n, txids = VALUE, 0, []
    while state[3] not in machine.halting and n < max_tx:
        nxt = successor(machine, state, k)
        vnext = value - FEE
        if controls and n == 0:
            wrong = (nxt[0], nxt[1], nxt[2], machine.states[0] if nxt[3] != machine.states[0]
                     else machine.states[1])
            okw, msg = submit(covenant_tx(txid, vout, wrong, vnext, code))
            check("%s: node refuses a successor with the wrong machine state" % label, not okw, msg)
            tape = nxt[1] if nxt[1] else nxt[0]
            if tape:
                fl = bytes([tape[0] ^ 1]) + tape[1:]
                wrong2 = (nxt[0], fl, nxt[2], nxt[3]) if nxt[1] else (fl, nxt[1], nxt[2], nxt[3])
                okw, msg = submit(covenant_tx(txid, vout, wrong2, vnext, code))
                check("%s: node refuses a successor with one tape cell altered" % label, not okw,
                      msg)
            okw, msg = submit(covenant_tx(txid, vout, nxt, vnext, code,
                                          extra=TX.TxOut(1000, SPK_WALLET)))
            check("%s: node refuses a second output" % label, not okw, msg)
            okw, msg = submit(covenant_tx(txid, vout, nxt, vnext, code,
                                          code_supplied=code + bytes([V1.OP_NOP])))
            check("%s: node refuses substituted code" % label, not okw, msg)
            okw, msg = submit(covenant_tx(txid, vout, nxt, vnext, code, value_field=vnext - 1))
            check("%s: node refuses a misstated transaction field" % label, not okw, msg)
            okw, msg = submit(chronicle_payout(txid, vout, value, lock, D_B))
            check("%s: node refuses payout before acceptance" % label, not okw, msg)
            for name, ftx, n_c, n_w in node_forgeries(txid, vout, vnext, lock, nxt, code, CV):
                okw, msg = submit(ftx)
                check("%s: node refuses a forged spend with %s" % (label, name),
                      n_c > 0 and n_w == 0 and not okw,
                      "%d cuts, none with serialised widths; %s" % (n_c, msg))
        tx = covenant_tx(txid, vout, nxt, vnext, code)
        okc, sid = submit(tx)
        if not okc:
            check("%s: node accepts covenant step %d" % (label, n + 1), False, sid)
            return None
        conf, _blk = mined(sid)
        if not conf:
            check("%s: covenant step %d mined" % (label, n + 1), False)
            return None
        txids.append(sid)
        txid, vout, value, state, lock, n = sid, 0, vnext, nxt, CV.locking_script(nxt, code), n + 1
    return {"code_bytes": len(code), "transactions": n, "state": state, "last_txid": txid,
            "last_vout": vout, "value": value, "lock": lock, "txids": txids}


for word in (b"aabbcc", b"aabbc"):
    st0 = (b"", word[1:], word[:1], abc.q0)
    res = run_covenant(abc, st0, 2, 100, "covenant a^k b^k c^k on %s" % word.decode(),
                       controls=(word == b"aabbcc"))
    ref = st0
    while ref[3] not in abc.halting:
        ref = abc.step(ref)
    if res is None:
        continue
    check("covenant on %s: %d consecutive transactions accepted and mined by the node" %
          (word.decode(), res["transactions"]), True, res["last_txid"])
    check("covenant on %s: final on-chain state equals the reference machine's" % word.decode(),
          res["state"] == ref, res["state"][3].decode())
    if res["state"][3] == abc.acc:
        okw, msg = submit(chronicle_payout(res["last_txid"], res["last_vout"], res["value"],
                                           res["lock"], D_B + 1))
        check("covenant on %s: node refuses payout signed by another key" % word.decode(),
              not okw, msg)
        okp, pid = submit(chronicle_payout(res["last_txid"], res["last_vout"], res["value"],
                                           res["lock"], D_B))
        conf, _ = mined(pid) if okp else (False, None)
        check("covenant on %s: beneficiary paid after acceptance, mined" % word.decode(),
              okp and conf, pid)
    else:
        okp, msg = submit(chronicle_payout(res["last_txid"], res["last_vout"], res["value"],
                                           res["lock"], D_B))
        check("covenant on %s: node refuses payout after rejection" % word.decode(), not okp, msg)
    record(kind="covenant", machine=abc.name, input=word.decode(), k=2,
           code_bytes=res["code_bytes"], transactions=res["transactions"],
           final_state=res["state"][3].decode(), txids=res["txids"])

# the same forged spends against a covenant built with covenant_v01 (no field-width test)
st0 = (b"", b"abbcc", b"a", abc.q0)
nxt0 = successor(abc, st0, 2)
code_v1 = CH1.translate(CH1.build_code_015(abc, 2, EC.pubkey_bytes(D_B)))
for name_i in range(2):
    lock_v1 = CV1.locking_script(st0, code_v1)
    txid1, vout1, _ = fund(lock_v1)
    name, ftx, n_c, _n_w = node_forgeries(txid1, vout1, VALUE - FEE, lock_v1, nxt0, code_v1,
                                          CV1)[name_i]
    okf, fid = submit(ftx)
    conf, _ = mined(fid) if okf else (False, None)
    check("covenant_v01 (no field-width test): node accepts and mines a forged spend with %s"
          % name, okf and conf, "%d cuts; %s" % (n_c, fid))
    if okf and name == "substituted code":
        steal = spend_tx(fid, 1, b"", [TX.TxOut(ftx.vout[1].value - FEE, SPK_WALLET)])
        oks, sid = submit(steal)
        conf, _ = mined(sid) if oks else (False, None)
        check("covenant_v01: the hijacked successor is spent with an empty unlocking script",
              oks and conf, sid)

cnt = CV.counter_machine()
st0 = (b"", b"", b"_", cnt.q0)
res = run_covenant(cnt, st0, 4, 60, "covenant binary counter", controls=True)
if res is not None:
    ref = successor(cnt, st0, 4 * res["transactions"])
    check("counter covenant: %d consecutive transactions accepted and mined (%d machine steps)"
          % (res["transactions"], 4 * res["transactions"]), res["transactions"] == 60,
          res["last_txid"])
    check("counter covenant: on-chain state equals the reference machine's", res["state"] == ref)
    record(kind="covenant", machine=cnt.name, k=4, code_bytes=res["code_bytes"],
           transactions=res["transactions"], txids=res["txids"])

for f in sorted(os.listdir(HERE)):
    if f.endswith(".py"):
        with open(os.path.join(HERE, f), "rb") as fh:
            out["files"][f] = hashlib.sha256(fh.read()).hexdigest()
out["time_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
out["failures"] = failures
with open(os.path.join(HERE, "regtest_results_v02.json"), "w", encoding="utf-8") as fh:
    json.dump(out, fh, indent=1)
with open(os.path.join(HERE, "regtest_results_v02.txt"), "w", encoding="utf-8") as fh:
    for c_ in out["checks"]:
        fh.write(("PASS " if c_["pass"] else "FAIL ") + c_["name"]
                 + (" | " + c_["detail"] if c_["detail"] else "") + "\n")
    fh.write("\nfailures: %d\n" % failures)
print("\nfailures:", failures)
