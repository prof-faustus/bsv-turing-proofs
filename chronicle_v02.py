"""The 0.1.5 constructions in the dialect of the BSV node after Chronicle (SV Node 1.2.x).

Differences from 0.1.5 that matter here, each read from bitcoin-sv v1.2.3 src/script:
  - opcodes.h: OP_SUBSTR, OP_LEFT, OP_RIGHT are 0xb3, 0xb4, 0xb5 (0.1.5: 0x7f, 0x80, 0x81,
    now OP_SPLIT, OP_NUM2BIN, OP_BIN2NUM). Every other opcode used here keeps its 0.1.5 value.
  - interpreter.cpp: OP_SUBSTR fails if offset >= size or len > size - offset (0.1.5
    truncated at the end), so the byte-reversal loop is guarded by a length test.
  - interpreter.cpp CheckSignatureEncoding: FORKID (0x40) is mandatory; SignatureHash uses the
    original algorithm whenever the CHRONICLE bit (0x20) is set. Hash type 0x61 =
    ALL | CHRONICLE | FORKID therefore selects the original digest of 0.1.5.
  - Version > 1 transactions are exempt from minimal-push, minimal-number, low-S, MINIMALIF,
    clean-stack and push-only-unlocking rules (EnforceNonMalleability). Spends use version 2.

translate() maps a 0.1.5 script to the Chronicle encoding operation by operation; pushed data is
copied byte for byte, so data that happens to contain 0x7f/0x80/0x81 is never touched.

v02 (3 November 2026): build_code_015 uses covenant_v02, whose CODE first requires the five
fixed transaction fields to have their serialised widths (covenant_v02.CHECK_FIELDS).
"""

import struct

import script015_v01 as V1
from script015_v01 import (Script, get_op, bn_getvch, OP_OVER, OP_SIZE, OP_NIP, OP_GREATERTHAN,
                           OP_IF, OP_ENDIF, OP_1, OP_SUBSTR, OP_SWAP, OP_CAT, OP_HASH256,
                           OP_ADD, OP_MOD, OP_CHECKSIGVERIFY, OP_DUP, OP_EQUAL, OP_ELSE,
                           OP_2DROP, OP_CHECKSIG, OP_2OVER, OP_TOALTSTACK, OP_FROMALTSTACK,
                           OP_ROT, OP_PUSHDATA4, OP_LEFT, OP_RIGHT)
import covenant_v02 as CV
import secp256k1_v01 as EC

MAP_015_TO_CHRONICLE = {OP_SUBSTR: 0xB3, OP_LEFT: 0xB4, OP_RIGHT: 0xB5}
SIGHASH_ALL_CHRONICLE_FORKID = 0x61


def translate(script):
    out, pc = bytearray(), 0
    while pc < len(script):
        start = pc
        ok, opcode, _vch, pc = get_op(script, pc)
        if not ok:
            raise ValueError("truncated script at %d" % start)
        if opcode in MAP_015_TO_CHRONICLE:
            out.append(MAP_015_TO_CHRONICLE[opcode])
        else:
            out += script[start:pc]
    return bytes(out)


def REV_GUARDED(s, maxlen):
    """[x] -> [reverse(x)]; reads byte i only when i < len(x)."""
    s.data(b"")
    for i in range(maxlen):
        s.op(OP_OVER).op(OP_SIZE).op(OP_NIP).num(i).op(OP_GREATERTHAN).op(OP_IF)
        s.op(OP_OVER).num(i).op(OP_1).op(OP_SUBSTR).op(OP_SWAP).op(OP_CAT)
        s.op(OP_ENDIF)
    s.op(OP_NIP)


def SIGN_CHRONICLE(s):
    s.op(OP_HASH256)
    REV_GUARDED(s, 32)
    s.data(b"\x00").op(OP_CAT)
    s.data(bn_getvch(EC.GX)).op(OP_ADD)
    s.data(bn_getvch(EC.N)).op(OP_MOD)
    REV_GUARDED(s, 33)
    s.op(OP_SIZE).op(OP_SWAP).op(OP_CAT)
    s.data(b"\x02").op(OP_SWAP).op(OP_CAT)
    s.data(b"\x02\x20" + EC.GX.to_bytes(32, "big")).op(OP_SWAP).op(OP_CAT)
    s.op(OP_SIZE).op(OP_SWAP).op(OP_CAT)
    s.data(b"\x30").op(OP_SWAP).op(OP_CAT)
    s.data(bytes([SIGHASH_ALL_CHRONICLE_FORKID])).op(OP_CAT)
    s.data(CV.PUB_G).op(OP_CHECKSIGVERIFY)


def build_code_015(tm, k, beneficiary_pub):
    """The covenant CODE in 0.1.5 numbering, with the two Chronicle adjustments (guarded
    reversal; hash type 0x61). Runs in the 0.1.5 model as well."""
    s = Script()
    s.op(OP_DUP).data(tm.acc).op(OP_EQUAL).op(OP_IF)
    s.op(OP_2DROP).op(OP_2DROP).data(beneficiary_pub).op(OP_CHECKSIG)
    s.op(OP_ELSE)
    CV.CHECK_FIELDS(s)
    s.op(OP_2OVER).op(OP_2OVER)
    CV.ENC4(s)
    s.op(OP_TOALTSTACK)
    for _ in range(k):
        CV.STEP(s, tm)
    CV.ENC4(s)
    s.op(OP_OVER).op(OP_CAT)
    s.op(OP_FROMALTSTACK).op(OP_ROT).op(OP_CAT)
    CV.CSX(s)
    s.op(OP_TOALTSTACK)
    CV.CSX(s)
    s.op(OP_SWAP).data(struct.pack("<I", SIGHASH_ALL_CHRONICLE_FORKID)).op(OP_CAT).op(OP_CAT)
    s.op(OP_CAT)
    s.data(b"\x01").op(OP_SWAP).op(OP_CAT)
    s.op(OP_CAT)
    s.op(OP_FROMALTSTACK).op(OP_SWAP).op(OP_CAT)
    s.op(OP_CAT)
    s.data(b"\x01").op(OP_SWAP).op(OP_CAT)
    s.op(OP_CAT)
    SIGN_CHRONICLE(s)
    s.op(OP_1)
    s.op(OP_ENDIF)
    return s.bytes()


def locking_script_015(state, code_015):
    return CV.locking_script(state, code_015)


def low_s_sign(d, z, k):
    """ECDSA with s normalised to the lower half (signatures made by the harness)."""
    r = EC.mul(k, EC.G)[0] % EC.N
    s = pow(k, -1, EC.N) * (z + r * d) % EC.N
    if s > EC.N // 2:
        s = EC.N - s
    return EC.der_encode(r, s)
