# Turing machines on a BSV node

**The constructions of [original-bitcoin-script](https://github.com/prof-faustus/original-bitcoin-script),
built in the 0.1.5 Script language, run on a real BSV node: submitted, validated and mined.**

Craig Steven Wright · ORCID [0000-0001-9374-0507](https://orcid.org/0000-0001-9374-0507) ·
University of Exeter Business School

---

## What was run, and on what

The node is the official image `bitcoinsv/bitcoin-sv:1.2.3`, pinned by digest
`sha256:d96fe4786a00e5fc10bc9e0e76a6006376f9472d4eb74d07e4c1e0d019493d33`, on regtest. Genesis
and Chronicle are active from block 1. The experiments ran on a single BSV 1.2.3 regtest node
with `acceptnonstdtxn=0`. The node accepted or refused transactions under the settings recorded
in `bitcoin.conf`. Every construction is placed in a funded output and spent by a transaction
submitted with `sendrawtransaction`. Every accepted spend is then mined in a block, and each
construction is also given spends that the node must refuse. Each spend pays a fee of 2,000
satoshis.

**43 checks, 0 failures** (`regtest_results_v02.txt`, `regtest_results_v02.json`).

### Two-stack Turing machines — unchanged 0.1.5 scripts

| Machine | *n* | steps | script bytes | member | non-member |
|---|---|---|---|---|---|
| decider for {aᵏbᵏcᵏ} | 6 | 23 | 8,594 | accepted, mined | refused |
| decider for {aᵏbᵏcᵏ} | 9 | 46 | 17,179 | accepted, mined | refused |
| decider for {0^(2^k)} | 64 | 833 | 159,234 | accepted, mined | — |
| decider for {0^(2^k)} | 48 | — | — | — | refused |

Refusals read: `mandatory-script-verify-flag-failed (Script evaluated without error but finished
with a false/empty top stack element)`.

### Ackermann's function on the alternate stack — unchanged 0.1.5 scripts

| (*m*, *n*) | *A* | iterations | script bytes | correct value | value + 1 |
|---|---|---|---|---|---|
| (2, 3) | 9 | 44 | 1,284 | accepted, mined | refused |
| (3, 3) | 61 | 2,432 | 70,536 | accepted, mined | refused |
| (3, 4) | 125 | 10,307 | 298,911 | accepted, mined | refused |

### The covenant chain — the 0.1.5 design in the Chronicle encoding

One fixed locking script carries a Turing machine forward, transaction by transaction. Each
spending transaction must carry the correct successor state: the script requires the transaction
fields it is given to have their serialised widths, reconstructs the spending transaction's
signature preimage, and verifies a signature over it that the script computes itself (see the
companion repository for the construction).

| Machine | input | steps per tx | code bytes | transactions accepted and mined | outcome |
|---|---|---|---|---|---|
| aᵏbᵏcᵏ decider | `aabbcc` | 2 | 2,977 | 12 | accepts; beneficiary paid and mined |
| aᵏbᵏcᵏ decider | `aabbc` | 2 | 2,977 | 7 | rejects; payout refused |
| binary counter (never halts) | — | 4 | 2,309 | 60 (240 machine steps) | state equals the reference machine's |

Refused by the node, each with `Script failed an OP_CHECKSIGVERIFY operation`: a successor with the
wrong machine state; a successor with one tape cell altered; a second output; substituted code;
a misstated transaction field. Refused with `Script failed an OP_EQUALVERIFY operation`, at the
width test: two spends forged by cutting the real preimage of a different transaction into fields
of other widths (a second output; a successor carrying the code `OP_1`). Also refused: payout
before acceptance; payout after rejection; payout signed by any key other than the
beneficiary's.

The same two forged spends were submitted against a covenant built with `chronicle_v01.py` and
`covenant_v01.py`, the code of version 1.0.x, which has no width test: the node accepted and mined
both, and the hijacked successor was then spent with an empty unlocking script. Those three
checks show that the controls can fail; the covenant of version 1.1.0 refuses the same spends.

---

## The Chronicle encoding of the 0.1.5 covenant

Read from the bitcoin-sv v1.2.3 source (`src/script/opcodes.h`, `interpreter.cpp`):

- `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT` are `0xb3`, `0xb4`, `0xb5` (in 0.1.5: `0x7f`, `0x80`, `0x81`,
  which now carry `OP_SPLIT`, `OP_NUM2BIN`, `OP_BIN2NUM`). Every other operation keeps its 0.1.5
  value. `chronicle_v02.translate` maps a script operation by operation and copies every push
  byte for byte; on the covenant it changes 139 of 2,346 operations and nothing else.
- `OP_SUBSTR` fails when the range passes the end of the string, where 0.1.5 truncated; the
  byte-reversal loop therefore tests the length before each read.
- FORKID (`0x40`) is mandatory, and the original signature-hash algorithm is selected whenever
  the CHRONICLE bit (`0x20`) is set: the covenant signs with hash type `0x61`.
- Transactions of version 2 or above are exempt from the minimal-push, minimal-number, low-S,
  MINIMALIF, clean-stack and push-only rules; every spend here is version 2.

Before the node is used, the runner checks the design with these changes in the 0.1.5 model, in
the original numbering; the translated bytes themselves run on the node only.

---

## Reproduce

Requires Docker and Python 3.8+.

```
sh start_node.sh                 # pinned bitcoin-sv 1.2.3, regtest, RPC 127.0.0.1:18432
python regtest_runs_v02.py       # 43 checks; writes regtest_results_v02.*
```

The model and constructions (`script015_*`, `tx015_v01.py`, `secp256k1_v01.py`,
`constructions_v01.py`, `covenant_v01.py`, `covenant_v02.py`) are byte-identical copies from
original-bitcoin-script v1.1.0. `chronicle_v01.py`, `regtest_runs_v01.py` and
`regtest_results_v01.*` are kept as released in version 1.0.1.

## Scope

Regtest, a single node, policy as configured in `bitcoin.conf`. On main net the BSV node 1.2.0
release notes schedule Chronicle at block 943,816 (target 7 April 2026). Transaction identifiers
in the results are those of the regtest run and identify transactions on that local chain only.

## Licence

MIT. See `LICENSE`.
