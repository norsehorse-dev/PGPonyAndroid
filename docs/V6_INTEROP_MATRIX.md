# PGPony v6 Interop Matrix (V6-7)

Cross-implementation hardening for OpenPGP v6 (RFC 9580). PGPony's v6 paths are
already verified against Sequoia (`sq`) end to end; this runbook widens that to
the other major v6 implementations using the **Stateless OpenPGP (SOP)** command
line, the standard interop surface for OpenPGP.

PGPony is an Android app, not a SOP binary, so it is the **manual node** in every
row: you produce artifacts with a SOP tool on the desktop and consume them in
PGPony (import cert, paste/share-in a message, read the result), and vice versa.
Each cell is one round-trip you run once and tick off.

---

## 1. SOP tools (the other implementations)

| Implementation        | SOP binary        | Install (macOS)                                  |
|-----------------------|-------------------|--------------------------------------------------|
| Sequoia PGP           | `sqop` (or `sq`)  | `brew install sequoia-sq` / `cargo install sqop` |
| rPGP                  | `rsop`            | `cargo install rsop`                             |
| PGPainless (BC-based) | `pgpainless-cli`  | see PGPainless docs (Gradle fat-jar) / `apt` on Linux |
| GopenPGP (Proton)     | `gosop`           | `go install github.com/ProtonMail/gosop@latest`  |

PGPainless is worth special attention: it is **also BouncyCastle-based**, so
agreement with `pgpainless-cli` is a strong same-engine cross-check, while `rsop`
(Rust), `gosop` (Go/Proton), and `sqop` (Rust/Sequoia) are independent engines.

All four implement the same verbs: `generate-key`, `extract-cert`, `sign`,
`verify`, `encrypt`, `decrypt`, `inline-sign`, `inline-verify`.

### v6 is profile-selected — do not assume the default

SOP defaults differ and several still default to a **v4** layout:

- `pgpainless-cli` defaults to `draft-koch-eddsa-for-openpgp-00` (a v4 Ed25519
  key), **not** v6.
- `sqop` / `sq` default to RFC 4880 (v4) and need `--profile rfc9580`.

So always pick the v6 profile explicitly. Discover the name per tool:

```
$SOP list-profiles generate-key
```

Then generate with whichever profile maps to RFC 9580 (commonly `rfc9580`):

```
$SOP generate-key --profile rfc9580 "Tester <tester@example.org>" > t.tsk
```

Confirm you actually got a v6 key before testing against PGPony:

```
sq inspect <(cat t.tsk)        # primary key version should read 6
```

---

## 2. Per-tool setup

Run this block once per implementation, setting `$SOP` to that tool's binary:

```
export SOP=sqop
PROFILE=rfc9580
$SOP generate-key --profile "$PROFILE" "SOP Tester <sop@example.org>" > sop.tsk
$SOP extract-cert < sop.tsk > sop.cert
printf 'pgpony v6 interop probe' > msg.txt
sq inspect sop.cert
```

(`sq inspect` is just the readout; any tool's cert works in PGPony.)

---

## 3. The matrix

For each tool, four round-trips. PGPony steps are in *italics*.

### A. Tool encrypts -> PGPony decrypts

```
$SOP encrypt sop.cert < msg.txt > to-pgpony.asc      # wrong key on purpose? no — see note
```

Note: encrypt to **PGPony's** v6 cert, not the tool's. So first export PGPony's
v6 public key (Key detail -> share/export) to `pgpony.cert`, then:

```
$SOP encrypt pgpony.cert < msg.txt > to-pgpony.asc
```

*In PGPony: decrypt `to-pgpony.asc` with the matching v6 key. Expect the probe text.*

### B. PGPony encrypts -> Tool decrypts

*In PGPony: import `sop.cert`, encrypt the probe text to it, save armored output as `from-pgpony.asc`.*

```
$SOP decrypt sop.tsk < from-pgpony.asc        # expect: pgpony v6 interop probe
```

### C. Tool signs -> PGPony verifies

```
$SOP inline-sign sop.tsk < msg.txt > signed-by-sop.asc
```

*In PGPony: verify `signed-by-sop.asc` against the imported `sop.cert`. Expect a valid signature naming the tool's key.*

(Detached variant: `$SOP sign sop.tsk < msg.txt > msg.sig`, then verify the
detached sig + `msg.txt` in PGPony.)

### D. PGPony signs -> Tool verifies

*In PGPony: produce a detached signature of `msg.txt`'s exact bytes with the v6 key, save as `pgpony.sig`.*

```
$SOP verify pgpony.sig pgpony.cert < msg.txt   # expect: a VERIFICATION line with PGPony's signing subkey
```

Byte-exactness matters for D: type the same content into `msg.txt` with `printf`
(no trailing newline) that PGPony signed, or sign `msg.txt` directly if PGPony
lets you pick a file.

---

## 4. Record the results

| Implementation | A decrypt | B decrypt | C verify | D verify |
|----------------|-----------|-----------|----------|----------|
| Sequoia (sqop) |           |           |          |          |
| rPGP (rsop)    |           |           |          |          |
| PGPainless     |           |           |          |          |
| GopenPGP/Proton (gosop) |  |           |          |          |

What each column actually exercises in PGPony:
- **A** — inbound v6 PKESK + SEIPDv2 decryption (and v4 SEIPDv1 if the tool
  downgrades). Run `sq packet dump to-pgpony.asc` to confirm PKESK v6 / SEIPD v2.
- **B** — PGPony's outbound capability gate: encrypting to the tool's v6 cert
  should emit SEIPDv2; to a v4 cert it should fall back to SEIPDv1.
- **C** — verifying a foreign v6 signature, including resolving a signer that
  signed with a subkey (most v6 layouts) to a name.
- **D** — PGPony's v6 signatures (salt + version-6 packet, signed by a
  Sign-capable subkey) accepted by an independent engine.

A green row for every tool, especially the non-BouncyCastle ones (`rsop`,
`gosop`, `sqop`), is the cross-engine evidence that PGPony's v6 is on-spec and
not just self-consistent with its own BouncyCastle backend.

---

## 5. CI companion

The static half of interop hardening lives in `RFC9580VectorTest` — it runs the
RFC 9580 Appendix A canonical vectors through PGPony's parse/verify/decrypt in
`testDebugUnitTest`. Populate the vectors once with `tools/fetch_rfc9580_vectors.sh`
and they regression-lock the v6 read paths on every build. This matrix is the
live counterpart that CI cannot run (external binaries) — worth re-running after
any change to the v6 crypto layer or a BouncyCastle bump.
