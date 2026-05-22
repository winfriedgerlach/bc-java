# Java Vector API speedup opportunities in bc-java

Survey of hot spots in the Bouncy Castle codebase where the JDK incubator
Vector API (`jdk.incubator.vector`) could deliver meaningful SIMD speedups on
x86-64 (AVX2 / AVX-512) and ARM (NEON / SVE).

All implementations would live in a JDK 17+ MR-jar overlay
(`<module>/src/main/jdk17/`) since `jdk.incubator.vector` requires JDK 16+ and
the base sources target JDK 8. Loading must tolerate the absence of the
`jdk.incubator.vector` module at runtime (the JVM doesn't auto-add incubator
modules) — gate every overlay class on a lazy detection probe and fall back to
the existing scalar implementation when the module isn't on the module path.

## Tier 1 — strongest wins (4–8x plausible, hot real-world paths)

### 1. ChaCha20 / Salsa20 quarter-round
- `core/src/main/java/org/bouncycastle/crypto/engines/ChaChaEngine.java:150` (`chachaCore`)
- `core/src/main/java/org/bouncycastle/crypto/engines/Salsa20Engine.java:413` (`salsaCore`)
- Also `ChaCha7539Engine.java`, `XSalsa20Engine.java`

16xu32 state, 20 rounds of column/diagonal `add+xor+rotl` with no cross-lane
dependencies. The biggest win is **across-block** parallelism: process 4 / 8 /
16 independent counter blocks at once with a `LANES`-wide IntVector per state
slot (libsodium playbook). Within a single block, vectorizing the 4-lane QR is
also possible but yields less.

Hot in TLS 1.3, WireGuard, anything with ChaCha20-Poly1305. Likely the
single highest-ROI item in the tree.

### 2. ML-KEM and ML-DSA NTT butterflies
- `core/src/main/java/org/bouncycastle/pqc/crypto/mlkem/Ntt.java`
- `core/src/main/java/org/bouncycastle/pqc/crypto/mldsa/Ntt.java`
- Sibling `Poly.java` (pointwise multiply) and `Reduce.java` (Montgomery / Barrett)

7-stage butterfly over `short[256]` (q=3329) and `int[256]` (q=8380417). Inner
loop is one mul + add/sub on independent pairs — textbook SIMD. Reference C
impls all use AVX2; the BC port is plain scalar.

On the critical path of every keygen / encap / decap / sign / verify. PQC is
increasingly the dominant cost in handshakes, and NTT is the #1 PQC
bottleneck.

### 3. BLAKE2b / BLAKE3 G function
- `core/src/main/java/org/bouncycastle/crypto/digests/Blake2bDigest.java:516` (`G`)
- `core/src/main/java/org/bouncycastle/crypto/digests/Blake3Digest.java:760` (`mixG`)
- Also `Blake2sDigest.java`

4-lane `add+xor+rotr` with constant rotate amounts (32 / 24 / 16 / 63 for 2b).
Clean function boundary, easy retrofit. BLAKE3 also has natural chunk-level
parallelism (hash 8 independent 1KiB chunks at once) that's a bigger win than
per-G vectorization.

Used by Argon2, increasingly by new protocols.

## Tier 2 — solid wins (2–3x)

### 4. Keccak θ and χ steps
- `core/src/main/java/org/bouncycastle/crypto/digests/KeccakDigest.java:379` (`KeccakPermutation`)

5x5 `long[25]` state. θ does 5 column-XOR reductions + 5 broadcasts; χ does
row-wise `a ^ (~b & c)`. Both lane-parallel. ρ/π is a fixed permutation — try
`VectorShuffle` but it likely won't beat scalar.

Touches every SHA-3 / SHAKE call, including the SHAKE inside ML-KEM / ML-DSA,
so wins compound with #2.

### 5. GHASH / GCM Karatsuba multiply
- `core/src/main/java/org/bouncycastle/crypto/modes/gcm/GCMUtil.java:153` (`multiply`, byte form)
- Same file `:191` (long form), plus `GCMBlockCipher.java`

Already hand-tuned with bit-reversal Karatsuba. Caveat: on x86 with PCLMUL the
JVM intrinsic / hardware path dominates anyway. Vectorize only if the
deployment target lacks PCLMUL or you batch many independent tags. Benchmark
before investing.

### 6. SHA-256 / SHA-512 message schedule
- `core/src/main/java/org/bouncycastle/crypto/digests/SHA256Digest.java:218`
- `core/src/main/java/org/bouncycastle/crypto/digests/SHA512Digest.java`

The schedule (`W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]`) has no
loop-carried dependency in groups of 4 and is a known SIMD target. Main
compression loop is serial — you can't touch that. Net per-hash gain
~1.3–1.5x. Multi-message batching (LMS/HSS, SPHINCS+) is the bigger door.

### 7. SPHINCS+/SLH-DSA and LMS/HSS batched hashes
- `core/src/main/java/org/bouncycastle/pqc/crypto/slhdsa/HT.java:149` (`treehash`)
- WOTS chain loops in `slhdsa/Wots.java`, `sphincsplus/`, `lms/`

Independent hash chains across an authentication tree -> batch 4–8
SHA-256 / SHAKE instances with vector message schedules. Bigger lift
(algorithmic restructuring, not just loop swap) but a real 3–4x on signing
throughput is plausible. Most impactful for SLH-DSA, which is otherwise
painfully slow.

## Tier 3 — opportunistic / niche

### 8. X25519 / Ed25519 field arithmetic
- `core/src/main/java/org/bouncycastle/math/ec/rfc7748/X25519Field.java`
- `core/src/main/java/org/bouncycastle/math/ec/rfc8032/Ed25519.java`

10-limb radix-2^25.5 `int[]` adds and conditional swaps in the Montgomery
ladder. Cswap is a clean Vector mask+select. Carry propagation stays serial.
~1.5–2x, every TLS 1.3 handshake hits it.

### 9. ML-KEM PolyVec pointwise multiply / matrix-vector product
- `core/src/main/java/org/bouncycastle/pqc/crypto/mlkem/PolyVec.java`
- `core/src/main/java/org/bouncycastle/pqc/crypto/mlkem/Poly.java:43` (`baseMultMontgomery`)

Secondary to the NTT itself but on the same critical path. Worth doing as part
of the NTT effort.

### 10. HQC / BIKE / Classic McEliece GF(2) polynomial XOR/multiply
- `core/src/main/java/org/bouncycastle/pqc/crypto/hqc/GF2x.java`
- `core/src/main/java/org/bouncycastle/pqc/crypto/bike/`
- `core/src/main/java/org/bouncycastle/pqc/crypto/cmce/`

Carry-less XOR on `long[]` — pure lane-parallel. Lower priority because none
of these are NIST-standardized; relevant if the deployment cares about HQC
interop.

### 11. `Nat.xorTo64` / `Nat.addTo` and friends
- `core/src/main/java/org/bouncycastle/math/raw/Nat.java:140` (`addTo`)
- `core/src/main/java/org/bouncycastle/math/raw/Nat.java:1606` (`xorTo64`)
- Sibling helpers throughout `Nat.java`

Trivial to vectorize but arrays are typically tiny (4–8 longs) and the JIT
already does well. Profile-driven; don't speculate.

## Skip list (don't waste cycles here)

- **AES** (`AESEngine`, `AESFastEngine`, `AESLightEngine`) — needs AES-NI;
  Vector API doesn't expose AES round instructions. The HotSpot intrinsic
  already hits hardware on JDK 17+.
- **`BigInteger` / Karatsuba in arbitrary-precision math** — bottleneck is
  64x64->128 multiply; needs `Math.unsignedMultiplyHigh` or CPU multiplier
  intrinsics, not Vector API.
- **SHA-1 / SHA-256 main compression body, AES MixColumns, NFSR feedback in
  Grain** — hard loop-carried dependencies.
- **ASN.1 / PEM / parsing code** — branchy, not throughput-bound.

## Practical notes for the BC layout

- `jdk.incubator.vector` is only available on JDK 16+ (incubating); base
  sources target JDK 8. Implementations need to live in an MR-jar overlay —
  the existing slot is `<module>/src/main/jdk17/` (see CLAUDE.md "Multi-Release
  JAR overlays"). The `BC_JDK17` / `BC_JDK21` / `BC_JDK25` env-var-gated test
  tasks already exercise this overlay path.
- The `core` module has no Gradle MR-jar setup of its own. `prov` is the build
  unit that produces `bcprov-<vmrange>.jar` from both `core/src/main/java` and
  `prov/src/main/java` (the core-into-prov srcDirs trick). Vector overlays for
  primitives that live under `core` should land at
  `prov/src/main/jdk17/org/bouncycastle/...` (matching the package path of the
  base class) so they get packaged into `META-INF/versions/17/` of the
  published `bcprov` jar.
- Pattern: keep the scalar engine as the JDK 8 base, ship a `*VectorImpl` (or
  override the engine class) in `jdk17/`. Runtime fallback when
  `IntVector.SPECIES_PREFERRED.length() == 1` or the module isn't loaded.
  Concretely: in the overlay class, have a `static final boolean
  VECTOR_ENABLED = detectVector()` that wraps the probe in `try/catch
  (Throwable)` so a missing module degrades to the scalar path instead of
  failing class load.
- Anything that touches `core/` recompiles into `prov/` too — the overlay only
  needs to be set up under `prov/src/main/jdk17/` even when the primitive
  itself lives in `core/`.
- **Constant-time concern**: stream cipher / NTT / Keccak inner loops are
  already branch-free on the data path; Vector API ops are constant-time-by-
  construction on lane data, so the property is preserved as long as you don't
  introduce mask-dependent control flow.
- BC enforces the "exception messages are part of the test contract" rule —
  vectorized variants must throw the same messages as the scalar code at the
  same call sites.
- Add a regression test that runs the same input through scalar and vector
  paths and asserts byte-equal output, across input sizes that exercise
  partial-block / aligned / odd-tail cases. `prov/src/test/jdk17/` is the
  right place.

## Implementation priority

1. **ChaCha / Salsa20** — simplest, highest impact for stream encryption,
   clean replacement target.
2. **BLAKE2b / BLAKE3 G** — clean function boundary, widely adopted.
3. **ML-KEM / ML-DSA NTT** — critical PQC bottleneck, well-defined loop, no
   other JVM optimization path available today.

These three deliver roughly 60% of the potential gain at ~30% of the total
effort and would materially improve BC's position in high-throughput
cryptographic workloads (TLS acceleration, batch PQC keygen, on-device
hashing).