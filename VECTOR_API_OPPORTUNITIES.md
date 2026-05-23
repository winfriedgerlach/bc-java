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

Result:
```
The kernel correctness is solid but the AVX2 path runs ~0.6× scalar throughput here. The QR rounds appear to be
JIT-compiled at C2 level 4, but the dominant costs look register-pressure-related (16 active state vectors + 16 saved
initial copies on a 16-YMM register file). Future work: try a 4-block kernel that recomputes initial-state broadcasts
on the add-back instead of holding them, or move the I/O XOR into a ByteVector form.
AVX-512 should win out of the box because of native vprolld.
```

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

Result:
```
=== ML-KEM bench ===
WARNING: Using incubator modules: jdk.incubator.vector
ML-KEM ntt (forward)        vector:    1156 ns/op   scalar:    1383 ns/op   speedup: 1,20x
ML-KEM invNtt (inverse)     vector:    1338 ns/op   scalar:    2213 ns/op   speedup: 1,65x
=== ML-DSA bench ===
WARNING: Using incubator modules: jdk.incubator.vector
ML-DSA ntt (forward)        vector:    2625 ns/op   scalar:    2237 ns/op   speedup: 0,85x
ML-DSA invNttToMont         vector:    2738 ns/op   scalar:    2556 ns/op   speedup: 0,93x
```

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

Result:

In practice the four-wide claim is generous: `W[t+2]` reads `W[t]` (the
value just being computed), so without the standard "split σ1" intrinsic
trick the algorithmic ceiling is two lanes per iteration. The 2-lane
overlay (`SHA256VectorImpl` / `SHA512VectorImpl`) goes through
`IntVector.SPECIES_64` / `LongVector.SPECIES_128`, leaving the unrolled
compression body scalar.

```
=== SHA schedule bench (JDK 25, AVX2 host: IntVector.SPECIES_PREFERRED = 256-bit / 8 lanes) ===
WARNING: Using incubator modules: jdk.incubator.vector
SHA-256 schedule        vector:      80 ns/op   scalar:      90 ns/op   speedup: 1,12x
SHA-512 schedule        vector:     120 ns/op   scalar:     144 ns/op   speedup: 1,19x
```

A small but real win, in line with the doc's "schedule alone is the
cheap part" framing — the schedule runs in roughly 25% of total
processBlock time, so the end-to-end per-hash gain is below 5%. A 4-lane
intrinsic-style implementation with the σ1 split would go further but
hasn't been pursued; the bigger door is still cross-message batching for
LMS/HSS/SLH-DSA (#7).

### 7. SPHINCS+/SLH-DSA and LMS/HSS batched hashes
- `core/src/main/java/org/bouncycastle/pqc/crypto/slhdsa/HT.java:149` (`treehash`)
- WOTS chain loops in `slhdsa/Wots.java`, `sphincsplus/`, `lms/`

Independent hash chains across an authentication tree -> batch 4–8
SHA-256 / SHAKE instances with vector message schedules. Bigger lift
(algorithmic restructuring, not just loop swap) but a real 3–4x on signing
throughput is plausible. Most impactful for SLH-DSA, which is otherwise
painfully slow.

Result:
```
The 8-lane batched SHA-256 compressor (SHA256BatchedVectorImpl) is
correct end-to-end — full SLH-DSA sha2-128s sign+verify roundtrips
through the batched WOTS pkGen, and pkGen output is byte-identical to
the scalar reference across all six SHA-2 parameter sets (N=16/24/32).

Kernel-only bench (compressBatch vs 8 sequential scalar one-block hashes):

WARNING: Using incubator modules: jdk.incubator.vector
compressBatch (LANES=8)   vector:    2665 ns/call   scalar (x8):    2616 ns/call   speedup: 0,98x

End-to-end WOTS+ pkGen (batched chain through SHA256BatchedVectorImpl
vs the original WOTS_LEN-loop, AVX2 host):

sha2-128s WOTS+ pkGen       vector:   261,0 us/op   scalar:   250,9 us/op   speedup: 0,96x
sha2-192s WOTS+ pkGen       vector:   378,7 us/op   scalar:   370,8 us/op   speedup: 0,98x
sha2-256s WOTS+ pkGen       vector:   456,7 us/op   scalar:   453,3 us/op   speedup: 0,99x

(WOTS pkGen numbers vary by ~5% across runs from JIT/scheduling noise;
parking near 1.0x in either direction across the three sizes.)

The predicted 3–4x SLH-DSA speedup does not materialise with the JVM
Vector API: the batched compression body is essentially the same speed
as eight fully-unrolled scalar SHA-256 compressions.  BC's
SHA256Digest.processBlock is heavily unrolled and JIT-optimised
(~290 ns/block), and HotSpot's per-IntVector-op overhead on the
64-round inner loop matches that ~290 ns/block per lane in steady
state — so 8-way lane parallelism collapses back to ~1× rather than
the 3–4× a C SIMD intrinsic kernel would deliver.

Three kernel shapes were tried:
- Loop-based with an IntVector[16] W circular buffer kept inside
  compressBatch (best, current): 2665 ns/call.  HotSpot's escape
  analysis stack-allocates the array, so the (t+14)&15 / (t+9)&15 /
  (t+1)&15 reads land on register-resident slots; per-IntVector-op
  overhead is what's left.
- Single fully-unrolled body with 16 named w0..w15 locals and the
  W rotation expressed via reassignment (the "standard SIMD pattern"):
  ~8 KB of bytecode, above C2's HugeMethodLimit=8000 threshold.
  HotSpot fell back to the interpreter and the kernel ran ~9× slower
  (~25 µs/call).
- Four chunk-of-16 static methods, each well under the size limit, with
  state and W passed as IntVector[] arrays.  Each chunk compiles fine,
  but the arrays escape across the call boundary, EA can't eliminate
  them, and every state[i] / w[i] access becomes a real heap load.
  Net: 4400 ns/call, worse than the loop.

The HotSpot constraints (method size for full unroll, EA on cross-call
arrays for chunked unroll) effectively box the achievable speed at the
loop form's level.  Further wins would need either:
- An -XX:HugeMethodLimit override at the deployment level (raising it
  to ~12000 lets the fully-unrolled variant compile, at the cost of a
  global JVM flag), or
- Native code via JNI / Project Panama for the inner kernel.

Other things even an ideal kernel would still need to deliver the
doc's 3–4x at the WOTS pkGen level:
- Batch the WOTS_LEN scalar PRF calls (35–67 per pkGen).
- Batch T_l (one ~9-block hash per pkGen).
- Batch across pkGens (HT.treehash drives 2^H' independent pkGens
  per layer — natural place to widen the batch).

Filed as "primitive + wiring proven correct; HotSpot Vector API caps
the achievable kernel speedup at ~1× scalar."  The batched
WotsPlus.pkGen is engaged on AVX-512 by default
(minLanes=8) and opt-in on AVX2 via
`-Dorg.bouncycastle.slhdsa.wots.vector.minLanes=2`.
```

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