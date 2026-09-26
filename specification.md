---
title: Bandersnatch VRF-AD Specification
author:
  - Davide Galassi
  - Seyed Hosseini
date: 26 Sep 2026 - Draft 36
---

\newcommand{\G}{\bold{G}}
\newcommand{\F}{\bold{F}}
\newcommand{\S}{\bold{\Sigma}}

---

# *Abstract*

This specification defines three Verifiable Random Function with Additional Data
(VRF-AD) schemes -- Tiny VRF, Thin VRF, and Pedersen VRF -- built on a
transcript-based Fiat-Shamir transform with support for multiple input/output
pairs via delinearization. Tiny VRF and Thin VRF are loosely inspired by IETF
ECVRF [RFC-9381] [@RFC9381], adapted with a transcript-based Fiat-Shamir
transform, support for additional data, and multiple I/O pairs via
delinearization. Pedersen VRF follows the construction introduced by
[BCHSV23] [@BCHSV23] and serves as a building block for anonymized ring
signatures based on the ring proof scheme derived from [CSSV22] [@CSSV22].
All schemes are instantiated over the Bandersnatch elliptic curve, constructed
over the BLS12-381 scalar field as specified in [MSZ21] [@MSZ21].


# 1. Preliminaries

## 1.1. Groups and Fields

- $\G$: Bandersnatch curve cyclic group of prime order $r$, defined over
  the base field of prime order $q$.
- $\F$: Scalar field of prime order $r$ (i.e. $\mathbb{Z}_r$).
- $\S^k$: Octet strings with length $k \in \mathbb{N}$ ($*$ for arbitrary length).
- $\mathcal{O}$: Identity point of $\G$.

The EC group $\G$ is the prime subgroup of the Bandersnatch elliptic curve,
in Twisted Edwards form, with finite field and curve parameters as specified in
[MSZ21] [@MSZ21]. For this group, `fLen` = `qLen` = $32$ and `cofactor` = $4$.

All point arithmetic MUST be performed in $\G$. Points not in $\G$ MUST be
rejected at all entry points; accepting a point on the full curve but outside
the prime-order subgroup enables small-subgroup attacks that break the VRF
relation.

## 1.2. Notation

- $x \in \F$: Secret key scalar.
- $Y \in \G$: Public key point defined as $x \cdot G$.
- $i \in \S^*$: VRF input data.
- $I \in \G$: VRF input point.
- $O \in \G$: VRF output point.
- $o \in \S^k$: VRF output hash.
- $T$: Transcript state.

The *group generator* $G \in \G$ is defined as:
$$\footnotesize\begin{aligned}
x &= 18886178867200960497001835917649091219057080094937609519140440539760939937304 \\
y &= 19188667384257783945677642223292697773471335439753913231509108946878080696678
\end{aligned}$$

## 1.3. VRF-AD

Regardless of the specific scheme, a *Verifiable Random Function with Additional
Data (VRF-AD)* can be concisely represented by three primary functions:

**Abstract interface**:

- $\texttt{prove}(x \in \F, \overline{io} \in (\G \times \G)^n, ad \in \S^*) \to \Pi$
- $\texttt{verify}(Y \in \G, \overline{io} \in (\G \times \G)^n, ad \in \S^*, \Pi) \to (\top \mid \bot)$
- $\texttt{output}(O \in \G) \to o \in \S^N$

For Pedersen VRF (section 4), the public key $Y$ is not an explicit input to
$\texttt{verify}$; the proof $\Pi$ carries a blinded commitment $\bar{Y}$ instead.

The additional data $ad$ is an arbitrary-length octet-string signed together with
the VRF output. It does not influence the produced VRF output.
The length of $ad$ MUST NOT exceed $2^{64} - 1$ bytes, as the length is encoded
via $\texttt{enc\_64}$ in the VRF transcript (section 1.6.5).

## 1.4. Constants

- `suite_id` = `"Bandersnatch-SHA512-ELL2-v1"` — the 27-byte ASCII string identifying
  the cipher suite. It bundles several tightly-coupled choices: curve (Bandersnatch
  in Twisted Edwards form), transcript construction (HashTranscript over SHA-512),
  nonce algorithm (RFC-8032 inspired), challenge derivation (transcript squeeze),
  point encoding (compressed little-endian), hash-to-curve (Elligator 2 random
  oracle), and security level (128-bit). Bump the trailing version suffix when
  any of these changes.

- `challenge_len` = 16 bytes (128-bit security).
- `expanded_scalar_len` = $\lceil(\lceil\log_2(r)\rceil + 128) / 8\rceil$ = 48 bytes.

Domain separation tags used throughout the protocol:

| Tag | Value | Usage |
|-----|-------|-------|
| TinyVrf | 0x00 | Tiny VRF scheme identifier |
| ThinVrf | 0x01 | Thin VRF scheme identifier |
| PedersenVrf | 0x02 | Pedersen VRF scheme identifier |
| NonceExpand | 0x10 | Nonce secret expansion |
| Nonce | 0x11 | Nonce derivation |
| PedersenBlinding | 0x12 | Pedersen blinding factor |
| PointToHash | 0x20 | VRF output hashing |
| Delinearize | 0x30 | Delinearization scalars |
| Challenge | 0x40 | Challenge derivation |
| BatchVerify | 0x50 | Batch verification randomization |
| HashToCurve | 0x60 | Hash-to-curve domain separation |

## 1.5. Codec

- $\texttt{enc\_scalar}(s \in \F)$: Encodes a scalar into 32 octets in little-endian
  representation.
- $\texttt{dec\_scalar}(buf \in \S^{32})$: Interpret octet string $buf$ as a little-endian
  integer. MUST output "INVALID" if the resulting value is $\geq r$.
- $\texttt{enc\_point}(P \in \G)$: Encodes a point in compressed form. The $y$
  coordinate is serialized in little-endian and the most significant bit of
  the last octet encodes the sign of the $x$-coordinate. This gives `ptLen` = `fLen` = $32$.
- $\texttt{dec\_point}(buf \in \S^{32})$: Interpret octet string $buf$ as a compressed point.
  Mask the sign bit from the last octet and interpret the result as a little-endian
  integer. MUST output "INVALID" if the resulting value is $\geq q$. Otherwise,
  decompress the point and MUST output "INVALID" if it does not decode to a point
  on the prime subgroup $\G$.
- $\texttt{dec\_scalar\_mod}(buf \in \S^*)$: Interpret octet string $buf$ as a little-endian
  integer and reduce modulo the prime field order $r$.
- $\texttt{enc\_64}(n \in \mathbb{N}_{2^{64}})$: Encode integer $n$ as an 8-byte little-endian octet string.

Aggregate types (e.g. proofs) MUST be encoded as the concatenation of their
individual fields in the order given by the structure definition, without any
separator.

## 1.6. Procedures

### 1.6.1. Transcript

The transcript provides a Fiat-Shamir transform with an absorb/squeeze
interface. Data is absorbed into an internal hash state; output bytes are
squeezed from it. After the first squeeze, $\texttt{absorb}$ MUST NOT be called.

**Abstract interface**:

- $\texttt{new\_transcript}() \to T$: Create a fresh transcript instance and absorb $\texttt{suite\_id}$.
- $\texttt{absorb}(data \in \S^*)$: Feed bytes into the hash state. MUST NOT be called after squeeze.
- $\texttt{squeeze}(n \in \mathbb{N}) \to \S^n$: Produce $n$ output bytes.
- $\texttt{fork}() \to T$: Clone the transcript state.

A concrete instantiation using SHA-512 is given in Appendix A.1.

### 1.6.2. VRF Input

The VRF input point $I \in \G$ is derived from the input octet-string using
a $\texttt{hash\_to\_curve}$ function that maps arbitrary-length octet-strings
to points in $\G$.

$$I \gets \texttt{hash\_to\_curve}(i)$$

The function MUST behave as a random oracle: its output must be
indistinguishable from a uniformly random point in $\G$, and the discrete
logarithm of the output with respect to any known base must be unknown.

Verifiers MUST independently compute each $I_i$ from the corresponding input
octet-string using the procedure above. Accepting prover-supplied input points
without recomputation breaks the VRF security guarantees, and in the case of
Thin VRF (section 3), enables trivial forgery.

A concrete instantiation using Elligator 2 is given in Appendix A.2.

### 1.6.3. VRF Output

The VRF output point is generated from the VRF input point and secret key scalar:

$$O \gets x \cdot I$$

The VRF output hash is a fixed-length octet string derived from the output point
using a transcript-based point-to-hash procedure. The procedure is deliberately
independent of the proof scheme: for a given key and input, the output point
$O = x \cdot I$ is unique regardless of whether Tiny VRF, Thin VRF, or Pedersen
VRF is used to prove correctness. The scheme determines how the proof is
constructed, not the VRF output itself. This separation allows applications to
obtain consistent output hashes across schemes for the same underlying evaluation.

**Input**:

- $O \in \G$: VRF output point.
- $N \in \mathbb{N}$: Desired output length in bytes. MUST be fixed per
  application context; $N$ is not absorbed into the transcript, so
  $\texttt{squeeze}(N_1)$ is a prefix of $\texttt{squeeze}(N_2)$ for $N_1 < N_2$.

**Output**:

- $o \in \S^N$: VRF output hash.

**Steps**:

1. $T \gets \texttt{new\_transcript}()$
2. $T.\texttt{absorb}(\texttt{PointToHash} \;\Vert\; \texttt{enc\_point}(O))$
3. $o \gets T.\texttt{squeeze}(N)$

**Transcript**:

- $T = \texttt{suite\_id} \;\Vert\; \texttt{PointToHash} \;\Vert\; \texttt{enc\_point}(O)$

### 1.6.4. Delinearization

Merges input/output pairs into a single pair using delinearization scalars
derived from the transcript. For $n = 0$, returns the identity pair.
For $n = 1$, the pair is returned unchanged ($z_0 = 1$). For $n \geq 2$,
random scalars prevent an attacker from mixing components across pairs.

**Input**:

- $\overline{io} \in (\G \times \G)^n$: Sequence of input/output pairs.
- $T$: Transcript state.

**Output**:

- $(I_m, O_m) \in \G \times \G$: Merged input/output pair.

**Steps**:

1. If $n = 0$: return $(\mathcal{O}, \mathcal{O})$
2. $T.\texttt{absorb}(\texttt{Delinearize})$
3. $z_0 \gets 1$
4. For $i = 1, \ldots, n-1$: $z_i \gets \texttt{dec\_scalar\_mod}(T.\texttt{squeeze}(\texttt{challenge\_len}))$
5. $I_m \gets \sum_{i=0}^{n-1} z_i \cdot I_i,\ O_m \gets \sum_{i=0}^{n-1} z_i \cdot O_i$
6. Return $(I_m, O_m)$

**Transcript** (where $T_{in}$ is the caller-supplied state):

- $T = T_{in} \;\Vert\; \texttt{Delinearize}$

### 1.6.5. VRF Transcript

Shared transcript construction used by all VRF-AD schemes. Absorbs
input/output pairs, merges them via delinearization (section 1.6.4),
and absorbs additional data.

**Input**:

- $scheme$: Scheme identifier tag.
- $\overline{io} \in (\G \times \G)^n$: Sequence of input/output pairs.
- $ad \in \S^*$: Additional data octet-string.

**Output**:

- $T$: Transcript state.
- $(I_m, O_m) \in \G \times \G$: Merged input/output pair.

**Steps**:

1. $T \gets \texttt{new\_transcript}()$
2. $T.\texttt{absorb}(scheme)$
3. $T.\texttt{absorb}(\texttt{enc\_64}(n))$
4. For each $(I_i, O_i)$ in $\overline{io}$:
   $T.\texttt{absorb}(\texttt{enc\_point}(I_i) \;\Vert\; \texttt{enc\_point}(O_i))$
5. $T.\texttt{absorb}(\texttt{enc\_64}(\texttt{len}(ad)) \;\Vert\; ad)$
6. $(I_m, O_m) \gets \texttt{delinearize}(\overline{io}, T.\texttt{fork}())$
7. Return $(T, (I_m, O_m))$

**Transcript**:

$\begin{aligned}
T = &\; \texttt{suite\_id} \;\Vert\; scheme \\
  &\; \Vert\; \texttt{enc\_64}(n) \;\Vert\; \texttt{enc\_point}(I_0) \;\Vert\; \texttt{enc\_point}(O_0) \;\Vert\; \cdots \;\Vert\; \texttt{enc\_point}(I_{n-1}) \;\Vert\; \texttt{enc\_point}(O_{n-1}) \\
  &\; \Vert\; \texttt{enc\_64}(\texttt{len}(ad)) \;\Vert\; ad
\end{aligned}$

### 1.6.6. Nonce

Deterministic nonce generation inspired by [RFC-8032] section 5.1.6. The
transcript carries shared state from $\texttt{vrf\_transcript}$, binding the
nonce to the I/O pairs and additional data.

**Input**:

- $d \in \F$: Secret scalar.
- $T$: Transcript state.

**Output**:

- $k \in \F$: Nonce scalar.

**Steps**:

1. $T' \gets T.\texttt{fork}()$
2. $T'.\texttt{absorb}(\texttt{NonceExpand} \;\Vert\; \texttt{enc\_scalar}(d))$
3. $h \gets T'.\texttt{squeeze}(64)$
4. $T.\texttt{absorb}(\texttt{Nonce} \;\Vert\; h)$
5. $k \gets \texttt{dec\_scalar\_mod}(T.\texttt{squeeze}(\text{expanded\_scalar\_len}))$
6. If $k = 0$: abort (implementation error; probability $\approx 2^{-253}$).

**Transcript** (where $T_{in}$ is the caller-supplied state):

- $T' = T_{in} \;\Vert\; \texttt{NonceExpand} \;\Vert\; \texttt{enc\_scalar}(d)$
- $T = T_{in} \;\Vert\; \texttt{Nonce} \;\Vert\; h$

### 1.6.7. Challenge

Derives a challenge scalar by absorbing curve points into the transcript and
squeezing.

**Input**:

- $\bar{P} \in \G^m$: Sequence of $m$ points.
- $T$: Transcript state.

**Output**:

- $c \in \F$: Challenge scalar.

**Steps**:

1. $T.\texttt{absorb}(\texttt{Challenge})$
2. For each $P_i$ in $\bar{P}$:
   $T.\texttt{absorb}(\texttt{enc\_point}(P_i))$
3. $c \gets \texttt{dec\_scalar\_mod}(T.\texttt{squeeze}(\texttt{challenge\_len}))$

**Transcript** (where $T_{in}$ is the caller-supplied state):

- $T = T_{in} \;\Vert\; \texttt{Challenge} \;\Vert\; \texttt{enc\_point}(P_0) \;\Vert\; \cdots \;\Vert\; \texttt{enc\_point}(P_{m-1})$

# 2. Tiny VRF

Compact VRF-AD scheme producing a short $(c, s)$ proof. Like Thin VRF, it
prepends the Schnorr pair $(G, Y)$ to the I/O list and proves a single DLEQ
on the delinearized merged pair. The challenge scalar $c$ is stored instead
of the nonce commitment, yielding a smaller proof at the cost of not
supporting batch verification.

**Security**: VRF input points MUST be constructed via hash-to-curve. If a
prover knows $d$ such that $I = d \cdot G$, they can forge arbitrary outputs
for that input, because the delinearization merges the Schnorr and VRF pairs
into a single check that collapses when all points are multiples of $G$.

**Proof encoding**: The challenge $c$ is produced by squeezing
$\texttt{challenge\_len}$ bytes from the transcript. Since $2^{8 \cdot \texttt{challenge\_len}} < r$,
no modular reduction occurs and $c$ is encoded as its raw $\texttt{challenge\_len}$-byte
little-endian representation. The scalar $s$ is encoded via $\texttt{enc\_scalar}$ (32 bytes).
The total proof size is $\texttt{challenge\_len} + 32$ bytes. Verifiers MUST reject
proofs where $c \geq 2^{8 \cdot \texttt{challenge\_len}}$.

## 2.1. Prove

**Input**:

- $x \in \F$: Secret key.
- $\overline{io} \in (\G \times \G)^n$: VRF input/output pairs.
- $ad \in \S^*$: Additional data octet-string.

**Output**:

- $\pi = (c, s) \in (\F, \F)$: Schnorr-like proof.

**Steps**:

1. $Y \gets x \cdot G$
2. $(T, (I_m, O_m)) \gets \texttt{vrf\_transcript}(\texttt{TinyVrf}, [(G, Y)] \;\Vert\; \overline{io}, ad)$
3. $k \gets \texttt{nonce}(x, T.\texttt{fork}())$
4. $R \gets k \cdot I_m$
5. $c \gets \texttt{challenge}([R], T)$
6. $s \gets k + c \cdot x$
7. $\pi \gets (c, s)$

## 2.2. Verify

**Input**:

- $Y \in \G$: Public key.
- $\overline{io} \in (\G \times \G)^n$: VRF input/output pairs.
- $ad \in \S^*$: Additional data octet-string.
- $\pi = (c, s) \in (\F, \F)$: Schnorr-like proof.

**Output**:

- $\theta \in \{ \top, \bot \}$: $\top$ if proof is valid, $\bot$ otherwise.

**Steps**:

1. Validate $Y$ and all $I_i, O_i$ $\in \G \setminus \{\mathcal{O}\}$, output $\bot$ if any is invalid or the identity.
2. $(T, (I_m, O_m)) \gets \texttt{vrf\_transcript}(\texttt{TinyVrf}, [(G, Y)] \;\Vert\; \overline{io}, ad)$
3. $R \gets s \cdot I_m - c \cdot O_m$
4. $c' \gets \texttt{challenge}([R], T)$
5. $\theta \gets \top \text{ if } c = c' \text{ else } \bot$

# 3. Thin VRF

Thin VRF is structurally similar to Tiny VRF: it prepends $(G, Y)$ to the I/O
pairs, applies delinearization, and proves a single DLEQ on the merged pair.
The difference is the proof format: Thin VRF stores the nonce commitment $R$
rather than the challenge $c$, which enables batch verification at the cost
of a slightly larger proof.

## 3.1. Prove

**Input**:

- $x \in \F$: Secret key.
- $\overline{io} \in (\G \times \G)^n$: VRF input/output pairs.
- $ad \in \S^*$: Additional data octet-string.

**Output**:

- $\pi = (R, s) \in (\G, \F)$: Thin VRF proof.

**Steps**:

1. $Y \gets x \cdot G$
2. $(T, (I_m, O_m)) \gets \texttt{vrf\_transcript}(\texttt{ThinVrf}, [(G, Y)] \;\Vert\; \overline{io}, ad)$
3. $k \gets \texttt{nonce}(x, T.\texttt{fork}())$
4. $R \gets k \cdot I_m$
5. $c \gets \texttt{challenge}([R], T)$
6. $s \gets k + c \cdot x$
7. $\pi \gets (R, s)$

## 3.2. Verify

**Input**:

- $Y \in \G$: Public key.
- $\overline{io} \in (\G \times \G)^n$: VRF input/output pairs.
- $ad \in \S^*$: Additional data octet-string.
- $\pi = (R, s) \in (\G, \F)$: Thin VRF proof.

**Output**:

- $\theta \in \{ \top, \bot \}$: $\top$ if proof is valid, $\bot$ otherwise.

**Steps**:

1. Validate $R \in \G$ and $Y, I_i, O_i \in \G \setminus \{\mathcal{O}\}$ for all $i$, output $\bot$ if any point is not in $\G$, or if $Y$ or any $I_i, O_i$ is the identity.
2. $(T, (I_m, O_m)) \gets \texttt{vrf\_transcript}(\texttt{ThinVrf}, [(G, Y)] \;\Vert\; \overline{io}, ad)$
3. $c \gets \texttt{challenge}([R], T)$
4. $\theta \gets \top \text{ if } s \cdot I_m = R + c \cdot O_m \text{ else } \bot$

The identity is a legal value for $R$ and MUST NOT be rejected. $R$ is a
prover-chosen commitment and step 4 is sound for any value of it. $R$ is the
identity only when $k = 0$, which makes $s = c \cdot x$ and publishes the secret
key. A verifier that rejects it diverges from one that does not, on a proof that
no honest prover produces.

## 3.3. Batch Verify

Multiple Thin VRF proofs can be verified together by combining the
individual verification equations with random weights (Schwartz-Zippel
lemma).

**Input**:

- For $j = 0, \ldots, N-1$: a tuple $(Y_j, \overline{io}_j, ad_j, \pi_j)$ where:
  - $Y_j \in \G$: Public key.
  - $\overline{io}_j \in (\G \times \G)^{M_j}$: VRF input/output pairs.
  - $ad_j \in \S^*$: Additional data octet-string.
  - $\pi_j = (R_j, s_j) \in (\G, \F)$: Thin VRF proof.

**Output**:

- $\theta \in \{ \top, \bot \}$: $\top$ if all proofs verify, $\bot$ otherwise.

**Steps**:

1. For each proof $j$:
   a. Validate $R_j \in \G$ and $Y_j, I_{j,i}, O_{j,i} \in \G \setminus \{\mathcal{O}\}$ for all $i$, output $\bot$ if any point is not in $\G$, or if $Y_j$ or any $I_{j,i}, O_{j,i}$ is the identity.
   b. $(T_j, (I_{m,j}, O_{m,j})) \gets \texttt{vrf\_transcript}(\texttt{ThinVrf}, [(G, Y_j)] \;\Vert\; \overline{io}_j, ad_j)$
   c. $c_j \gets \texttt{challenge}([R_j], T_j)$

2. Derive random weights:
   a. $T_w \gets \texttt{new\_transcript}()$
   b. $T_w.\texttt{absorb}(\texttt{BatchVerify})$
   c. For each $j$: $T_w.\texttt{absorb}(\texttt{enc\_scalar}(c_j) \;\Vert\; \texttt{enc\_scalar}(s_j))$

3. Check the combined equation:
   $$\sum_{j=0}^{N-1} w_j \cdot (s_j \cdot I_{m,j} - R_j - c_j \cdot O_{m,j}) = \mathcal{O}$$
   where $w_j \gets \texttt{dec\_scalar\_mod}(T_w.\texttt{squeeze}(\texttt{challenge\_len}))$.

**Transcript**:

$\begin{aligned}
T_w = &\; \texttt{suite\_id} \;\Vert\; \texttt{BatchVerify} \\
  &\; \Vert\; \texttt{enc\_scalar}(c_0) \;\Vert\; \texttt{enc\_scalar}(s_0) \;\Vert\; \cdots \;\Vert\; \texttt{enc\_scalar}(c_{N-1}) \;\Vert\; \texttt{enc\_scalar}(s_{N-1})
\end{aligned}$


# 4. Pedersen VRF

Pedersen VRF resembles Tiny VRF but replaces the public key with a Pedersen
commitment to the secret key, which makes this VRF useful in anonymized ring
proofs.

The scheme proves that the output has been generated with a secret key
associated with a blinded public key (instead of the public key). The blinded
public key is a cryptographic commitment to the public key, and it can be
unblinded to prove that the output of the VRF corresponds to the public key of
the signer.

This specification mostly follows the design proposed by [BCHSV23] [@BCHSV23]
in section 4 with some details about blinding base point value and challenge
generation procedure.

The *blinding base* $B \in \G$ is defined as:
$$\footnotesize\begin{aligned}
x &= 17638779463981703257024232969105388646911395063733460320920179720743770753630 \\
y &= 43412064883199366458194534351728261914394039555474967635990234742472338103665
\end{aligned}$$

A point with unknown discrete logarithm derived using the `hash_to_curve` function
as described in Appendix A.2 with input the string: `"pedersen-blinding"`.

## 4.1. Prove

**Input**:

- $x \in \F$: Secret key.
- $\overline{io} \in (\G \times \G)^n$: VRF input/output pairs.
- $ad \in \S^*$: Additional data octet-string.

**Output**:

- $\pi = (\bar{Y}, R, O_k, s, s_b) \in (\G, \G, \G, \F, \F)$: Pedersen proof.
- $b \in \F$: Blinding factor.

**Steps**:

1. $(T, (I_m, O_m)) \gets \texttt{vrf\_transcript}(\texttt{PedersenVrf}, \overline{io}, ad)$
2. $b \gets \texttt{blinding}(x, T.\texttt{fork}())$ (see Appendix A.4)
3. $\bar{Y} \gets x \cdot G + b \cdot B$
4. $T.\texttt{absorb}(\texttt{enc\_point}(\bar{Y}))$
5. $k \gets \texttt{nonce}(x, T.\texttt{fork}())$, $\quad k_b \gets \texttt{nonce}(b, T.\texttt{fork}())$
6. $R \gets k \cdot G + k_b \cdot B$
7. $O_k \gets k \cdot I_m$
8. $c \gets \texttt{challenge}([R, O_k], T)$
9. $s \gets k + c \cdot x$, $\quad s_b \gets k_b + c \cdot b$
10. $\pi \gets (\bar{Y}, R, O_k, s, s_b)$

## 4.2. Verify

**Input**:

- $\overline{io} \in (\G \times \G)^n$: VRF input/output pairs.
- $ad \in \S^*$: Additional data octet-string.
- $\pi = (\bar{Y}, R, O_k, s, s_b) \in (\G, \G, \G, \F, \F)$: Pedersen proof.

**Output**:

- $\theta \in \{ \top, \bot \}$: $\top$ if proof is valid, $\bot$ otherwise.

**Steps**:

1. Validate $R, O_k \in \G$ and $\bar{Y}, I_i, O_i \in \G \setminus \{\mathcal{O}\}$ for all $i$, output $\bot$ if any point is not in $\G$, or if $\bar{Y}$ or any $I_i, O_i$ is the identity.
2. $(T, (I_m, O_m)) \gets \texttt{vrf\_transcript}(\texttt{PedersenVrf}, \overline{io}, ad)$
3. $T.\texttt{absorb}(\texttt{enc\_point}(\bar{Y}))$
4. $c \gets \texttt{challenge}([R, O_k], T)$
5. $\theta_0 \gets \top \text{ if } O_k + c \cdot O_m = s \cdot I_m \text{ else } \bot$
6. $\theta_1 \gets \top \text{ if } R + c \cdot \bar{Y} = s \cdot G + s_b \cdot B \text{ else } \bot$
7. $\theta = \theta_0 \land \theta_1$

Note: no public key appears in the verify inputs -- verification uses the
committed key $\bar{Y}$ from the proof.

The identity is a legal value for $R$ and $O_k$ and MUST NOT be rejected. Both
are prover-chosen commitments and steps 5 and 6 are sound for any value of them.
Both are the identity only when $k = 0$, which makes $s = c \cdot x$ and
publishes the secret key. $O_k$ is also the identity for every honest proof with
$n = 0$, where $I_m = \mathcal{O}$ (see Appendix B). A verifier that rejects
these values diverges from one that does not.

## 4.3. Unblinding

Links a Pedersen VRF proof to a specific public key. The prover reveals the
blinding factor $b$, and the verifier checks that the proof is valid and that
its committed key opens to the claimed public key.

**Input**:

- $\overline{io} \in (\G \times \G)^n$: VRF input/output pairs.
- $ad \in \S^*$: Additional data octet-string.
- $\pi = (\bar{Y}, R, O_k, s, s_b) \in (\G, \G, \G, \F, \F)$: Pedersen proof.
- $b \in \F$: Blinding factor revealed by the prover.
- $Y \in \G$: Claimed public key.

**Output**:

- $\theta \in \{ \top, \bot \}$: $\top$ if the proof is attributable to $Y$, $\bot$ otherwise.

**Steps**:

1. Validate $Y$ and $\bar{Y}$ $\in \G \setminus \{\mathcal{O}\}$, output $\bot$ if either is invalid or the identity.
2. $\theta_0 \gets Pedersen.verify(\overline{io}, ad, \pi)$ (section 4.2)
3. $\theta_1 \gets \top \text{ if } \bar{Y} = Y + b \cdot B \text{ else } \bot$
4. $\theta \gets \theta_0 \land \theta_1$

The verifier MUST NOT accept the association unless step 2 outputs $\top$ for
the same $(\overline{io}, ad, \pi)$ that supplied $\bar{Y}$. Step 3 on its own
is not evidence of authorship: any party can compute $\bar{Y} = Y + b \cdot B$
for a public key $Y$ it does not control, without knowledge of the
corresponding secret key.

## 4.4. Batch Verify

Multiple Pedersen VRF proofs can be verified together by combining the
individual verification equations with random weights (Schwartz-Zippel
lemma). Each proof contributes two equations (VRF correctness and Pedersen
commitment correctness), each weighted by an independent random scalar.

**Input**:

- For $j = 0, \ldots, N-1$: a tuple $(\overline{io}_j, ad_j, \pi_j)$ where:
  - $\overline{io}_j \in (\G \times \G)^{M_j}$: VRF input/output pairs.
  - $ad_j \in \S^*$: Additional data octet-string.
  - $\pi_j = (\bar{Y}_j, R_j, O_{k,j}, s_j, s_{b,j}) \in (\G, \G, \G, \F, \F)$: Pedersen proof.

**Output**:

- $\theta \in \{ \top, \bot \}$: $\top$ if all proofs verify, $\bot$ otherwise.

**Steps**:

1. For each proof $j$:
   a. Validate $R_j, O_{k,j} \in \G$ and $\bar{Y}_j, I_{j,i}, O_{j,i} \in \G \setminus \{\mathcal{O}\}$ for all $i$, output $\bot$ if any point is not in $\G$, or if $\bar{Y}_j$ or any $I_{j,i}, O_{j,i}$ is the identity.
   b. $(T_j, (I_{m,j}, O_{m,j})) \gets \texttt{vrf\_transcript}(\texttt{PedersenVrf}, \overline{io}_j, ad_j)$
   c. $T_j.\texttt{absorb}(\texttt{enc\_point}(\bar{Y}_j))$
   d. $c_j \gets \texttt{challenge}([R_j, O_{k,j}], T_j)$

2. Derive random weights:
   a. $T_w \gets \texttt{new\_transcript}()$
   b. $T_w.\texttt{absorb}(\texttt{BatchVerify})$
   c. For each $j$: $T_w.\texttt{absorb}(\texttt{enc\_scalar}(c_j) \;\Vert\; \texttt{enc\_scalar}(s_j) \;\Vert\; \texttt{enc\_scalar}(s_{b,j}))$

3. Check the combined equations:
   $$\sum_{j=0}^{N-1} t_j \cdot (O_{k,j} + c_j \cdot O_{m,j} - s_j \cdot I_{m,j}) + u_j \cdot (R_j + c_j \cdot \bar{Y}_j - s_j \cdot G - s_{b,j} \cdot B) = \mathcal{O}$$
   where:
   - $t_j \gets \texttt{dec\_scalar\_mod}(T_w.\texttt{squeeze}(\texttt{challenge\_len}))$
   - $u_j \gets \texttt{dec\_scalar\_mod}(T_w.\texttt{squeeze}(\texttt{challenge\_len}))$

**Transcript**:

$\begin{aligned}
T_w = &\; \texttt{suite\_id} \;\Vert\; \texttt{BatchVerify} \\
  &\; \Vert\; \texttt{enc\_scalar}(c_0) \;\Vert\; \texttt{enc\_scalar}(s_0) \;\Vert\; \texttt{enc\_scalar}(s_{b,0}) \\
  &\; \Vert\; \cdots \\
  &\; \Vert\; \texttt{enc\_scalar}(c_{N-1}) \;\Vert\; \texttt{enc\_scalar}(s_{N-1}) \;\Vert\; \texttt{enc\_scalar}(s_{b,N-1})
\end{aligned}$

# 5. Ring VRF

Anonymized ring VRF based on Pedersen VRF (section 4) and Ring Proof as
proposed in [BCHSV23] [@BCHSV23].

The ring proof can be seen as a special case of the Committee Key Scheme (CKS)
introduced by [CSSV22] [@CSSV22], reduced to a single signer. In CKS, a prover
commits to a set of public keys using a KZG polynomial commitment and produces a
SNARK showing that a subset of keys -- identified by a bitvector -- belongs to the
committed set. The ring proof is the degenerate case where the bitvector has exactly
one bit set: it proves that a single (blinded) key is a member of the committed ring,
without revealing which one.

The concrete specification of the ring proof scheme is given in [VG24] [@VG24].
The following configuration specializes it for this scheme:

- **Groups and Fields**:
  - $\mathbb{G_1}$: BLS12-381 prime order subgroup.
  - $\mathbb{F}$: BLS12-381 scalar field.
  - $J$: Bandersnatch curve defined over $\mathbb{F}$.

- **Polynomial Commitment Scheme**
  - KZG with SRS derived from [Zcash](https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony) powers of tau ceremony.

- **Fiat-Shamir Transform**
  - [`ark-transcript`](https://crates.io/crates/ark-transcript).
  - Begin with empty transcript and "ring-proof" label.
  - Push $R$ to the transcript after instancing.


- Accumulator base point $S \in \G$ is defined as:
$$\footnotesize\begin{aligned}
x &= 40491514051566626997660191275481402633028619220985639345189701840760973773876 \\
y &= 30656473616574028893331120350555815475572115533831243689136786502363899874226
\end{aligned}$$

A point with unknown discrete logarithm derived using the `hash_to_curve` function
as described in Appendix A.2 with input the string: `"ring-accumulator"`.

- Padding point $\square \in \G$ is defined as:
$$\footnotesize\begin{aligned}
x &= 36880292816015504914760276407095125078764838679354034448146164617114507060377 \\
y &= 42881976946106967947876454617806466371421329384961230126625568686348457494844
\end{aligned}$$

A point with unknown discrete logarithm derived using the `hash_to_curve` function
as described in Appendix A.2 with input the string: `"ring-padding"`.

- Polynomials domain ($\langle \omega \rangle = \mathbb{D}$) generator:
$$\footnotesize \omega = 49307615728544765012166121802278658070711169839041683575071795236746050763237$$

- $|\mathbb{D}| = 2048$

## 5.1. Prove

**Input**:

- $x \in \F$: Secret key.
- $\overline{io} \in (\G \times \G)^n$: VRF input/output pairs.
- $ad \in \S^*$: Additional data octet-string.
- $P$: Ring prover (encapsulates ring keys and prover index).

**Output**:

- $\pi_p \in (\G, \G, \G, \F, \F)$: Pedersen proof.
- $\pi_r \in ((G_1)^4, (\F)^7, G_1, \F, G_1, G_1)$: Ring proof.

**Steps**:

1. $(\pi_p, b) \gets Pedersen.prove(x, \overline{io}, ad)$
2. $\pi_r \gets Ring.prove(P, b)$

The blinding factor $b$ is derived internally by Pedersen prove (section 4.1,
step 2) and forwarded to the ring prover. $Ring.prove$ and $Ring.verify$ are
defined in [VG24] [@VG24].

## 5.2. Verify

**Input**:

- $\overline{io} \in (\G \times \G)^n$: VRF input/output pairs.
- $ad \in \S^*$: Additional data octet-string.
- $\pi_p \in (\G, \G, \G, \F, \F)$: Pedersen proof.
- $\pi_r \in ((G_1)^4, (\F)^7, G_1, \F, G_1, G_1)$: Ring proof.
- $V \in (G_1)^3$: Ring verifier (pre-processed commitment).

**Output**:

- $\theta \in \{ \top, \bot \}$: $\top$ if proof is valid, $\bot$ otherwise.

**Steps**:

1. $\theta_0 \gets Pedersen.verify(\overline{io}, ad, \pi_p)$
2. $(\bar{Y}, R, O_k, s, s_b) \gets \pi_p$
3. $\theta_1 \gets Ring.verify(V, \pi_r, \bar{Y})$
4. $\theta \gets \theta_0 \land \theta_1$

Note: to attribute a ring signature to a public key, apply the unblinding
procedure of section 4.3 to $\pi_p$. The verifier MUST NOT accept that
attribution unless this procedure outputs $\top$ for the same inputs, because
$Ring.verify$ is what binds $\bar{Y}$ to a member of the ring. A $\top$ from
$Pedersen.verify$ alone proves knowledge of an opening of $\bar{Y}$, not ring
membership.


# Appendix A. Concrete Instantiations

The following are concrete instantiations of the abstract interfaces defined
in the main specification. They are provided to enable interoperable
implementations and reproducible test vectors. Alternative constructions
that satisfy the same security requirements are equally valid.

## A.1. Transcript Construction

Instantiation of the transcript interface (section 1.6.1) using SHA-512.

**Initialization**: $\texttt{new\_transcript}()$ creates a fresh SHA-512 state and
feeds $\texttt{suite\_id}$ into it.

**Absorb**: feeds raw bytes directly into the SHA-512 state. Consecutive absorb
calls are equivalent to a single absorb of the concatenated data. This is safe
because all protocol fields use fixed-width encoding ($\texttt{enc\_point}$: 32
bytes, $\texttt{enc\_scalar}$: 32 bytes, $\texttt{enc\_64}$: 8 bytes, domain
tags: 1 byte) or explicit length prefixing ($ad$ via
$\texttt{enc\_64}(\texttt{len}(ad)) \;\Vert\; ad$), so the byte stream is
unambiguous given the inputs agreed upon by both parties.

**Squeeze** (counter-mode XOF): on the first squeeze call, finalize the SHA-512
state to obtain a 64-byte $seed$. Then produce output blocks:

$$block_i = \text{SHA-512}(seed \;\Vert\; \texttt{enc\_64}(i)) \quad \text{for } i = 0, 1, 2, \ldots$$

where $\texttt{enc\_64}(n)$ encodes integer $n$ as an 8-byte little-endian octet string.
Each block yields 64 bytes. Output is read sequentially across blocks; partial
block state is preserved between squeeze calls.

**Fork**: duplicates the full internal state (including any partial block position
if squeezing has begun).

## A.2. Hash to Curve

Instantiation of the $\texttt{hash\_to\_curve}$ function (section 1.6.2)
using the method defined in section 3 of [RFC-9380] [@RFC9380], with the
*Elligator 2* map to curve (section 6.8.2) and
$\texttt{expand\_message\_xmd}$ with SHA-512 (section 5.3.1).

The zero prefix $Z_{pad}$ of $\texttt{expand\_message\_xmd}$ has the length of
the SHA-512 input block, $\texttt{s\_in\_bytes} = 128$, as section 5.3.1 requires.

This is the random oracle (`_RO_`) construction: the input is hashed to two
independent field elements, each is mapped to a curve point via Elligator 2,
and the results are added.

$$I \gets \texttt{hash\_to\_curve\_ell2}(DST, i)$$

The domain separation tag is:

$$DST = \texttt{suite\_id} \;\Vert\; \texttt{HashToCurve}$$

i.e. the 27-byte $\texttt{suite\_id}$ string concatenated with the single
$\texttt{HashToCurve}$ tag byte (0x60). This matches the per-operation
tagging used elsewhere in the protocol.

## A.3. Secret Key Generation

Derives a secret scalar from a 32-byte seed.

**Input**:

- $seed \in \S^{32}$: seed octet-string.

**Output**:

- $x \in \F$: secret key scalar.

**Steps**:

1. $i \gets 0$
2. $T \gets \texttt{new\_transcript}()$
3. $T.\texttt{absorb}(seed)$
4. If $i > 0$: $T.\texttt{absorb}(i)$ where $i$ is encoded as a single octet
5. $d \gets \texttt{dec\_scalar\_mod}(seed)$
6. $x \gets \texttt{nonce}(d, T)$
7. If $x = 0$: increment $i$ and go to step 2
8. Return $x$

The seed is absorbed into the transcript and also passed as a scalar to the
$\texttt{nonce}$ procedure (section 1.6.6), ensuring seed entropy flows through
both the transcript state and the secret scalar input paths.

## A.4. Blinding Factor Generation

Generates the Pedersen VRF blinding factor deterministically from the secret
key and the VRF transcript state, using the nonce function (section 1.6.6)
with a distinct domain separator.

**Linkability warning**: because $b$ is derived deterministically from $(x, T)$,
two Pedersen VRF proofs with the same secret key, I/O pairs, and additional data
will produce the same blinding factor $b$ and therefore the same blinded public
key $\bar{Y} = x \cdot G + b \cdot B$. An observer can detect that both proofs
originate from the same signer by comparing $\bar{Y}$ values. Applications that
require unlinkability across repeated proofs on the same inputs should generate
$b$ as a fresh uniformly random scalar rather than using this deterministic method.

**Input**:

- $x \in \F$: Secret scalar.
- $T$: Transcript state (from $\texttt{vrf\_transcript}$).

**Output**:

- $b \in \F$: Blinding factor scalar.

**Steps**:

1. $T.\texttt{absorb}(\texttt{PedersenBlinding})$
2. $b \gets \texttt{nonce}(x, T)$

# Appendix B. Behavior with Zero I/O Pairs

When $n = 0$ no VRF output can be derived, since there are no output points
to hash. The proof-of-knowledge component, however, remains sound in all
schemes: a valid proof still requires knowledge of the secret key $x$.

- **Tiny VRF and Thin VRF**: Both schemes prepend the Schnorr pair $(G, Y)$
  to the I/O list before delinearization (sections 2.1 and 3.1, step 2),
  so the internal pair count is at least 1 regardless of the user-supplied $n$.
  With zero VRF pairs, the scheme degenerates to a Schnorr signature on the
  additional data $ad$, proving knowledge of $x$ for public key $Y$.

- **Pedersen VRF**: No Schnorr pair is prepended, so with $n = 0$ the
  $\texttt{delinearize}$ procedure (section 1.6.4) sets the merged pair to
  the identity: $(I_m, O_m) = (\mathcal{O}, \mathcal{O})$. The VRF output
  check $O_k + c \cdot O_m = s \cdot I_m$ degenerates to $O_k = \mathcal{O}$,
  which an honest prover satisfies because $O_k = k \cdot \mathcal{O}$. This is
  why section 4.2 step 1 accepts the identity for $O_k$. The commitment check
  $R + c \cdot \bar{Y} = s \cdot G + s_b \cdot B$ still proves knowledge
  of the Pedersen commitment opening $(x, b)$.

Such a proof carries no VRF output. An application that consumes a VRF output
MUST require $n \geq 1$ at the call site. The schemes do not enforce it.

# Appendix C. Test Vectors

The test vectors in this section were generated using `ark-vrf` version `0.6.0`.

## C.1. Tiny VRF Test Vectors

Schema:

```
sk (x): Secret key,
pk (Y): Public key,
in (alpha): Input octet-string,
ad: Additional data octet-string,
h (I): VRF input point,
gamma (O): VRF output point,
out (beta): VRF output octet string,
proof_c: Proof 'c' component,
proof_s: Proof 's' component,
```

### bandersnatch_sha-512_ell2_tiny - vector-1

```
c9922b7a9849b9928e15c655dd2f22ceef737cc355024f43d4b04bf4398c270d,
5a538209ff1fc7b1c9c8e1da05b3e169acf10a8b1591b3af029fe4eede0bbc71,
-,
-,
da53140f00880b48b521e30eeae932b00af63e89ef3f6b6de6429ca116df3e92,
7d73e10faa2d14c62c5178f189684bf37e522933658cd54d793ec59e513b4ce1,
b525d2bbdd50f584b7bec9053144c7b3d6e07c3b471b23ce11c2915902bc63ea,
0f3ff3657224ccdcac3371612b4ae57d,
1c658faa6d21791a7afa39f4f5297859d223630fbc67e479d9079396ee110f03,
```

### bandersnatch_sha-512_ell2_tiny - vector-2

```
0b4259ca1b10c9ed462532639113e1caf26b3a1a2d9e91ecef2fc5c2d23aed0a,
ff341f0c9da793b2d8fef91bcbfd5b55c2185352e4289edc1dd6c64e3fe09b0d,
0a,
-,
a983ad5fa909ee27bee75a51961b64b5f73ba50200cf7556f6585a716db52567,
e0b97c7186421f417d0bee66b4c6e0b221a89d1d6c8ee2997d6641b368601e8e,
ded743c72cb4803ee03f09f9bf1fcd3817aab9ef82a4d07df69e141a8f4928c4,
105c2fad8ae226ad0f7522872edb9a6b,
853255974a38c7802813c2d077a4e6853f50a74153660a5a7f7a056586c94005,
```

### bandersnatch_sha-512_ell2_tiny - vector-3

```
dd60163595ff312a49aa5849917ba19020038ccd42f8a1d468da0973079bdb15,
fbba8feb488e767b9864726fffdc8595896757430eba9162a1a5d9a03381d5a4,
-,
0b8c,
da53140f00880b48b521e30eeae932b00af63e89ef3f6b6de6429ca116df3e92,
3c1ddf34f1d281a420d94c01b72af4dfc8dd4e8441e21f1b6fa158bb6b2a4772,
695fbcdc0d960798a7202d2c08cbed5d4d6a6209355432d639a38a8dba1f64d2,
4c355100a7d17ad4882226563c64f6b8,
98ec15f2f5f7540e89be38c350deab563958581e82c67775adacbb87214fe00f,
```

### bandersnatch_sha-512_ell2_tiny - vector-4

```
dfc32f03fe9487f123f2afeeb9487cb6b1eb23efac24a60ae540f5aa632ddd18,
f8487052801a89161424ee745189b5f7fe568819b9f13f44a8b3d173b57e928a,
73616d706c65,
-,
cd62c478f6751112afb7f29b0e046e5827927fe5e5e3b51c0977ff95aa20c859,
2ad7e3bdf71a946a75c7bb7b5bb639efc2f92feae4a79be2d01a05b4a5b268e3,
fd43c8d27c24f99392a0ac5e82050eacfbfdad9d6f4c835b21eea27fef083ec0,
554856f6336cce0824abdcdc83dd1044,
c8938371d718ff0b18ff275401eea815aa21dafa251349278860c3fa3caaab14,
```

### bandersnatch_sha-512_ell2_tiny - vector-5

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
-,
5101703a33a054dde44c22bd34bf8a09d5e6b4308ee0b9f74fb5157c8510a11a,
7a506355bf7ccd218c7e98f8065b0cc2e408a99c0decffcc46f76f4bf8f17b64,
431afac5eaf0ca01e941ddb9286e3a75b9a7cd394173ca04b19aa1e55daaf50e,
b27f7adcce3a887c5b537bcebefa1a11,
7b58a03acad3adcad2878cc5fe27d617ad1d2d38590453c14fd3269a649b7111,
```

### bandersnatch_sha-512_ell2_tiny - vector-6

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
1f42,
5101703a33a054dde44c22bd34bf8a09d5e6b4308ee0b9f74fb5157c8510a11a,
7a506355bf7ccd218c7e98f8065b0cc2e408a99c0decffcc46f76f4bf8f17b64,
431afac5eaf0ca01e941ddb9286e3a75b9a7cd394173ca04b19aa1e55daaf50e,
f53350f961ac3cddf2d6f0e012ed2aa9,
e1562c67ec7d7ac9ebce6084eafefd395f89cff47b06b475506f32ce2f5a3401,
```

### bandersnatch_sha-512_ell2_tiny - vector-7

```
9504efbeadf81b20a9cb64c1331915eb3718a574227458230d1d80dfa94e8b13,
704fd3784947de4db4fdcf0b477530d094bf5a656707b7d6cb43edbc4db7336b,
42616e646572736e6174636820766563746f72,
1f42,
5101703a33a054dde44c22bd34bf8a09d5e6b4308ee0b9f74fb5157c8510a11a,
7cbd62788fe8bbcc769314af10959eaeaa1f190c6bb5ce8ba7814e55631f9451,
467c08c60416cf1b7846ee311e4898e188683bd91e9606c39ccf20ddd43208bc,
91ba7006ac304954eb1004f597511536,
2a0ff9fc403e485abd521fbfb384756160257da28899b10d5126155ef5b0931a,
```

## C.2. Thin VRF Test Vectors

```
sk (x): Secret key,
pk (Y): Public key,
in (alpha): Input octet-string,
ad: Additional data octet-string,
h (I): VRF input point,
gamma (O): VRF output point,
out (beta): VRF output octet string,
proof_r: Proof 'r' component,
proof_s: Proof 's' component,
```

### bandersnatch_sha-512_ell2_thin - vector-1

```
c9922b7a9849b9928e15c655dd2f22ceef737cc355024f43d4b04bf4398c270d,
5a538209ff1fc7b1c9c8e1da05b3e169acf10a8b1591b3af029fe4eede0bbc71,
-,
-,
da53140f00880b48b521e30eeae932b00af63e89ef3f6b6de6429ca116df3e92,
7d73e10faa2d14c62c5178f189684bf37e522933658cd54d793ec59e513b4ce1,
b525d2bbdd50f584b7bec9053144c7b3d6e07c3b471b23ce11c2915902bc63ea,
b5d0c11e95ac116497a0205c2aa9d51f37ed61e35313738a093275813fcba903,
69ceb9268574dd1f174a98fde63b15131bb1c6d2e39ff24f445eb1ab61dab20d,
```

### bandersnatch_sha-512_ell2_thin - vector-2

```
0b4259ca1b10c9ed462532639113e1caf26b3a1a2d9e91ecef2fc5c2d23aed0a,
ff341f0c9da793b2d8fef91bcbfd5b55c2185352e4289edc1dd6c64e3fe09b0d,
0a,
-,
a983ad5fa909ee27bee75a51961b64b5f73ba50200cf7556f6585a716db52567,
e0b97c7186421f417d0bee66b4c6e0b221a89d1d6c8ee2997d6641b368601e8e,
ded743c72cb4803ee03f09f9bf1fcd3817aab9ef82a4d07df69e141a8f4928c4,
6bc5fbdaa6a31506e730d1c40df43ca648794924a8aca68ee131f9981e67cb8b,
ab72142b9d8c30a85bb0ead1ebce598f2a2d748abb2c6d82d9bb3362bde05b0b,
```

### bandersnatch_sha-512_ell2_thin - vector-3

```
dd60163595ff312a49aa5849917ba19020038ccd42f8a1d468da0973079bdb15,
fbba8feb488e767b9864726fffdc8595896757430eba9162a1a5d9a03381d5a4,
-,
0b8c,
da53140f00880b48b521e30eeae932b00af63e89ef3f6b6de6429ca116df3e92,
3c1ddf34f1d281a420d94c01b72af4dfc8dd4e8441e21f1b6fa158bb6b2a4772,
695fbcdc0d960798a7202d2c08cbed5d4d6a6209355432d639a38a8dba1f64d2,
e5bfcbb1f633a92e958af5e9f920ffd0d3993b5881d30039a2c379f7844b4443,
9c40ae822c672f09775305837a0f54fa99dd9088b006e1f9afafaf036a3ce90e,
```

### bandersnatch_sha-512_ell2_thin - vector-4

```
dfc32f03fe9487f123f2afeeb9487cb6b1eb23efac24a60ae540f5aa632ddd18,
f8487052801a89161424ee745189b5f7fe568819b9f13f44a8b3d173b57e928a,
73616d706c65,
-,
cd62c478f6751112afb7f29b0e046e5827927fe5e5e3b51c0977ff95aa20c859,
2ad7e3bdf71a946a75c7bb7b5bb639efc2f92feae4a79be2d01a05b4a5b268e3,
fd43c8d27c24f99392a0ac5e82050eacfbfdad9d6f4c835b21eea27fef083ec0,
0b164114bde80a74b8d22e969c16e8275a1d6609fc7abce3f650e7d45d231ae6,
120674667637995b723bacc63e9557621b08fda79159250c031e08e673c09010,
```

### bandersnatch_sha-512_ell2_thin - vector-5

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
-,
5101703a33a054dde44c22bd34bf8a09d5e6b4308ee0b9f74fb5157c8510a11a,
7a506355bf7ccd218c7e98f8065b0cc2e408a99c0decffcc46f76f4bf8f17b64,
431afac5eaf0ca01e941ddb9286e3a75b9a7cd394173ca04b19aa1e55daaf50e,
207e3fde415f91d7615c48f66fea1062e639ec4c368a9f107975821d57e12d93,
2eea79fce59148e17ef4d6b7c18ede42327b94721d9b079a7a11b8a26c7ebd0e,
```

### bandersnatch_sha-512_ell2_thin - vector-6

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
1f42,
5101703a33a054dde44c22bd34bf8a09d5e6b4308ee0b9f74fb5157c8510a11a,
7a506355bf7ccd218c7e98f8065b0cc2e408a99c0decffcc46f76f4bf8f17b64,
431afac5eaf0ca01e941ddb9286e3a75b9a7cd394173ca04b19aa1e55daaf50e,
ce955a1a13960e53f5032889ae6347766e76e1ccf573f766ca07772708189cbb,
909b9b6a7188dffb4189216f31d25f9eba4d72afaf4762354abf4721234bf71b,
```

### bandersnatch_sha-512_ell2_thin - vector-7

```
9504efbeadf81b20a9cb64c1331915eb3718a574227458230d1d80dfa94e8b13,
704fd3784947de4db4fdcf0b477530d094bf5a656707b7d6cb43edbc4db7336b,
42616e646572736e6174636820766563746f72,
1f42,
5101703a33a054dde44c22bd34bf8a09d5e6b4308ee0b9f74fb5157c8510a11a,
7cbd62788fe8bbcc769314af10959eaeaa1f190c6bb5ce8ba7814e55631f9451,
467c08c60416cf1b7846ee311e4898e188683bd91e9606c39ccf20ddd43208bc,
968d574099edced7bf06f6923eb05f171aee5256151a04395a9a178ac08fe8d3,
3a5dacca8c36013fefeb4d9cb43b47367a773a0e9eb0d0516eb5b54be7f68302,
```

## C.3. Pedersen VRF Test Vectors

Schema:

```
sk (x): Secret key,
pk (Y): Public key,
in (alpha): Input octet-string,
ad: Additional data octet-string,
h (I): VRF input point,
gamma (O): VRF output point,
out (beta): VRF output octet string,
blinding: Blinding factor,
proof_pk_com (Y^-): Public key commitment,
proof_r: Proof 'R' component,
proof_ok: Proof 'O_k' component,
proof_s: Proof 's' component,
proof_sb: Proof 's_b' component
```

### bandersnatch_sha-512_ell2_pedersen - vector-1

```
c9922b7a9849b9928e15c655dd2f22ceef737cc355024f43d4b04bf4398c270d,
5a538209ff1fc7b1c9c8e1da05b3e169acf10a8b1591b3af029fe4eede0bbc71,
-,
-,
da53140f00880b48b521e30eeae932b00af63e89ef3f6b6de6429ca116df3e92,
7d73e10faa2d14c62c5178f189684bf37e522933658cd54d793ec59e513b4ce1,
b525d2bbdd50f584b7bec9053144c7b3d6e07c3b471b23ce11c2915902bc63ea,
13019b834e09fbd3d8f7c2f7e4df0331da830f816fe7d744e665b877e5093b03,
348028451cd329b3625545a53a466db9643e18db7371c930ba78810a1243159d,
a44cb42b162d0df19e45523f43e51035205548aa2270972b1fe59076b3897d4d,
8cb651e59811db93b0241bc947583521d9cd5ee29cddbf172ede62700635ef5f,
5fc11c37f5950147861b19ec63e6968c3fcbd19edf81cf768f07d2ca74ffe90d,
c516b53aeb9438808b10e510ef7318cfd26f584774927fcb9c709251794bf30a,
```

### bandersnatch_sha-512_ell2_pedersen - vector-2

```
0b4259ca1b10c9ed462532639113e1caf26b3a1a2d9e91ecef2fc5c2d23aed0a,
ff341f0c9da793b2d8fef91bcbfd5b55c2185352e4289edc1dd6c64e3fe09b0d,
0a,
-,
a983ad5fa909ee27bee75a51961b64b5f73ba50200cf7556f6585a716db52567,
e0b97c7186421f417d0bee66b4c6e0b221a89d1d6c8ee2997d6641b368601e8e,
ded743c72cb4803ee03f09f9bf1fcd3817aab9ef82a4d07df69e141a8f4928c4,
0c0b4a2f50c5286cefe8445ca51fc60bca9eee92a43416132b9ef9f3a0925c0d,
454643f57f8e9e54337c878cd1ecd24d26e603d915ec98341d5b8b4d2063812c,
d4db568710ce5b75b337550fe85a3edd49b37287e029e368e99bd36a3b610126,
1753b67eceb4f8157a684584895e480942bdf28914505d434fdc8c35d0391f3c,
5e0eb5a8caa204970baa0838fd22606acb61526a3d174465cecc46f7f101ab15,
e2230207a3f24a1e6043892aff9d90b9a68cda52db1dedb95e217936d968bc17,
```

### bandersnatch_sha-512_ell2_pedersen - vector-3

```
dd60163595ff312a49aa5849917ba19020038ccd42f8a1d468da0973079bdb15,
fbba8feb488e767b9864726fffdc8595896757430eba9162a1a5d9a03381d5a4,
-,
0b8c,
da53140f00880b48b521e30eeae932b00af63e89ef3f6b6de6429ca116df3e92,
3c1ddf34f1d281a420d94c01b72af4dfc8dd4e8441e21f1b6fa158bb6b2a4772,
695fbcdc0d960798a7202d2c08cbed5d4d6a6209355432d639a38a8dba1f64d2,
ab326869bc1af08ea3026e96aa328cf86a6c3d42cfb8ea7bd32494b029ad9509,
fbaee4032036cc1e014e7e0a6d058602fa01fe01bd15244ef85c871b967b1967,
addde9505c29ec565783a4893562dac1272820aefd45c97b5c680a484841a994,
ebb55d70641daaf7c95ffaef7d94436e592785ba8dd091e64c0807fd9a2af43f,
a057106f4932a34546943ee2911290ff8d10731366d933d25f71b9e04f0af800,
95960b71a7adbf23f75fbfb16915f4fdf972f698fc712da447ef7a5d8601e603,
```

### bandersnatch_sha-512_ell2_pedersen - vector-4

```
dfc32f03fe9487f123f2afeeb9487cb6b1eb23efac24a60ae540f5aa632ddd18,
f8487052801a89161424ee745189b5f7fe568819b9f13f44a8b3d173b57e928a,
73616d706c65,
-,
cd62c478f6751112afb7f29b0e046e5827927fe5e5e3b51c0977ff95aa20c859,
2ad7e3bdf71a946a75c7bb7b5bb639efc2f92feae4a79be2d01a05b4a5b268e3,
fd43c8d27c24f99392a0ac5e82050eacfbfdad9d6f4c835b21eea27fef083ec0,
2f105bee93949fd8929078b849e07538f49325723946d6b350aa48a1d197f119,
9eb92236e9db8b3dcc1a68fcaef4b0d27058328aaa8ce444581a83681a4b91d1,
67b07cecffaaf5b0823a80ad57c1907b347cb92aaa53a1147a3268dc4cdd88f3,
db2d7ae1efa97aa634aab19dace2cf17d422833d3945d057a818cc364cb779c8,
bff315fdeec7cb195134fa6ad915023cbaaaf088a6dc92fdfd206764c853c311,
61bfbd83933666bcd1b7a35a24e92cde7cc33f81bcf10fa4f5412a13a0ec9815,
```

### bandersnatch_sha-512_ell2_pedersen - vector-5

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
-,
5101703a33a054dde44c22bd34bf8a09d5e6b4308ee0b9f74fb5157c8510a11a,
7a506355bf7ccd218c7e98f8065b0cc2e408a99c0decffcc46f76f4bf8f17b64,
431afac5eaf0ca01e941ddb9286e3a75b9a7cd394173ca04b19aa1e55daaf50e,
7b38b65acda35146522cafb3ff7f54548cf80d94d4bcb79107df58aa6b2b9c1c,
e217005a15d6814b0f66f7f950de451dfa7b94bb3c7f31342db351ed597387bb,
83e70bf1e0987445942481f3c500a056ddb5d050ab4888df2f01092db9705b2b,
aab254a61dbfec10b8b0de3d32d7abe955a96742a80be476c95ad22daae86b03,
2a698873fc078f442de9ec9a4ace0f52f2b136c8a16a12d7ff49476ea9fe6c10,
ba1a9d06fa98ef8ed3708586f3d4e946d8a1d1f7e14e08f67fc17ccef248fb14,
```

### bandersnatch_sha-512_ell2_pedersen - vector-6

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
1f42,
5101703a33a054dde44c22bd34bf8a09d5e6b4308ee0b9f74fb5157c8510a11a,
7a506355bf7ccd218c7e98f8065b0cc2e408a99c0decffcc46f76f4bf8f17b64,
431afac5eaf0ca01e941ddb9286e3a75b9a7cd394173ca04b19aa1e55daaf50e,
7b3dfd9e3e20f433831f7f77834435773773d7aef0003e4a20dbe65452b3ae14,
bc81076816153284d03136bd7c27223d7923162bf447dc4c1e36e25e4ff9584d,
98055b81caa91003fbd4c5d47da1a31693836d0ebcbb8c4c93c8e4198a69ef5e,
e02c45337dd0c6a7f7453ef437716eeee8658a13116697177f311cf2e0e0c957,
768031ec19ddd62cf5c1f9621ca817a93979dd31a4cd1d42c065554dfbfe9419,
96361eb858f2f3b370f939414495581d7e03130644abd7547a04d5fd50381518,
```

### bandersnatch_sha-512_ell2_pedersen - vector-7

```
9504efbeadf81b20a9cb64c1331915eb3718a574227458230d1d80dfa94e8b13,
704fd3784947de4db4fdcf0b477530d094bf5a656707b7d6cb43edbc4db7336b,
42616e646572736e6174636820766563746f72,
1f42,
5101703a33a054dde44c22bd34bf8a09d5e6b4308ee0b9f74fb5157c8510a11a,
7cbd62788fe8bbcc769314af10959eaeaa1f190c6bb5ce8ba7814e55631f9451,
467c08c60416cf1b7846ee311e4898e188683bd91e9606c39ccf20ddd43208bc,
ac7a84c0ae8462f1f375f2eff85c54506aa3fa5ca7b653d0a98d585f8c394e00,
22481b1e7dda724a032487f2b3ec389a238ee36c6421841b72c3f675c6f5a85e,
e4d55ac4816301e1b8406587060d0238a8138e920e208b022ce04735d11e5c8a,
5ef27127b2ea6e78009ec97d937e30c51963755ff2de32fb246a8664873e3285,
f652c9d56962f8e3e559db55315fcd66449d714cc282b3486f4a55fe4786d109,
b0365e43ff857130943e227ee5770a6744bf2ca1418dcc933863e89be8f19211,
```

## C.4. Ring VRF Test Vectors

KZG SRS parameters are derived from Zcash BLS12-381 [powers of tau ceremony](https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony).

The evaluations for the ZK domain items, specifically the evaluations of the
last three items in the evaluation domain $\mathbb{D}$, are set to 0 rather than
being randomly generated.

Schema:

```
sk (x): Secret key,
pk (Y): Public key,
in (alpha): Input octet-string,
ad: Additional data octet-string,
h (I): VRF input point,
gamma (O): VRF output point,
out (beta): VRF output octet string,
blinding: Blinding factor,
proof_pk_com (Y^-): Pedersen proof public key commitment,
proof_r: Pedersen proof 'R' component,
proof_ok: Pedersen proof 'O_k' component,
proof_s: Pedersen proof 's' component,
proof_sb: Pedersen proof 's_b' component,
ring_pks: Ring public keys,
ring_pks_com: Ring public keys commitment,
ring_proof: Ring proof
```

### bandersnatch_sha-512_ell2_ring - vector-1

```
c9922b7a9849b9928e15c655dd2f22ceef737cc355024f43d4b04bf4398c270d,
5a538209ff1fc7b1c9c8e1da05b3e169acf10a8b1591b3af029fe4eede0bbc71,
-,
-,
da53140f00880b48b521e30eeae932b00af63e89ef3f6b6de6429ca116df3e92,
7d73e10faa2d14c62c5178f189684bf37e522933658cd54d793ec59e513b4ce1,
b525d2bbdd50f584b7bec9053144c7b3d6e07c3b471b23ce11c2915902bc63ea,
13019b834e09fbd3d8f7c2f7e4df0331da830f816fe7d744e665b877e5093b03,
348028451cd329b3625545a53a466db9643e18db7371c930ba78810a1243159d,
a44cb42b162d0df19e45523f43e51035205548aa2270972b1fe59076b3897d4d,
8cb651e59811db93b0241bc947583521d9cd5ee29cddbf172ede62700635ef5f,
5fc11c37f5950147861b19ec63e6968c3fcbd19edf81cf768f07d2ca74ffe90d,
c516b53aeb9438808b10e510ef7318cfd26f584774927fcb9c709251794bf30a,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..5a538209ff1fc7b1c9c8e1da05b3e169acf10a8b1591b3af029fe4eede0bbc71
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
a2cf167201899b2dafb2dde95917147f5b1bf6d41492c3de76e33a2d0553adb2
..bd94e7812fd52a1944fac7f6b32ba862b1612a907fea992c721fe9a18065e65d
..88935c22311ce4e8feb76953ef05b5331926b1ce01e824d69647e311326e8b5e
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
a761bf1875cae0c3701b57c9113285873652031520ee145db12f464f5576f129
..6faa5b94a2a41f6452107d129c1692739107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..b72fd6bd7b44fcbec546a0434ad45257825832d67f33045267d01bbf522ecae2
..9374298b90adcc036cb69c1ccb0441c6b11137ad80f38f07ed9254940fa9da5a
..b875b3276420929b1f74b65b713bc084b2c9b7bd2d0d8829aa3445494032a0c3
..2c485f1a214eb78bb13567537e91aa0932495975a8ee639386db6005914d7942
..a335209b992e8abb886c7943d19837ef72c42486044d6e07647c353b0a235653
..a9e9acbed81aca7f48d62aadd72e3de1b187b53e32f4dfa4901187b23e78411d
..08965b08a6b283e6bafbfe138f1d0a1539f2810b41fa48365145119c98766822
..1330a6a812d9f5111ba6f7eadd32bff15889606b902f9fe7ccfc1599467a6938
..4de7ae182750ec7584dc291380222c33fbe47fc35266f726f20bfcde70a98d15
..a0858fbc075829a872c2b06b2e562fe5ea1d288dc968e443d081ac6018790056
..94767105375cd7af64024efeffee1deaf0dc417211ff532e0a0851e92644d46f
..ce4917c659f57cb661b22d1d08f6e187716227f8c0d49dc8bbe3d3d524b2636c
..c538c9a3bdae7ce6bb48c6270a5280568c157b1366dc08a8ed93d56d79af4af9
..8846b34bf5fac8cda7018bdd7e5f1f51d63bdcfc7203c03e6d6c85864c982192
..a07b50d4b6160fe992e5e4fd32d707d104cc952186775618dac2f08d3d1a8f16
..aa36502c02bbb610c0c3da0e90c8ca2f,
```

### bandersnatch_sha-512_ell2_ring - vector-2

```
0b4259ca1b10c9ed462532639113e1caf26b3a1a2d9e91ecef2fc5c2d23aed0a,
ff341f0c9da793b2d8fef91bcbfd5b55c2185352e4289edc1dd6c64e3fe09b0d,
0a,
-,
a983ad5fa909ee27bee75a51961b64b5f73ba50200cf7556f6585a716db52567,
e0b97c7186421f417d0bee66b4c6e0b221a89d1d6c8ee2997d6641b368601e8e,
ded743c72cb4803ee03f09f9bf1fcd3817aab9ef82a4d07df69e141a8f4928c4,
0c0b4a2f50c5286cefe8445ca51fc60bca9eee92a43416132b9ef9f3a0925c0d,
454643f57f8e9e54337c878cd1ecd24d26e603d915ec98341d5b8b4d2063812c,
d4db568710ce5b75b337550fe85a3edd49b37287e029e368e99bd36a3b610126,
1753b67eceb4f8157a684584895e480942bdf28914505d434fdc8c35d0391f3c,
5e0eb5a8caa204970baa0838fd22606acb61526a3d174465cecc46f7f101ab15,
e2230207a3f24a1e6043892aff9d90b9a68cda52db1dedb95e217936d968bc17,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..ff341f0c9da793b2d8fef91bcbfd5b55c2185352e4289edc1dd6c64e3fe09b0d
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
879b36924a292920ba827c52166fec9d6b038832efd05106f6a2f7b011940eb8
..e0dea6986c3128bac221b9360175269fad61d57d09ebfcd621d0cd84abba712d
..d560cc1bb62904605336a550d46856f87d985e02f34c872a57c7401cfd5b2515
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
b5c74602c531f3c767df078024d882ead80568b14b8306e8aca5e98e7231468a
..179236fa55662f7629123f33aa40fff79107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..aaee0230b20310982ce9606c6f3f27f5be0b1b9f17947480beb0684df9e507a3
..dde900fe916d4f1b9665e65ba348f9f5b4fe4b97bcb8c9e41d425a37ebe25a91
..30e3a264ab951d75111f74dc8fedb3440994d737204f9c2e8dcd04d84d5258d6
..bf50ccddeb771823b726e41f13d9e753116971e2c4633552557ac200cfeeb36a
..6f347216a8399f4e3b8f759689499ee04127f1ee0553d0626a390be5bbacaf16
..062a73005c64a13641c3e8cdac6ed405e7faa64c01788b70c5e905485a822452
..b8142e8ff78dc3bc2070e249f5ee6ae8940e9a2fd9d3df4856c327ab068f5d24
..362e86863dde1a6b3e466e97ee47165326d9933bee45159b48f46dfa85103259
..c3837518c2e2b7a737df78c964ecda9b2a20a37b40da32b5a79e08f654eeb60f
..ea5ead837a8cc7f504abeb17ebef6839848e5696e955a83c11d425effbb92d38
..8350ab8c3a739e39d3132a07091445c8d1a5961a5ff0bd438161c1462f5db4ed
..c218c1f6ce68baba679f4250e15cbf91a9055b0fc7a46bf43010e3f2ae757620
..8e2cf63f6616f67cbb3884c8da597630970795ed08d6aaed58880857b0a60746
..80b157fdc2116ace7ad4cf54aeb6800b47bce98e570f6155a2fc7c58cfcdf47c
..acbf6261f9bf454143c5bacece8ec1d39af23aca116bfd6b199dc69e6384bd3b
..3d17fd6be5291ee4f2613446ebcf50b9,
```

### bandersnatch_sha-512_ell2_ring - vector-3

```
dd60163595ff312a49aa5849917ba19020038ccd42f8a1d468da0973079bdb15,
fbba8feb488e767b9864726fffdc8595896757430eba9162a1a5d9a03381d5a4,
-,
0b8c,
da53140f00880b48b521e30eeae932b00af63e89ef3f6b6de6429ca116df3e92,
3c1ddf34f1d281a420d94c01b72af4dfc8dd4e8441e21f1b6fa158bb6b2a4772,
695fbcdc0d960798a7202d2c08cbed5d4d6a6209355432d639a38a8dba1f64d2,
ab326869bc1af08ea3026e96aa328cf86a6c3d42cfb8ea7bd32494b029ad9509,
fbaee4032036cc1e014e7e0a6d058602fa01fe01bd15244ef85c871b967b1967,
addde9505c29ec565783a4893562dac1272820aefd45c97b5c680a484841a994,
ebb55d70641daaf7c95ffaef7d94436e592785ba8dd091e64c0807fd9a2af43f,
a057106f4932a34546943ee2911290ff8d10731366d933d25f71b9e04f0af800,
95960b71a7adbf23f75fbfb16915f4fdf972f698fc712da447ef7a5d8601e603,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..fbba8feb488e767b9864726fffdc8595896757430eba9162a1a5d9a03381d5a4
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
b4add29b37e55b68171fe3beae59d2d0bcf83a963d13701cf2196279452221c8
..75c3da612be79bd86b8af2678fa204839171c059b30420c0451725fcc9b2c027
..f6bc457085c9e7f4b5c0394d30cdf9b5d688425eeff0a5715cb8fd63e63ece1c
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
a7f8b5bb09fce02b187fcdd021f85febf6820904f243945c93426dc87bab8c16
..013a75d64e6034511d8538210f02b90c9107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..97cbb73227a20299e1ce000528275f39c70e6720c1dc9d2f8c9ab9d4ebde2c98
..39bf8a37c9bae78c5d31f10d3bf69c42a0f6a1c1251f226f22f1b9391af1c6c5
..5444c46098722c146a9c3d7030e770fe2bfc0f66ddff80df7e7ca1288a4c2954
..4aac14fcdd5facb053acf3733626eb8294e5b33fee880dc2eb4e5b316c6ca54e
..f1584bac88c871ec86f97249f82a8f987138b8a57a5b18e16901552d39ca640a
..7f6fbf60af8dc29f1bd463d82aacacffc0c6cd84cbe82a3adb1018ca76be7b66
..91934760318cd86fd513a92ec90d439a91bd2bc8a129f12364dc8735b9f0f70b
..8c3462678388f4ab807ab62fd81f5cb6a360946adbb15e9008b35b90c97ef22c
..091856c161af7d9f0ff096f55e5ecf187bce55897f3089f7655514d4dd0e464d
..8237e2a1489bd0e28c25711b4f670e7c2ecef602859a802ad1ff0a21e690bd6c
..ac8a34932ccff89ace7325b15a1740e977c3794e0d4566449a0de90882f80de7
..4ddb23711b3c05fd11668a562aa56928c3c7063665b301273a1610b7848b6631
..cb3b151ea8e90e6887de083d9db38f16987d83d4062f5eb6d4490046dd175399
..882de50e37bebf66eaf2a9b9fe341665beadcd24d38fca3c53982f524808c1f3
..965d089653369ca77ce3f72f91f6dda4bde5932e291afd63533fec975d654113
..e0fd5cf9735087f2cb7e850cd9fc29c8,
```

### bandersnatch_sha-512_ell2_ring - vector-4

```
dfc32f03fe9487f123f2afeeb9487cb6b1eb23efac24a60ae540f5aa632ddd18,
f8487052801a89161424ee745189b5f7fe568819b9f13f44a8b3d173b57e928a,
73616d706c65,
-,
cd62c478f6751112afb7f29b0e046e5827927fe5e5e3b51c0977ff95aa20c859,
2ad7e3bdf71a946a75c7bb7b5bb639efc2f92feae4a79be2d01a05b4a5b268e3,
fd43c8d27c24f99392a0ac5e82050eacfbfdad9d6f4c835b21eea27fef083ec0,
2f105bee93949fd8929078b849e07538f49325723946d6b350aa48a1d197f119,
9eb92236e9db8b3dcc1a68fcaef4b0d27058328aaa8ce444581a83681a4b91d1,
67b07cecffaaf5b0823a80ad57c1907b347cb92aaa53a1147a3268dc4cdd88f3,
db2d7ae1efa97aa634aab19dace2cf17d422833d3945d057a818cc364cb779c8,
bff315fdeec7cb195134fa6ad915023cbaaaf088a6dc92fdfd206764c853c311,
61bfbd83933666bcd1b7a35a24e92cde7cc33f81bcf10fa4f5412a13a0ec9815,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..f8487052801a89161424ee745189b5f7fe568819b9f13f44a8b3d173b57e928a
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
ab619d810d4b14cb48b200e93318250de071b6a81d55aec17337662f85564603
..6100189ad648c94ef38125cdeb6b6228a3a36cfec3abc648ae046a08f7646451
..9fe2e3e662904c164b40be802c10af4be7064532b2724069f7e268d30ca88d16
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
a84beb829918d4b5834fd2ccfd2cddc0ef237ce16dcd4a23b060f3b4bd1dc0b2
..7acf40dc8b8cebb6cb80bea21c68cf559107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..a263d340b501bbb28fc1ef61884b0fc9dd646f6ff75b8537c7fbb2535c1ffdd0
..4efa45c651acfb00d54419038ead1159ab2d3858e242351bde697875c96a1936
..0dff0b09e9062e590ce13c7bc0e2ab39cfa4b6aded01924ecaa06ae3134ae560
..107eaa66b226c59567d7656f994e68989a9f8319bc9b72f142a2540e6cd37757
..9124abfda43f90c7241e7b44f06dd59630ceba55a60dfe60bdeb0ce376d7d714
..29e0d8b83e0387cc1f0c5b418ef03dab1abe4d65c24cba101d06511d9c078f06
..5d189995e64dcdb8fdcadd6ef6fd76dd96e37cd49473b4d3e3936f83b4fa8a0d
..2c1730cd474af6c8ece31ff92ab889d0545bc36264e941d4bb926756dc267842
..879983f5e541276d8059c86a4a153616b0fee2cfcc285844c0c87c3764f64150
..9a6299212a6b987c7239a9a29759701ef4e1cceffee8b83e01c6e4cb05b25c3b
..89131db1d0691340c45989d7d4b3126e95dc4fdb1a970d188768d582d6475714
..86471491b8539562ed63d037951f5d8830834bedf8ac529ba89b4c7d75be0924
..05b7b997674f6fbb8253bcc870603817a3f5ff51f90bbdf23696b7b49f48c286
..37b08545924663d06612020fef45a1c016f4e862c53954f6966b85f573885b75
..aab534f146a8d83d9fd13ebac581b1f3d464ac2fbcdc8e1b9a03fcedea57f92c
..28df7656255eb9d66e38a10f3f3212bf,
```

### bandersnatch_sha-512_ell2_ring - vector-5

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
-,
5101703a33a054dde44c22bd34bf8a09d5e6b4308ee0b9f74fb5157c8510a11a,
7a506355bf7ccd218c7e98f8065b0cc2e408a99c0decffcc46f76f4bf8f17b64,
431afac5eaf0ca01e941ddb9286e3a75b9a7cd394173ca04b19aa1e55daaf50e,
7b38b65acda35146522cafb3ff7f54548cf80d94d4bcb79107df58aa6b2b9c1c,
e217005a15d6814b0f66f7f950de451dfa7b94bb3c7f31342db351ed597387bb,
83e70bf1e0987445942481f3c500a056ddb5d050ab4888df2f01092db9705b2b,
aab254a61dbfec10b8b0de3d32d7abe955a96742a80be476c95ad22daae86b03,
2a698873fc078f442de9ec9a4ace0f52f2b136c8a16a12d7ff49476ea9fe6c10,
ba1a9d06fa98ef8ed3708586f3d4e946d8a1d1f7e14e08f67fc17ccef248fb14,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
8e0c9bd66876cfa5ea896d9382068479a62f5aacf05c7349eb36aeec2397e397
..0e1f26dc699689cd12785a9cf62c9efab7bf5185ebb42ae5a1c9963a5344abbc
..c6818e15fa4d163a93cd7bcaa8097e7f99d9ee772878535c8bfb0c8f5b767c7c
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
a22caa66691b6409eccd50b5ef93cf1ae3fe8d6075a90087a9038061c7cf479f
..82f193c3b34b7662685711d38915de4b9107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..9186f492adb4210d08693e98588015becf59f149c8fca8e7dfb86b4c74e96c5e
..a55207fd02fc867dcd5a556e4965e064a97a0df012129f6960833fc295ac1572
..1ec0d4e56dbb54d7c57975188b8b617e3b5afb44c3bc58778e5d727f86d44cac
..cf7a5398ac4762c77943c8cc05e41d55443177b0f3e1d62530675849fd599517
..d900af94bf8030d44d6637b531c63ee7a8fe0397730b0cfd462f9823725c7845
..91dd22ffdaa62e332830a23504218958c300dfe580c41b08e9111f98e4c6ad5d
..44806139729080f318e8f37cc496ee7a8ea893b65932b077ad69b08e03e7365c
..47d379f27df63bfe5e5133957d6b6c122909e44dde92a33b3d9a15a0a81c2309
..44de73b01fbb8b2e821d5d800b16c5c1074201d4e5d2d44b5544d927f807ce6e
..997c4f1af8add7cf22fc5db897a869d9201d4856579634c31081cbb10919b253
..8de65f32a75532f08c9034322e6492fc3536ff781402f2b6680408ac1e3a718e
..1f8976c0b08c7b69817a5d0ce2109819614e120d885c6f847360b42b2a2524e7
..3c38af8c271088193d10210d9c5f766eb62e9bd61bc0e5a54df521608c3b20d8
..e5037609ff022d82bf88d60d882467cd17426e9d3ad946fb883846e1e7940cf5
..b879293c99d655a5575124c116afa2b3b423e70347cc5df61888358f729a1f24
..124ccf3beb71b66345e3aba21c2a9ead,
```

### bandersnatch_sha-512_ell2_ring - vector-6

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
1f42,
5101703a33a054dde44c22bd34bf8a09d5e6b4308ee0b9f74fb5157c8510a11a,
7a506355bf7ccd218c7e98f8065b0cc2e408a99c0decffcc46f76f4bf8f17b64,
431afac5eaf0ca01e941ddb9286e3a75b9a7cd394173ca04b19aa1e55daaf50e,
7b3dfd9e3e20f433831f7f77834435773773d7aef0003e4a20dbe65452b3ae14,
bc81076816153284d03136bd7c27223d7923162bf447dc4c1e36e25e4ff9584d,
98055b81caa91003fbd4c5d47da1a31693836d0ebcbb8c4c93c8e4198a69ef5e,
e02c45337dd0c6a7f7453ef437716eeee8658a13116697177f311cf2e0e0c957,
768031ec19ddd62cf5c1f9621ca817a93979dd31a4cd1d42c065554dfbfe9419,
96361eb858f2f3b370f939414495581d7e03130644abd7547a04d5fd50381518,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
8e0c9bd66876cfa5ea896d9382068479a62f5aacf05c7349eb36aeec2397e397
..0e1f26dc699689cd12785a9cf62c9efab7bf5185ebb42ae5a1c9963a5344abbc
..c6818e15fa4d163a93cd7bcaa8097e7f99d9ee772878535c8bfb0c8f5b767c7c
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
a4e79f34a702b473d75ce60fc1e8b658c8b7852c2af59096bd064d5b7ed8390e
..c3966aea1f767c8a92532795e1182d279107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..a121217c3a1193ad80f622ef007d7be483ffc09305d91419a1c61ac7ed155186
..4eacf9f7e88abff1789cc62e9327aab78c50ed28026d6072d9559b49cf231d3f
..8ed1d97ddf4d88a5f2696fbbc53a529230aa0505ebc2da050e6310683312f545
..1cede24645b92eff210535c349825488802408dba6e492a6c8ff5b8bc2254353
..80f10936ed679fb7a8dd1f1c8a2eca2aa491c3f67de8d1ab4f1447db3378a030
..3947fac5176702311f2a53d4666c208f305099587ed72fe18172960cb9752526
..30b70835b2f5c8766ba11e23445ae588eb5cb708c9052b5fcfd8148e8102c64d
..b09b0df2105872afd721282816cb4e7ca1b7cbdcce48a9af9ddf0d1ac82e855e
..5ccc308a622328a53bf01a310cfd72137cfb38f094ac2e429823f21741e25d6a
..7474021029105c98823798113434a0392bf6fe11b1550ad1d406b8086709aa02
..8a083a675e4d73088fbd89f5b52e982ea92a44a70f8e3bc9b09d7f8537945d33
..8bfa579190c6c63731c171afa906070e29d24f9ada3121e332e28aad46445652
..cc9e62007794293b807e22ee474e003796afc630d8aeca6290dbcb97ebafc236
..f3f2ff573e5314d51e23a379a924b70e0eb52d4cb7ff010427ba59f3ec2750dd
..b52d7457653e5454898ad4a4c77dbae30dda2df7349992e2153f6fda4f94d4d9
..0f4e5cf12777bbe4b73548ffab5af1f3,
```

### bandersnatch_sha-512_ell2_ring - vector-7

```
9504efbeadf81b20a9cb64c1331915eb3718a574227458230d1d80dfa94e8b13,
704fd3784947de4db4fdcf0b477530d094bf5a656707b7d6cb43edbc4db7336b,
42616e646572736e6174636820766563746f72,
1f42,
5101703a33a054dde44c22bd34bf8a09d5e6b4308ee0b9f74fb5157c8510a11a,
7cbd62788fe8bbcc769314af10959eaeaa1f190c6bb5ce8ba7814e55631f9451,
467c08c60416cf1b7846ee311e4898e188683bd91e9606c39ccf20ddd43208bc,
ac7a84c0ae8462f1f375f2eff85c54506aa3fa5ca7b653d0a98d585f8c394e00,
22481b1e7dda724a032487f2b3ec389a238ee36c6421841b72c3f675c6f5a85e,
e4d55ac4816301e1b8406587060d0238a8138e920e208b022ce04735d11e5c8a,
5ef27127b2ea6e78009ec97d937e30c51963755ff2de32fb246a8664873e3285,
f652c9d56962f8e3e559db55315fcd66449d714cc282b3486f4a55fe4786d109,
b0365e43ff857130943e227ee5770a6744bf2ca1418dcc933863e89be8f19211,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..704fd3784947de4db4fdcf0b477530d094bf5a656707b7d6cb43edbc4db7336b
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
b32e2c1abe5c201e8719daa182139f9bb3524fa9be5ac52e07b4dc7efb486893
..b16222a4edd71fcb82b6d3a6ccc62e9c8f4e0d94ed0cb3f2d5110eeaca40c122
..4cf6923daa22e928d94d7f592ac364230932698fa9771a4b44336ab604e70807
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
95fcc25ecae8eb6d16b827881d2221abf551bef0c9d6d96b52ae19a76c439fd7
..b2f22fd108575382c9376d82937c9f6e9107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..98f6ac41142712454ddbf9efbc0af9c5ad670eaba6fcdf880c4bb7a6f220b62a
..d05c8f98762efe775087b504ad707ecc83cdd70f5c92d7315ba24ddbdba20ea3
..b7a8c846dda282032c7f3aa286e452fd1caba9f5669e2186b24e22d2c5d9e037
..e6018c425592d2dc01c5d9a45dfd4dfa337957ace07e8212c509c355d868286c
..af6b75c909e590fa00fda5d8afea21cf1514fd4efd6f1572acc9fbc6c5b8de45
..a308800d116ec60180625be0727ff38bc023ae8b4795e22fa34e1292d6140212
..f892aa67b1e8b59eacca71ee9b3c9d719f974271ef8ed76a814b4385c195d458
..bc39ecd7f73c4fdb21845378f675163fddbdcb0e172a4b8667bb215949e21b22
..d57ed356d399bc5ac31e5f280f4a5506c30970048939afee0a03261e689aa31e
..bf0c9ccd345e5a942c1b026023e65e0e4490843f575ece0aaefabc0cc3005b65
..b50ab33ae42847d27ee3cd5af636a8c1abda45b1266e06c54c46a37413b1cef5
..f29d1b9b5a1f8aae11f37694504a57b67b005becdb8c6339f4e025fa6b36c237
..ae3e2f02bda24fe281b12ff8c8f63c4992fb9acff1d67ef3ea2d2356490c697c
..3e9a1cd63d29bec05c7ffbc27489c85b8b86ecf9636cb3220c2d94c291b6e0b5
..b67dae81a2af61564cad7b05f1322000ec6043e144a82fdffb15726db11c7975
..855a030bc04938f39acc0445c154b813,
```

# References

[RFC-9380]: <https://datatracker.ietf.org/doc/rfc9380>
[RFC-9381]: <https://datatracker.ietf.org/doc/rfc9381>
[RFC-6234]: <https://datatracker.ietf.org/doc/rfc6234>
[BCHSV23]: <https://eprint.iacr.org/2023/002>
[MSZ21]: <https://eprint.iacr.org/2021/1152>
[CSSV22]: <https://eprint.iacr.org/2022/1205>
[VG24]: <https://github.com/davxy/ring-proof-spec>
