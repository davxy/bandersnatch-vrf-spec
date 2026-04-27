---
title: Bandersnatch VRF-AD Specification
author:
  - Davide Galassi
  - Seyed Hosseini
date: 27 Apr 2026 - Draft 34
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
The length of $ad$ MUST NOT exceed $2^{32} - 1$ bytes, as the length is encoded
via $\texttt{enc\_32}$ in the VRF transcript (section 1.6.5).

## 1.4. Constants

- `suite_id` = `"Bandersnatch-SHA512-ELL2"` — the 24-byte ASCII string identifying the
  cipher suite. It bundles several tightly-coupled choices: curve (Bandersnatch in
  Twisted Edwards form), transcript construction (HashTranscript over SHA-512),
  nonce algorithm (RFC-8032 inspired), challenge derivation (transcript squeeze),
  point encoding (compressed little-endian), hash-to-curve (Elligator 2 random
  oracle), and security level (128-bit). Change the string when any of these
  changes.

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
- $\texttt{enc\_32}(n \in \mathbb{N}_{2^{32}})$: Encode integer $n$ as a 4-byte little-endian octet string.

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
3. $T.\texttt{absorb}(\texttt{enc\_32}(n))$
4. For each $(I_i, O_i)$ in $\overline{io}$:
   $T.\texttt{absorb}(\texttt{enc\_point}(I_i) \;\Vert\; \texttt{enc\_point}(O_i))$
5. $T.\texttt{absorb}(\texttt{enc\_32}(\texttt{len}(ad)) \;\Vert\; ad)$
6. $(I_m, O_m) \gets \texttt{delinearize}(\overline{io}, T.\texttt{fork}())$
7. Return $(T, (I_m, O_m))$

**Transcript**:

$\begin{aligned}
T = &\; \texttt{suite\_id} \;\Vert\; scheme \\
  &\; \Vert\; \texttt{enc\_32}(n) \;\Vert\; \texttt{enc\_point}(I_0) \;\Vert\; \texttt{enc\_point}(O_0) \;\Vert\; \cdots \;\Vert\; \texttt{enc\_point}(I_{n-1}) \;\Vert\; \texttt{enc\_point}(O_{n-1}) \\
  &\; \Vert\; \texttt{enc\_32}(\texttt{len}(ad)) \;\Vert\; ad
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

1. Validate $Y$, $R$, and all $I_i, O_i$ $\in \G \setminus \{\mathcal{O}\}$, output $\bot$ if any is invalid or the identity.
2. $(T, (I_m, O_m)) \gets \texttt{vrf\_transcript}(\texttt{ThinVrf}, [(G, Y)] \;\Vert\; \overline{io}, ad)$
3. $c \gets \texttt{challenge}([R], T)$
4. $\theta \gets \top \text{ if } s \cdot I_m = R + c \cdot O_m \text{ else } \bot$

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
   a. Validate $Y_j$, $R_j$, and all $I_{j,i}, O_{j,i}$ $\in \G \setminus \{\mathcal{O}\}$, output $\bot$ if any is invalid or the identity.
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
x &= 2035996659106347027231843009894751612317716910942125238709394115821582620399 \\
y &= 45658295857182261137200330826382983531055622672653801121971633713275795694044
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

1. Validate $\bar{Y}$, $R$, $O_k$, and all $I_i, O_i$ $\in \G \setminus \{\mathcal{O}\}$, output $\bot$ if any is invalid or the identity.
2. $(T, (I_m, O_m)) \gets \texttt{vrf\_transcript}(\texttt{PedersenVrf}, \overline{io}, ad)$
3. $T.\texttt{absorb}(\texttt{enc\_point}(\bar{Y}))$
4. $c \gets \texttt{challenge}([R, O_k], T)$
5. $\theta_0 \gets \top \text{ if } O_k + c \cdot O_m = s \cdot I_m \text{ else } \bot$
6. $\theta_1 \gets \top \text{ if } R + c \cdot \bar{Y} = s \cdot G + s_b \cdot B \text{ else } \bot$
7. $\theta = \theta_0 \land \theta_1$

Note: no public key appears in the verify inputs -- verification uses the
committed key $\bar{Y}$ from the proof.

## 4.3. Unblinding

To link a Pedersen VRF proof to a specific public key, the prover reveals
the blinding factor $b$ and the verifier checks:

$$\bar{Y} = Y + b \cdot B$$

where $Y \in \G \setminus \{\mathcal{O}\}$ is the claimed public key. The
verifier MUST validate $Y$ before accepting the association.

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
   a. Validate $\bar{Y}_j$, $R_j$, $O_{k,j}$, and all $I_{j,i}, O_{j,i}$ $\in \G \setminus \{\mathcal{O}\}$, output $\bot$ if any is invalid or the identity.
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
x &= 16694082298476211322146772242502885282285019951942003725400283854213354132169 \\
y &= 3984482500670880510122500361427819834225058783213717391641528393088138818906
\end{aligned}$$

A point with unknown discrete logarithm derived using the `hash_to_curve` function
as described in Appendix A.2 with input the string: `"ring-accumulator"`.

- Padding point $\square \in \G$ is defined as:
$$\footnotesize\begin{aligned}
x &= 4402102242935417179871831084241429782095672201912973408557750418598048316572 \\
y &= 10958542895453316083794025818390929159397855597085770403103690185444830671348
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
bytes, $\texttt{enc\_scalar}$: 32 bytes, $\texttt{enc\_32}$: 4 bytes, domain
tags: 1 byte) or explicit length prefixing ($ad$ via
$\texttt{enc\_32}(\texttt{len}(ad)) \;\Vert\; ad$), so the byte stream is
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

This is the random oracle (`_RO_`) construction: the input is hashed to two
independent field elements, each is mapped to a curve point via Elligator 2,
and the results are added.

$$I \gets \texttt{hash\_to\_curve\_ell2}(DST, i)$$

The domain separation tag is:

$$DST = \texttt{suite\_id} \;\Vert\; \texttt{HashToCurve}$$

i.e. the 24-byte $\texttt{suite\_id}$ string concatenated with the single
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
  check $O_k + c \cdot O_m = s \cdot I_m$ is vacuously satisfied
  ($\mathcal{O} = \mathcal{O}$), but the commitment check
  $R + c \cdot \bar{Y} = s \cdot G + s_b \cdot B$ still proves knowledge
  of the Pedersen commitment opening $(x, b)$.

# Appendix C. Test Vectors

The test vectors in this section were generated using `ark-vrf` libraries
revision `f3ba9dd`.

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
469f3c9f791dd38a44bf44a4393398664c065fa742c46618115f6881445b6c02,
b5efd1caf6873c10bd351992a72182718417063fc67f30cdbafe335a6c5efaeb,
-,
-,
507b8f930c8559d29b409054f5aacc435b3756c37ee6f38ba55678961a63013f,
bcc83458ca7f51de0cd2fe921df735d82affba6f5dd269e3d3a90f455e3cf293,
975a5998db2b2701027c00986ac7c5d50e13616dd4f2468bbb2993884cda9f6a,
2fb0931872cce701a92fb83d34cf3a1b,
db8a1609d23a04f069a4c9e37a8b88f626126583c2ef1de2a3f351d891592f15,
```

### bandersnatch_sha-512_ell2_tiny - vector-2

```
6b750d2754ebaf3163bd2b9a1ffb0137de1096c53467a75ee0625c133a4b101b,
d6351fb4f9dcb616f34b2b48a94acabf8faf769018f20457d56156076501a9b5,
0a,
-,
bf5904142f7fff1a333ec352f02e07d368bb437f77a1159fae0480b9bc444dbf,
e0e64cc4b110dd4d8a6d1c2c6d900f1b36c19bd5c6a847849650d8837a6c2af3,
7e04da6e16cc9a19888d9a9861c14d20959e183177086645e9716066c51259c7,
f5c7d0a468fd4b0bf263a59d1504fc7c,
35baf5eaa7763ec01cbf68111bc3954a4c171e75934debdfb442f55da0c1fe04,
```

### bandersnatch_sha-512_ell2_tiny - vector-3

```
d65e63da3835b1cbd4a56743b33465b991893271be22970f213899fddfdf451c,
b27d1ca12ede738d0909705d2dc69d7aca8b7fb3f451db3721cb92baf7f75bad,
-,
0b8c,
507b8f930c8559d29b409054f5aacc435b3756c37ee6f38ba55678961a63013f,
014e64809463cfef1e2fce8eddc3af72402a5d20981549fd14f75d3a961efec9,
8789e98c6b52051328e1f7513f735e623e7d46463e11b9650bb8f2097a84280f,
80a69351c31f5f661043a1753a83c2e5,
a69e799abc5317d509637971164b83b50d353006810ff6e2bedb1dcded792302,
```

### bandersnatch_sha-512_ell2_tiny - vector-4

```
23af4703982081016292d2873cd291eaed09bae027a0ffa027b8d906dba50916,
ccd66b701aa97824a42bbb748dabd371f3eb0ce29352a749073afd4f39369cea,
73616d706c65,
-,
e6952ff094431bdf3292564f316b472e567a47161feb20e48adcd9e4943a912a,
20ae74617586e0e357706b6c1e2775b4efb8c2a6766b5d10bc69b824b53e2039,
13ddeab303bdaa180338ff7f2821b48142a0b4d0a29b26e9fc8b847c38712be4,
012e34921430062fa11721655cf5df20,
b831d6c5c5f347066aece5425f8711256c2b9612d30159980b777bea36b8c51b,
```

### bandersnatch_sha-512_ell2_tiny - vector-5

```
d3474b24545500bf46e4cab5eaaf7b3778d92fea7d60339d2c04f14787b54216,
6d972e05ba078b9b1452c7f407a11499d78c951bbc75f29dc39da267f038fee3,
42616e646572736e6174636820766563746f72,
-,
73068394e07bca18a291338b07bca6db4375dd003fb6202eb70765dae1cccd48,
f7245e2d4f92bfcb731ffc065aa940659bf28d7ad857650f21e3b8312f75d602,
52444c24a837fd222430b317078d5e1ab52c12944089f523c34907c752f4f81a,
453340e4fd3a190a12a0276fc88d80bc,
42fb97207d1893ff7b3606c69b45ea1f4ed73430c4faff496eff79a903db0704,
```

### bandersnatch_sha-512_ell2_tiny - vector-6

```
d3474b24545500bf46e4cab5eaaf7b3778d92fea7d60339d2c04f14787b54216,
6d972e05ba078b9b1452c7f407a11499d78c951bbc75f29dc39da267f038fee3,
42616e646572736e6174636820766563746f72,
1f42,
73068394e07bca18a291338b07bca6db4375dd003fb6202eb70765dae1cccd48,
f7245e2d4f92bfcb731ffc065aa940659bf28d7ad857650f21e3b8312f75d602,
52444c24a837fd222430b317078d5e1ab52c12944089f523c34907c752f4f81a,
31c198ae4a808d320855aece9d7fa357,
bd6a404040a7fccdd3f6524a31120e79d12a6d60898c6270dde08b99df435109,
```

### bandersnatch_sha-512_ell2_tiny - vector-7

```
d3ca62c2eff12acf77b6745a0a4ef633bbd87d44c163dea26bfd57ad6ddce80b,
a05f85d1afd54269db4e51d4a0aa7dada0ba0b20d00e21dbcafc96afcc87bd34,
42616e646572736e6174636820766563746f72,
1f42,
73068394e07bca18a291338b07bca6db4375dd003fb6202eb70765dae1cccd48,
38eefb096193eb94d8ffe21340e123c69205c213afc18b5df6c0ebfc9d94f45b,
a4df10b7839ec0f64d364e97f5b37e470595412d8c2c5adc30558e95f292e0bd,
2fa93e3e1af4a14542cca2d4d384bcaa,
e24e20dfaba3c93c4a22419eccf7b7bde422b6a82d048b0e3ffb816b188c690b,
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
469f3c9f791dd38a44bf44a4393398664c065fa742c46618115f6881445b6c02,
b5efd1caf6873c10bd351992a72182718417063fc67f30cdbafe335a6c5efaeb,
-,
-,
507b8f930c8559d29b409054f5aacc435b3756c37ee6f38ba55678961a63013f,
bcc83458ca7f51de0cd2fe921df735d82affba6f5dd269e3d3a90f455e3cf293,
975a5998db2b2701027c00986ac7c5d50e13616dd4f2468bbb2993884cda9f6a,
0bc378d2bb80aa89413bc2db01972b4d284ae3786f0084265d2a4062d38a4005,
9a6806395b36e8deff21469f68f217a8ba5cbedf714a0b8857ea4bd50ae8b405,
```

### bandersnatch_sha-512_ell2_thin - vector-2

```
6b750d2754ebaf3163bd2b9a1ffb0137de1096c53467a75ee0625c133a4b101b,
d6351fb4f9dcb616f34b2b48a94acabf8faf769018f20457d56156076501a9b5,
0a,
-,
bf5904142f7fff1a333ec352f02e07d368bb437f77a1159fae0480b9bc444dbf,
e0e64cc4b110dd4d8a6d1c2c6d900f1b36c19bd5c6a847849650d8837a6c2af3,
7e04da6e16cc9a19888d9a9861c14d20959e183177086645e9716066c51259c7,
1091f3fedd369ade45c43a485d4d01f48fc74105ebf31087086f28104ecd7707,
14a9dcb918337b9f23d9098665207a20bc60b7b588d1d1f729209fce6b247e19,
```

### bandersnatch_sha-512_ell2_thin - vector-3

```
d65e63da3835b1cbd4a56743b33465b991893271be22970f213899fddfdf451c,
b27d1ca12ede738d0909705d2dc69d7aca8b7fb3f451db3721cb92baf7f75bad,
-,
0b8c,
507b8f930c8559d29b409054f5aacc435b3756c37ee6f38ba55678961a63013f,
014e64809463cfef1e2fce8eddc3af72402a5d20981549fd14f75d3a961efec9,
8789e98c6b52051328e1f7513f735e623e7d46463e11b9650bb8f2097a84280f,
927050c68c70094aea7f99001c9ca07ecb285e470b7b863ff7cd6d109e1121e2,
14020058ed45594711a258687a88cda3cc9d404ea48e371c3b55d4213a28a901,
```

### bandersnatch_sha-512_ell2_thin - vector-4

```
23af4703982081016292d2873cd291eaed09bae027a0ffa027b8d906dba50916,
ccd66b701aa97824a42bbb748dabd371f3eb0ce29352a749073afd4f39369cea,
73616d706c65,
-,
e6952ff094431bdf3292564f316b472e567a47161feb20e48adcd9e4943a912a,
20ae74617586e0e357706b6c1e2775b4efb8c2a6766b5d10bc69b824b53e2039,
13ddeab303bdaa180338ff7f2821b48142a0b4d0a29b26e9fc8b847c38712be4,
02db2a64519641375a3dc02ceb129f8c249750059998076e2d92047b22f3e5cc,
636f002cd228b6d54f6150a6a66069cca7b34b5e7b05ee86f62aed6b8d24e015,
```

### bandersnatch_sha-512_ell2_thin - vector-5

```
d3474b24545500bf46e4cab5eaaf7b3778d92fea7d60339d2c04f14787b54216,
6d972e05ba078b9b1452c7f407a11499d78c951bbc75f29dc39da267f038fee3,
42616e646572736e6174636820766563746f72,
-,
73068394e07bca18a291338b07bca6db4375dd003fb6202eb70765dae1cccd48,
f7245e2d4f92bfcb731ffc065aa940659bf28d7ad857650f21e3b8312f75d602,
52444c24a837fd222430b317078d5e1ab52c12944089f523c34907c752f4f81a,
557ea5924b36b48ddffc92ad09710a38ec24560a3a9294292680b0ae54eaa1de,
dc9a2b79cae984da805fd3e1a2cd95af6d9911e811f9ca113972ce4243d7220d,
```

### bandersnatch_sha-512_ell2_thin - vector-6

```
d3474b24545500bf46e4cab5eaaf7b3778d92fea7d60339d2c04f14787b54216,
6d972e05ba078b9b1452c7f407a11499d78c951bbc75f29dc39da267f038fee3,
42616e646572736e6174636820766563746f72,
1f42,
73068394e07bca18a291338b07bca6db4375dd003fb6202eb70765dae1cccd48,
f7245e2d4f92bfcb731ffc065aa940659bf28d7ad857650f21e3b8312f75d602,
52444c24a837fd222430b317078d5e1ab52c12944089f523c34907c752f4f81a,
8328c6f6ddfb21e5788fb77ef2d8e3193d197725457bfb5a515fa6d91f9a8b9b,
917973b874805f3251c48484f5fdcf00196d9fc3109d25d0e76d5bf3e38c430f,
```

### bandersnatch_sha-512_ell2_thin - vector-7

```
d3ca62c2eff12acf77b6745a0a4ef633bbd87d44c163dea26bfd57ad6ddce80b,
a05f85d1afd54269db4e51d4a0aa7dada0ba0b20d00e21dbcafc96afcc87bd34,
42616e646572736e6174636820766563746f72,
1f42,
73068394e07bca18a291338b07bca6db4375dd003fb6202eb70765dae1cccd48,
38eefb096193eb94d8ffe21340e123c69205c213afc18b5df6c0ebfc9d94f45b,
a4df10b7839ec0f64d364e97f5b37e470595412d8c2c5adc30558e95f292e0bd,
c866019fe05e072048d4542ce22899d27c0b246f98c399cabe7b0962b455830d,
f54d085199ac31c9bcccc7b4684d9abb1a2cfffae3c0047d9a61e3dfd1fdd002,
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
469f3c9f791dd38a44bf44a4393398664c065fa742c46618115f6881445b6c02,
b5efd1caf6873c10bd351992a72182718417063fc67f30cdbafe335a6c5efaeb,
-,
-,
507b8f930c8559d29b409054f5aacc435b3756c37ee6f38ba55678961a63013f,
bcc83458ca7f51de0cd2fe921df735d82affba6f5dd269e3d3a90f455e3cf293,
975a5998db2b2701027c00986ac7c5d50e13616dd4f2468bbb2993884cda9f6a,
d2e3f0f4d88034304d37ea5eb11c9fed0293e6ba493d916f1aa83384c575870c,
7260bc3a9540575c2071391dc0ecf2e74a397b91b8508f9179f20d1c533c1731,
0be90ca84dd0a03908a2b471718c2fbf1aa36f773ff8b94dbafb99ec27deb7c7,
9b00b061ac051e546b8d07f1f4d959829e039b524641e0f084022042370ee31c,
5948127a272f3eaa27a0378e027407ca8c2b842997749bf56da3019fb1f5bc16,
e5f8b1f8e2139ab4d0d829c6f1e60ca737879cc70ea5ec675954ec5b2e79b709,
```

### bandersnatch_sha-512_ell2_pedersen - vector-2

```
6b750d2754ebaf3163bd2b9a1ffb0137de1096c53467a75ee0625c133a4b101b,
d6351fb4f9dcb616f34b2b48a94acabf8faf769018f20457d56156076501a9b5,
0a,
-,
bf5904142f7fff1a333ec352f02e07d368bb437f77a1159fae0480b9bc444dbf,
e0e64cc4b110dd4d8a6d1c2c6d900f1b36c19bd5c6a847849650d8837a6c2af3,
7e04da6e16cc9a19888d9a9861c14d20959e183177086645e9716066c51259c7,
371e8373751a4b0ed6b59a5f08a83cea22c2dfd925695315d2dc4824bd368408,
ef5058187cb6f117f3f091a8243b53b533123488ddc32fe5306d41f6bf7fc1d2,
f101d7a4e97b6aabebc338ba27d714ed6d46fc314d6cb7f8cb7ad1b59f8c28c4,
dc452942c6742830ed982e6096171bec3c00c8919e6d93c3977a3e2d7267ebc9,
ee65dbeaf545aca526f3968688862483840e1ea154c2f52d0d7db830c2de4015,
9996ba654ae210f7bb74026f7be4eb3fd5bec113c60c36fff2d30077e2b4c314,
```

### bandersnatch_sha-512_ell2_pedersen - vector-3

```
d65e63da3835b1cbd4a56743b33465b991893271be22970f213899fddfdf451c,
b27d1ca12ede738d0909705d2dc69d7aca8b7fb3f451db3721cb92baf7f75bad,
-,
0b8c,
507b8f930c8559d29b409054f5aacc435b3756c37ee6f38ba55678961a63013f,
014e64809463cfef1e2fce8eddc3af72402a5d20981549fd14f75d3a961efec9,
8789e98c6b52051328e1f7513f735e623e7d46463e11b9650bb8f2097a84280f,
47b44926c9a52aadd92c6394a251499eb22ad52df58bd057fc1eda1fc1121e01,
f052b4b7394bc58d6e3f35ac9fa7914db8dca08dab1d86f3a8af9b3a06a4a81a,
b337e3fce7b29347938f0daa81745bc439b19f567d918e45db7bf69974ecca51,
876e077d8cbaac4f78fbe3ab0aa058dbc83661f73a6a2028871ed74a9b2e68a1,
8ca70184988af3da4c31936c879f20a3bc50faf226e0c0d02d20fddda61ed51a,
7c58bab21c811c7fcc5466681fdf35aca9d416e5b4d7b1af1b2c754491b19a09,
```

### bandersnatch_sha-512_ell2_pedersen - vector-4

```
23af4703982081016292d2873cd291eaed09bae027a0ffa027b8d906dba50916,
ccd66b701aa97824a42bbb748dabd371f3eb0ce29352a749073afd4f39369cea,
73616d706c65,
-,
e6952ff094431bdf3292564f316b472e567a47161feb20e48adcd9e4943a912a,
20ae74617586e0e357706b6c1e2775b4efb8c2a6766b5d10bc69b824b53e2039,
13ddeab303bdaa180338ff7f2821b48142a0b4d0a29b26e9fc8b847c38712be4,
a90778fa94841666b5ed8e753326bbd56aaefaf39fc8272e34c56b1b2846ba0b,
3874f9dcb49f359e0b9b3db29b119828517c3857b33b1937a8b8e8209109041e,
9c356fad97b79e589763abbe9c67bdf5feaaa9e897a4914b49863d7aec562da2,
dfaf403db6c9e29bd40c69c461363bc3afbdc98bb2971001848bc02f8a0ef90e,
e77991fcd10c83921f08fdc7666daf6c7b082691d8f289e3dbe4b41e54b4a80c,
70991887fcf9abe4e3b169c899e598fcf8b2b0577be91598cbd2a15754c4241c,
```

### bandersnatch_sha-512_ell2_pedersen - vector-5

```
d3474b24545500bf46e4cab5eaaf7b3778d92fea7d60339d2c04f14787b54216,
6d972e05ba078b9b1452c7f407a11499d78c951bbc75f29dc39da267f038fee3,
42616e646572736e6174636820766563746f72,
-,
73068394e07bca18a291338b07bca6db4375dd003fb6202eb70765dae1cccd48,
f7245e2d4f92bfcb731ffc065aa940659bf28d7ad857650f21e3b8312f75d602,
52444c24a837fd222430b317078d5e1ab52c12944089f523c34907c752f4f81a,
0702700c7eac908e31f6a92e148dbdcd854777aed5de632ac12b42b364d2c613,
7d63c597baeb24f32d4fcdacd939bb2f3dc88aa43d39cf7c448729f43f70f207,
39f50b04ef04ff2619f42675b35acdbb4d2359527d972ba4a44000bdef189f85,
103691e064422bad1add6d32d0ee55a4b509e7cea4104abfda363dd0e72d6526,
beeec912cfcaeddaeecff1605af14a5ab1cab288cd0074b4d1da7189e1b12a0a,
da497db0b72ddc5f06d5f78d53eb538937716edd742385e1820d4ff75b9e740c,
```

### bandersnatch_sha-512_ell2_pedersen - vector-6

```
d3474b24545500bf46e4cab5eaaf7b3778d92fea7d60339d2c04f14787b54216,
6d972e05ba078b9b1452c7f407a11499d78c951bbc75f29dc39da267f038fee3,
42616e646572736e6174636820766563746f72,
1f42,
73068394e07bca18a291338b07bca6db4375dd003fb6202eb70765dae1cccd48,
f7245e2d4f92bfcb731ffc065aa940659bf28d7ad857650f21e3b8312f75d602,
52444c24a837fd222430b317078d5e1ab52c12944089f523c34907c752f4f81a,
1e7365c45df7cf8c794ae59a470dadd546166d31120dbfbbc055598072199b17,
913c4f02bd0e132896082c464107e4835b4d77ffd65a3ea7b9025a98886b0981,
9a52a1c931defee9f0b9d8a5ab3c945c1055d96e9c1c903a486c612a1756ae95,
509caf042ae3dc08b4431723367395952073aaf1b71a625b766790354066f834,
5305c3d3f33f0480b9c7be4da9b27b7145b2d7cc2a2b2f3a0478e8ad8103370d,
16948495dc63b3ae489b9206f93aebc47af37f25d18804b3685f05a4ef39d102,
```

### bandersnatch_sha-512_ell2_pedersen - vector-7

```
d3ca62c2eff12acf77b6745a0a4ef633bbd87d44c163dea26bfd57ad6ddce80b,
a05f85d1afd54269db4e51d4a0aa7dada0ba0b20d00e21dbcafc96afcc87bd34,
42616e646572736e6174636820766563746f72,
1f42,
73068394e07bca18a291338b07bca6db4375dd003fb6202eb70765dae1cccd48,
38eefb096193eb94d8ffe21340e123c69205c213afc18b5df6c0ebfc9d94f45b,
a4df10b7839ec0f64d364e97f5b37e470595412d8c2c5adc30558e95f292e0bd,
0b9b0728f497c925d7fc730656b8fce60d5df309cc48a9a98efcfeb54728d70e,
41cfcaa44aefc251f80de667765ccbb2342043b12ccea51e58dc21f0605ab01e,
1963d7687f050751bc85648887cb31d489d7136a21a37f8f14c25f0c5a91380f,
d1be8e787e651db9139ed6906e66ac7fd412e5c9766c8719b6dc806fd91bf31d,
3c088d386d0b374b0ec431e05c6232e6b8708b8e91c03e4d456778e5fb3b7617,
b77c408ad1cf1403f3c253230786af9ff6bd61622caf118406333c7fec04d411,
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
469f3c9f791dd38a44bf44a4393398664c065fa742c46618115f6881445b6c02,
b5efd1caf6873c10bd351992a72182718417063fc67f30cdbafe335a6c5efaeb,
-,
-,
507b8f930c8559d29b409054f5aacc435b3756c37ee6f38ba55678961a63013f,
bcc83458ca7f51de0cd2fe921df735d82affba6f5dd269e3d3a90f455e3cf293,
975a5998db2b2701027c00986ac7c5d50e13616dd4f2468bbb2993884cda9f6a,
d2e3f0f4d88034304d37ea5eb11c9fed0293e6ba493d916f1aa83384c575870c,
7260bc3a9540575c2071391dc0ecf2e74a397b91b8508f9179f20d1c533c1731,
0be90ca84dd0a03908a2b471718c2fbf1aa36f773ff8b94dbafb99ec27deb7c7,
9b00b061ac051e546b8d07f1f4d959829e039b524641e0f084022042370ee31c,
5948127a272f3eaa27a0378e027407ca8c2b842997749bf56da3019fb1f5bc16,
e5f8b1f8e2139ab4d0d829c6f1e60ca737879cc70ea5ec675954ec5b2e79b709,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..b5efd1caf6873c10bd351992a72182718417063fc67f30cdbafe335a6c5efaeb
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
8a60c2625629f9129cb932843859f719e656999b1c2280512bc6f5008585e1dc
..1300dc867c12cc84742b4d182aea0b78b9b22ac7113e0426c062f9759f8c5d77
..96dc89af27b32f5b6760c128406552f34b4785b94e3eb0e7cd1e5f56eb76efd5
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
8b5b47170bd988fdad118e4a80fb8396f2638bada741fcb1ff584a2bc3023d4f
..78734026a2f5ac8e985f19a8ae4639589107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..890fa5a6de704aff007a2f739257aae5f07d0642b83cd0821cb28c764fb976b2
..75c0fba256d56892e98a8a84197cb87bb7fd7cdca8e88ded497276288ca9e8fc
..06389faabc1814bc731256df23e7316604d528fe2ea823abc1a9af51c0eb73bd
..80ec85dc6a451a51a7f3b707e1c3301bc6cdf6fa878272fad9e7113b8166a11a
..65e100aa0ceb3d617988bfaba5f2391cb0ebde916e19c8893beef0a4c4312451
..db75bc241b4f7199d014ba5018376f39d0fa75802306564f355a9da97b05fb47
..ac8a63a3c17e8fa6c306d47e8970b217aa82c794b9377220ed86836f768d2f31
..7888ff556b18b1f57037b8c73a16363c54c37c41adf6c4b954f0e3279e9a584d
..1e8c04b5a5e127525969f3bf92f23b4c807ecc02950a7dadcdad47596d642246
..d0e21c5ddbdac40b234f079444b3d7ec21893a3503079539680069cfb9ee6a1d
..b5f73b104ff67d74d7cf4b00d040fa26ba216849dbce6a59f02ae1e2e9d52f0f
..656cff3b3e963e0d93728735bde20ddb0c64869a7f372178c3948ec86b155474
..5351dc51bb871cbe11bd44501e74806d87cbb198409683a540e43168e2512acb
..b80e2227c14c2d37c631aca20ebebcb21428cd4cedda8c9b466d5a9d5f4df49f
..aae353facd1d34ee063228b56925a59579f990732b9bee6f3909c3126a8f680f
..42233638898995e684e79fd09c9c882f,
```

### bandersnatch_sha-512_ell2_ring - vector-2

```
6b750d2754ebaf3163bd2b9a1ffb0137de1096c53467a75ee0625c133a4b101b,
d6351fb4f9dcb616f34b2b48a94acabf8faf769018f20457d56156076501a9b5,
0a,
-,
bf5904142f7fff1a333ec352f02e07d368bb437f77a1159fae0480b9bc444dbf,
e0e64cc4b110dd4d8a6d1c2c6d900f1b36c19bd5c6a847849650d8837a6c2af3,
7e04da6e16cc9a19888d9a9861c14d20959e183177086645e9716066c51259c7,
371e8373751a4b0ed6b59a5f08a83cea22c2dfd925695315d2dc4824bd368408,
ef5058187cb6f117f3f091a8243b53b533123488ddc32fe5306d41f6bf7fc1d2,
f101d7a4e97b6aabebc338ba27d714ed6d46fc314d6cb7f8cb7ad1b59f8c28c4,
dc452942c6742830ed982e6096171bec3c00c8919e6d93c3977a3e2d7267ebc9,
ee65dbeaf545aca526f3968688862483840e1ea154c2f52d0d7db830c2de4015,
9996ba654ae210f7bb74026f7be4eb3fd5bec113c60c36fff2d30077e2b4c314,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..d6351fb4f9dcb616f34b2b48a94acabf8faf769018f20457d56156076501a9b5
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
8b2bb43930b193d6adbd2199c286b1f7981e303fb075c14d4d35de5672d817ac
..dde9153110657576f31611c6d5e9c77e810a2191adf3e5093df4472ee8e78fdd
..0cc608c75261c3316738b08eb4d30e96992e798d81836e7a0dcb71866cda24d9
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
83d55a9aa4b199b0b99a4fc9200bee2de99c8b6d07682802c01c40355ec33440
..1f82cc9135351f496d6b3baf68fcc4db9107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..ac9be2467517f0ac26f61ac0bba448279c3d0908e69cb527863d5de30e340949
..5400ace4ff8bafd739bfeb14e558825bb3a7b8cf4e30d8881a12f9189a7c2434
..837e26d32e623b4bd36b71cb15e4ba25d51c69f52840fd6faaa84f7171230f8b
..712514510eb90d509929c195904d35207a2907aa3c6930c41bf6cbfaa69fa354
..b2a84d32a45d252f929142686e73eac96201b0133315959bcf7f96a1f93cfe37
..80f877841f96eb223814b0dd33f55e1d06c36c149d0baa2619acfb564130e05e
..529ee8c423c758ba338d1e5fedd79bccfe08a5cdfcf96a3c33c7b3eeee549a5a
..d97f7a99af94387278e47309f1f762d0b221ddb95cde96ab14e01573965a424f
..49b5eafad36ac61e67bc07661fca829f2235023da47c5e99d3007823eea1803c
..ab0e15f955bf6128b4da5c9b110d5cf00da10242b266312c3ee1ed1174a9df33
..b4e450ec51c75739738db3f2cc71c89c0c55bc8004b8a4aecfc9a2e77ecdefa3
..aab1272e50f2e6e1f3b4288957806d60a326f817961268329c952983ba1ee736
..d1309a1169f557301ff3558194c32a1baa420b227546db6302e75d664de7a468
..da68acf1cfaca911ae9ae57bc7663df00b8ca652f4acaa1e0712d41dfb565f49
..82c6c0f30c98b7fdf33d4502685f6c5f9e2e7d2a7e6ffefd1e79609e3ab03925
..fff4fa4f1c4b50336a20c2059a4dfed9,
```

### bandersnatch_sha-512_ell2_ring - vector-3

```
d65e63da3835b1cbd4a56743b33465b991893271be22970f213899fddfdf451c,
b27d1ca12ede738d0909705d2dc69d7aca8b7fb3f451db3721cb92baf7f75bad,
-,
0b8c,
507b8f930c8559d29b409054f5aacc435b3756c37ee6f38ba55678961a63013f,
014e64809463cfef1e2fce8eddc3af72402a5d20981549fd14f75d3a961efec9,
8789e98c6b52051328e1f7513f735e623e7d46463e11b9650bb8f2097a84280f,
47b44926c9a52aadd92c6394a251499eb22ad52df58bd057fc1eda1fc1121e01,
f052b4b7394bc58d6e3f35ac9fa7914db8dca08dab1d86f3a8af9b3a06a4a81a,
b337e3fce7b29347938f0daa81745bc439b19f567d918e45db7bf69974ecca51,
876e077d8cbaac4f78fbe3ab0aa058dbc83661f73a6a2028871ed74a9b2e68a1,
8ca70184988af3da4c31936c879f20a3bc50faf226e0c0d02d20fddda61ed51a,
7c58bab21c811c7fcc5466681fdf35aca9d416e5b4d7b1af1b2c754491b19a09,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..b27d1ca12ede738d0909705d2dc69d7aca8b7fb3f451db3721cb92baf7f75bad
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
a3cc305ef6c649564b5b14337e95d91e16b33f2b0313f7322e2f3e9e04f2245f
..6b906a81b653886e15e6ff00b57cd6a0985ab96eef8d2398455644d1d050ee95
..2bd9514924660e8d83aaaa52444ad7257452da60ddfc344dceb9c300c7b52b5f
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
8e0da4251b34bd32200df303b1f2713e91a98cb84c3478327afc491d262c1fc5
..50319146342f3af0df608ad496c99d399107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..89a032ba743d41ea8f2bf76183097b0e8c8f0b9e97d49a2f95c9e96f1bd2aa95
..1b76469320e4b8fb893ca6de730e0b41b14f91cac0bfa9fd0c42df9746e8db32
..dc6177298452e7228c748763c673169890500195361b98bc1268d31468634fba
..519e3c9d2019e4fe874f9fa09d6f6bf032120140cc764645800eb3615ac96a63
..1d0f2c9d23893b9ea7d5be0f908b23f94236eb096434440caff102164d33766e
..18b85cc589f9065d6633d96a756801c5676f96de6b468de0827296767fac485c
..2d8296c4d01449fc04772e4f22a68825ddfe6475076c5b7f51f5045b15cc385d
..a0dc6de585080771543762710e1a05ec584d3c165148e97fc93b73ee259ffd2b
..a0c607de5d2532914716b8d688f06b77e1f576f3f241c122d20c8647429e6e65
..f2d7f2841db1514c55398b15761a22bef60a8af4a1c3a2ed4cfc755e2469803a
..91d9860dce595acd63071bc7917b52ed94e681188ee0917c852095def941d539
..78e7a0906e2e1e2c665e8ee71e2dcca1aef1f69d0be51af57a28a98452c766fd
..1a5fa73b49d88e0cbe0e36770452c01cb2e66ada9720a58a9065fe159561f951
..7bc3572e1fd42d05dbceab98974fc3bdd75f0f243532849f0783730bb192266d
..8f1a3fbdd3987cb75d5805b9318ff6d3279402818eea0ca8368bc9458bde0bdd
..0dc7f5087755403fb3e34710da2e03ee,
```

### bandersnatch_sha-512_ell2_ring - vector-4

```
23af4703982081016292d2873cd291eaed09bae027a0ffa027b8d906dba50916,
ccd66b701aa97824a42bbb748dabd371f3eb0ce29352a749073afd4f39369cea,
73616d706c65,
-,
e6952ff094431bdf3292564f316b472e567a47161feb20e48adcd9e4943a912a,
20ae74617586e0e357706b6c1e2775b4efb8c2a6766b5d10bc69b824b53e2039,
13ddeab303bdaa180338ff7f2821b48142a0b4d0a29b26e9fc8b847c38712be4,
a90778fa94841666b5ed8e753326bbd56aaefaf39fc8272e34c56b1b2846ba0b,
3874f9dcb49f359e0b9b3db29b119828517c3857b33b1937a8b8e8209109041e,
9c356fad97b79e589763abbe9c67bdf5feaaa9e897a4914b49863d7aec562da2,
dfaf403db6c9e29bd40c69c461363bc3afbdc98bb2971001848bc02f8a0ef90e,
e77991fcd10c83921f08fdc7666daf6c7b082691d8f289e3dbe4b41e54b4a80c,
70991887fcf9abe4e3b169c899e598fcf8b2b0577be91598cbd2a15754c4241c,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..ccd66b701aa97824a42bbb748dabd371f3eb0ce29352a749073afd4f39369cea
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
90bbab52a7628599234444c36d2116748e7346966a72fdcd9d846f67c92d4b9f
..82eae30ffd9c11748f7cab956b10334e8de1e1a552709f8b8e16d9091fada848
..584ab9a5b021331742e3fb67f17ef0a2431071e3321720ec9986e0492e8b9244
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
93d1ffd3e38e167e19897c94e127b61d95804f46b31e57efff6005b2f6645f18
..382ba75fd699424c0994500c7ac6c95e9107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..86b7c6da8b995c77ee6b353f28b539e66b183a0eaf8f6a4638d6ccbdcb4e5708
..c43fd24439702ca090c30c7735a79887b8b239b403328cf91f9845a94b5706e1
..e49922dc2430e29c0032f5a53fd6e0cd0dec236c1d8c54fc828b8927338feded
..3a2a88ea5216c78ee240894ca19ea406d46d851aaf6b2da9e9191e3d19ffdf64
..a99ac232b8b1d0adfa7b2cbd950115288ac3602620b815f2dca7e2de0a483043
..e443497dd245fa750939362df5964cbd1df6ab14b42c9115d451c72257069327
..a0fc4865df5a4e4141205efad4e32f595bffe64f2c13458283c520c4f0708a6b
..d8e3c2fc95b82b4525fdbb1fa5dac9f487d578b5fd2c09bdefb910ac5a478c44
..659b66a0bc22fbe0a4c4c70c65d532f19869e8114484bda4e0cdab271cb5350b
..f9c190498050256d24ef397b2751732f5e5b257a13da3d6a69669441d6d1626f
..982f2ef8b35088f1dc725375874351283da572b7fd23dd3099df36ed707faf44
..c76359970794c8d20bb0471af18abd585e68bcf07e649d08d06111cbd3e11a70
..91ddbba17a53da6677eb441944ddef04aca6a677af3acf9dfca3440af2b1c052
..75d896c4def723e8b041ed0a6fd1ed498fbbad740ae119a950a1c568f7707185
..b1063f698928c9ba99b785bf5fab6c20143f940f4adc8421850ef64512d9bfaa
..a6306f21104d98d0c8c41591fbe87767,
```

### bandersnatch_sha-512_ell2_ring - vector-5

```
d3474b24545500bf46e4cab5eaaf7b3778d92fea7d60339d2c04f14787b54216,
6d972e05ba078b9b1452c7f407a11499d78c951bbc75f29dc39da267f038fee3,
42616e646572736e6174636820766563746f72,
-,
73068394e07bca18a291338b07bca6db4375dd003fb6202eb70765dae1cccd48,
f7245e2d4f92bfcb731ffc065aa940659bf28d7ad857650f21e3b8312f75d602,
52444c24a837fd222430b317078d5e1ab52c12944089f523c34907c752f4f81a,
0702700c7eac908e31f6a92e148dbdcd854777aed5de632ac12b42b364d2c613,
7d63c597baeb24f32d4fcdacd939bb2f3dc88aa43d39cf7c448729f43f70f207,
39f50b04ef04ff2619f42675b35acdbb4d2359527d972ba4a44000bdef189f85,
103691e064422bad1add6d32d0ee55a4b509e7cea4104abfda363dd0e72d6526,
beeec912cfcaeddaeecff1605af14a5ab1cab288cd0074b4d1da7189e1b12a0a,
da497db0b72ddc5f06d5f78d53eb538937716edd742385e1820d4ff75b9e740c,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..6d972e05ba078b9b1452c7f407a11499d78c951bbc75f29dc39da267f038fee3
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
a08f0b8f4bb802f544b68a5fd3e15e636ef7ae1705513c35bf6331a69f5f1bd2
..d9d5a7d7b89da9eec5796c1745c6003989241294ecaa5c5d68be560071ead6a8
..764d508055800ea224ec820e263ef3e191339c7ad61a883702d989f4fc85fb0d
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
ae3a84f1d8b621e8a21b6ca946b8000c38cc14354d72dd9f6762d52d42dd3e94
..a78f46ec42a557ece8ce67dc7c3da4a59107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..9163c863857d69edf95f5e399740588d22a4d5bda54e3d401ce6e88fc544b0aa
..f68a5354e7bf40bb03a63016298cb4359749d5177eb738222a201716277ad6ee
..af0989ef4554610d9f6403343c30552ddf3c89b9ebb63116090ee8a2237cb858
..8dbb7b630e04c65e90efe2583aaecd5239d8629a5170feefada9b451ad15c459
..9db3820c3064a6a855c1f85706c9a5415738f08343eb7aa98b2f51be9be52e48
..55fa0aa7172fc86b05e4760674cd839c842bc653493d32931790b57ff1657f43
..a58eaa10599fc3a49c0e6397aa3f1bf4ef28203a760a03bfd5a2233ec6ff7e40
..6ccee7a82e2bb72e6d11a2c56687365ec410f12580fdfe7a1b1db942ecf47843
..f43509586c731819fae7ee9df3f6e13b77453e375dba01c70f64bc8886e17072
..9c428726e3f1da850cd4a450f65e95fac188bde4d80916e2a5e6fd3802f75227
..973c3018cdc2fc4e77de306718cf15f2651191316787ce91fb8f39bda2452cba
..685ad593db00f60ab31eabd6ebd73a9275c59bba262a3c638bf2f6e1eb765888
..3c25f6674fe7d81a4a88238ac5ed7d4eb968e3f55d280a215ccfc84152b6cbf2
..d907e98fc2c1cd163c96f6701f457c1d5752001c38828b951e825a429529d1f5
..986f7f8f935694546e47b0fc290b949198ffcdfbb2dce4c8e56bc51762f2e76b
..8dba7c01700352dd8cd1408dc46dc445,
```

### bandersnatch_sha-512_ell2_ring - vector-6

```
d3474b24545500bf46e4cab5eaaf7b3778d92fea7d60339d2c04f14787b54216,
6d972e05ba078b9b1452c7f407a11499d78c951bbc75f29dc39da267f038fee3,
42616e646572736e6174636820766563746f72,
1f42,
73068394e07bca18a291338b07bca6db4375dd003fb6202eb70765dae1cccd48,
f7245e2d4f92bfcb731ffc065aa940659bf28d7ad857650f21e3b8312f75d602,
52444c24a837fd222430b317078d5e1ab52c12944089f523c34907c752f4f81a,
1e7365c45df7cf8c794ae59a470dadd546166d31120dbfbbc055598072199b17,
913c4f02bd0e132896082c464107e4835b4d77ffd65a3ea7b9025a98886b0981,
9a52a1c931defee9f0b9d8a5ab3c945c1055d96e9c1c903a486c612a1756ae95,
509caf042ae3dc08b4431723367395952073aaf1b71a625b766790354066f834,
5305c3d3f33f0480b9c7be4da9b27b7145b2d7cc2a2b2f3a0478e8ad8103370d,
16948495dc63b3ae489b9206f93aebc47af37f25d18804b3685f05a4ef39d102,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..6d972e05ba078b9b1452c7f407a11499d78c951bbc75f29dc39da267f038fee3
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
a08f0b8f4bb802f544b68a5fd3e15e636ef7ae1705513c35bf6331a69f5f1bd2
..d9d5a7d7b89da9eec5796c1745c6003989241294ecaa5c5d68be560071ead6a8
..764d508055800ea224ec820e263ef3e191339c7ad61a883702d989f4fc85fb0d
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
8f843a2c4561a81b5eda5abe61b50303bf4fcb8c3f04a9475c4f3edda2ed3750
..1d30951ccdef5831a086370aeadc42419107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..a474644feb1d85a3f25dc92cfa2c5a531c87ee83d967f5fe7ce68789bb44e875
..611c3d47eacf38b8ed19c6bb5cbc6ca4ad04daaf0a37553906d018a53836fc41
..3753a27b6a5e2694b7a6def3646592f0e190893e3fb97ef0f68806479aaf4ef8
..d48331e8180bcf0f9c61891c09d072f805f7a58beed833ea871a4fc503482e69
..b27dac26ef1df4fc50e8f6f3e0259d5842323b14b5e401d29470db7a0d22846a
..b402448ca0d5fee6b5a6b10bd6943d2d8ce2711c32391e27e1c75df0d3dc641d
..4b57559e77752af3937f6f41575c9148d799e851786a6981c363826580ff716f
..5efb627b4eca8fd682c3f4a10a363107710e2a7b05c9c95d04ff9fe8a11b0e50
..9051423bcf98375dda71418b81a7fccaa244aef2a46c389f2f0e1a64118fa259
..ea7f58fd6993f1198306eca438431e660d8e52a580f3b0e46aa0b83bfe21d61d
..b05b2e19e856818f8e2fd1410dd3769aa83f67c9ccc5f7f802fe85b4d6b1aac5
..d76e134b879c7d09bba40d9cb89f38a6037e2ee05e8a5841d03c334277ec0f97
..06c18ffebc4e20ec869489e0a1b0156fa0e7fb3c55fc38b9031e09370e1e3f8e
..dbdcf3f06da5ea39d9e5c50e551925e76ca7abca1c4eb318194f4f298e761338
..a93ec3b6a2ea6742ed319def13a2a255a46127998ade7c25a163c5a10904d7c1
..d3398a2d60242c982298f4025c87f6ea,
```

### bandersnatch_sha-512_ell2_ring - vector-7

```
d3ca62c2eff12acf77b6745a0a4ef633bbd87d44c163dea26bfd57ad6ddce80b,
a05f85d1afd54269db4e51d4a0aa7dada0ba0b20d00e21dbcafc96afcc87bd34,
42616e646572736e6174636820766563746f72,
1f42,
73068394e07bca18a291338b07bca6db4375dd003fb6202eb70765dae1cccd48,
38eefb096193eb94d8ffe21340e123c69205c213afc18b5df6c0ebfc9d94f45b,
a4df10b7839ec0f64d364e97f5b37e470595412d8c2c5adc30558e95f292e0bd,
0b9b0728f497c925d7fc730656b8fce60d5df309cc48a9a98efcfeb54728d70e,
41cfcaa44aefc251f80de667765ccbb2342043b12ccea51e58dc21f0605ab01e,
1963d7687f050751bc85648887cb31d489d7136a21a37f8f14c25f0c5a91380f,
d1be8e787e651db9139ed6906e66ac7fd412e5c9766c8719b6dc806fd91bf31d,
3c088d386d0b374b0ec431e05c6232e6b8708b8e91c03e4d456778e5fb3b7617,
b77c408ad1cf1403f3c253230786af9ff6bd61622caf118406333c7fec04d411,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..a05f85d1afd54269db4e51d4a0aa7dada0ba0b20d00e21dbcafc96afcc87bd34
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
8f5b84eca9493d4726b47e13bfcb511a6141b073c239f1fcf0a72ff7043393e2
..32dcfc7363d3fcc19c965c5c2d91fca98fcad446d732161e257a57d7f55f6e1d
..c28e9e3bdcfeb31c86530a352c6db405c2e9f2b734f8af7cfb7aa370c3fe9e20
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
a0d3d386e4c91ebf69dc9afe9510a389b353d7b98f5e7124b8f7067154e7f602
..f2ea7c36aeda396a04d2b9498d72cba09107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..ae661328e821164662d54bb5568174b558c1a53774b84c2a20c88f667e5079c4
..773361baf60fb2f13c7cae666eb0af3e8f7be2171541e789b1e10aad992d4ef6
..bca6cdf5520cbfd16ba1bce50e796e7b5d5285283575458f8254722f54641210
..053ffd6c49d690d213ddb8b0d528deb4af9b6c14fdff47407863aede90d98b71
..65b58fd9890a338fc2b61b1ab32adfcd709df8cf9083268ac44b02ed970bef26
..6ec3a73f8721690700d5784567a48cadc5125613c6c7257c664d1730259eb464
..70aff076d473fc703f5afe06f2cb713bba766601a7d854771d89ff7fc2bcf40d
..b87b116576005c31fcdbb52187d51ff57f00471eace7ad4f6959398d8d434841
..9676116db8d4e17feba223668612325b76b4f566559ea6283021a83102f4732e
..84eb234a65c3451e54b8f4836148f7a7a23fc984696bcd616e389e0580a53171
..adc0d5f25dd326eb6e78923522c9827247e80dd703554a1175509bbfc9076f1c
..748c1cb38b7c1477766cf20115ddc8b704b6db942e9dd82cb8ab65d0ba177674
..fdafbc123fcfd231faf9a6174d42ac46a94c16eab6a6ff83e01b963490eb121b
..a8d00e85b407f7bdac514005283bdc50aa52c9467019b1a2307aaf07c1fca6de
..8aca7ed5fdf7e198718f37d38614c3901fbab59ce4b2b87d04544951f8e192ed
..8768abd486546104bc6f79e0605b280d,
```

# References

[RFC-9380]: <https://datatracker.ietf.org/doc/rfc9380>
[RFC-9381]: <https://datatracker.ietf.org/doc/rfc9381>
[RFC-6234]: <https://datatracker.ietf.org/doc/rfc6234>
[BCHSV23]: <https://eprint.iacr.org/2023/002>
[MSZ21]: <https://eprint.iacr.org/2021/1152>
[CSSV22]: <https://eprint.iacr.org/2022/1205>
[VG24]: <https://github.com/davxy/ring-proof-spec>
