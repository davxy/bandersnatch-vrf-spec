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
x &= 23335687741101763108036518445642207119627658113885888016488710494487028845889 \\
y &= 5552214580375038693022409684979828600325210968745774080859660443337357929963
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
x &= 14056632001415368875257708737821299882600475929746323097150942355715730684350 \\
y &= 10322661992765989500407719465917595459409463902187386706652408883505670839210
\end{aligned}$$

A point with unknown discrete logarithm derived using the `hash_to_curve` function
as described in Appendix A.2 with input the string: `"ring-accumulator"`.

- Padding point $\square \in \G$ is defined as:
$$\footnotesize\begin{aligned}
x &= 26913883415342152801331916189968962157924271221160514298872262294143390094043 \\
y &= 30874728313203001508631936119690348239461579770372782660098261717479009115354
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
  check $O_k + c \cdot O_m = s \cdot I_m$ is vacuously satisfied
  ($\mathcal{O} = \mathcal{O}$), but the commitment check
  $R + c \cdot \bar{Y} = s \cdot G + s_b \cdot B$ still proves knowledge
  of the Pedersen commitment opening $(x, b)$.

# Appendix C. Test Vectors

The test vectors in this section were generated using `ark-vrf` version `0.5.0`.

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
f508a4e84812ee3dce73ef72bb9064308128384b4801f81ef8616a7dffc486bc,
54421f7ffc399872f1cb868efbb7eef4034178f1e369cebfb964ca61e4f3f256,
7b89f2aba6af7474694f24f75adf48336e00dcc8f3ac889ef4daa53c859497a6,
5685489f948058d1ac34ffc87d6adc09,
be881519a8790c307e3997b9b7905061b82009bc9d73ee5c5363319b1c884915,
```

### bandersnatch_sha-512_ell2_tiny - vector-2

```
0b4259ca1b10c9ed462532639113e1caf26b3a1a2d9e91ecef2fc5c2d23aed0a,
ff341f0c9da793b2d8fef91bcbfd5b55c2185352e4289edc1dd6c64e3fe09b0d,
0a,
-,
8ec04d55a790d47cd32c5062cb44517f164515dac88a8ea6d972db1a7da08abf,
e20e48a14d1ab23cad04e8bc39705d194e87587072fe2e7114d1f85fd7fb6105,
f7f5da876f037509854307d89273b14ef5db4f0971df0879963e1bf0e775636f,
8d56976c451b512a88a28704cd62546e,
68a6a31d6ce21ac9ea4e6eb688e19e08fc30a50a0dcd7c459dc0be49daaad415,
```

### bandersnatch_sha-512_ell2_tiny - vector-3

```
dd60163595ff312a49aa5849917ba19020038ccd42f8a1d468da0973079bdb15,
fbba8feb488e767b9864726fffdc8595896757430eba9162a1a5d9a03381d5a4,
-,
0b8c,
f508a4e84812ee3dce73ef72bb9064308128384b4801f81ef8616a7dffc486bc,
719ace6342e2c5b3615e33d6e081c6ffbf0813f3f42ccbdf92973869fab0bbe5,
cc87c37551a222fe1207655f20225cb79a3dc2ebcefd7111550911e36423ad62,
7d7a08eed618b81bef1ca85695b93d6d,
3a1107ff4361fd10bf5b891d5554cc76e56502d9f034e921eb2cac0aa73d9206,
```

### bandersnatch_sha-512_ell2_tiny - vector-4

```
dfc32f03fe9487f123f2afeeb9487cb6b1eb23efac24a60ae540f5aa632ddd18,
f8487052801a89161424ee745189b5f7fe568819b9f13f44a8b3d173b57e928a,
73616d706c65,
-,
fa6a45172b622ddaccbcf7a3b2d91a36ba504598a83d5a4ed23b416063e4e039,
8f3ee5f3e386775c13093f84678e01594419d747a7037619fa7ea20790044218,
67c6fbdf10f3b5abec5c5ea368662455aa1cac36a6a17621ddb2b526c52fd8dc,
e44e5064895730cb04907d46262e63fa,
393f12e07c2ce66c08855bcf64a9c3b1dc29e455af7e235500f04076edb0c70e,
```

### bandersnatch_sha-512_ell2_tiny - vector-5

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
-,
832414b806b4dd6f98117818f1518667c8bb2bd625dfe353b1f2d22d4f32ead6,
a99080c7bb9f8f4ccf68aa2cc8a946b03dbf07735564a5102009f2c8e5013bd2,
d52ea29fddc6c87f38e5d56ef2f5af434f90f28e8e122dd99284076b57d29997,
c43dfc9ad3e72ab427810f5879683725,
08484f31d398c8f27b8ff363354bb14a5b5c23caf1436b321f5ea30b7f555e13,
```

### bandersnatch_sha-512_ell2_tiny - vector-6

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
1f42,
832414b806b4dd6f98117818f1518667c8bb2bd625dfe353b1f2d22d4f32ead6,
a99080c7bb9f8f4ccf68aa2cc8a946b03dbf07735564a5102009f2c8e5013bd2,
d52ea29fddc6c87f38e5d56ef2f5af434f90f28e8e122dd99284076b57d29997,
53613c4e23191e4bc2632927f7fd4316,
84e4072747518ad201335c841fac19222f8ee895f288da6304cd89b3ab4c7708,
```

### bandersnatch_sha-512_ell2_tiny - vector-7

```
9504efbeadf81b20a9cb64c1331915eb3718a574227458230d1d80dfa94e8b13,
704fd3784947de4db4fdcf0b477530d094bf5a656707b7d6cb43edbc4db7336b,
42616e646572736e6174636820766563746f72,
1f42,
832414b806b4dd6f98117818f1518667c8bb2bd625dfe353b1f2d22d4f32ead6,
1617b4fca3d7354fd43ae783bd6d0cfc526a80e257fcccfdf8e4d87e74dd7c6d,
6b279b85a1c55f55db80167e6bee997a5bf25c1767ffc2a34ae696baf606f5a0,
365b235ddb44510f484f14d5d19a1cd6,
9f5f9515507c84924f87b5cf549da8b177879cd2f835f94b91e36543e0cfbb0c,
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
f508a4e84812ee3dce73ef72bb9064308128384b4801f81ef8616a7dffc486bc,
54421f7ffc399872f1cb868efbb7eef4034178f1e369cebfb964ca61e4f3f256,
7b89f2aba6af7474694f24f75adf48336e00dcc8f3ac889ef4daa53c859497a6,
d969c67f8fd97fcc8c0f8b129810ef5427786e319e304a056038caf32286d15e,
374e93cc0df1aaa3cbe7a66397213275e852717462f8a9b775ed8bcb68f45b00,
```

### bandersnatch_sha-512_ell2_thin - vector-2

```
0b4259ca1b10c9ed462532639113e1caf26b3a1a2d9e91ecef2fc5c2d23aed0a,
ff341f0c9da793b2d8fef91bcbfd5b55c2185352e4289edc1dd6c64e3fe09b0d,
0a,
-,
8ec04d55a790d47cd32c5062cb44517f164515dac88a8ea6d972db1a7da08abf,
e20e48a14d1ab23cad04e8bc39705d194e87587072fe2e7114d1f85fd7fb6105,
f7f5da876f037509854307d89273b14ef5db4f0971df0879963e1bf0e775636f,
22be463a480dfadb3beb93ba75890a612fb65e206fecdd9fa9ec130ed16db268,
2eb15dc87c37022290606c34db23fdd7a80648e6aa0dce076ca3694000a72c01,
```

### bandersnatch_sha-512_ell2_thin - vector-3

```
dd60163595ff312a49aa5849917ba19020038ccd42f8a1d468da0973079bdb15,
fbba8feb488e767b9864726fffdc8595896757430eba9162a1a5d9a03381d5a4,
-,
0b8c,
f508a4e84812ee3dce73ef72bb9064308128384b4801f81ef8616a7dffc486bc,
719ace6342e2c5b3615e33d6e081c6ffbf0813f3f42ccbdf92973869fab0bbe5,
cc87c37551a222fe1207655f20225cb79a3dc2ebcefd7111550911e36423ad62,
2d726da5bc791c511e7b5629bde266151d66f9f36d276dbe16dc1c900f4913dd,
743aaadff73eaaccc8e6cc333542faa331a132012e9cb2112a1e681546152d01,
```

### bandersnatch_sha-512_ell2_thin - vector-4

```
dfc32f03fe9487f123f2afeeb9487cb6b1eb23efac24a60ae540f5aa632ddd18,
f8487052801a89161424ee745189b5f7fe568819b9f13f44a8b3d173b57e928a,
73616d706c65,
-,
fa6a45172b622ddaccbcf7a3b2d91a36ba504598a83d5a4ed23b416063e4e039,
8f3ee5f3e386775c13093f84678e01594419d747a7037619fa7ea20790044218,
67c6fbdf10f3b5abec5c5ea368662455aa1cac36a6a17621ddb2b526c52fd8dc,
9a638cee379161ecf1a9269801631303359a531b035076369617c42ef46afcb1,
223446d4fd1450c1fef095c3fd3d5a52ae9f3a8b07a88d7e7ddaed089b235504,
```

### bandersnatch_sha-512_ell2_thin - vector-5

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
-,
832414b806b4dd6f98117818f1518667c8bb2bd625dfe353b1f2d22d4f32ead6,
a99080c7bb9f8f4ccf68aa2cc8a946b03dbf07735564a5102009f2c8e5013bd2,
d52ea29fddc6c87f38e5d56ef2f5af434f90f28e8e122dd99284076b57d29997,
fdfae23d8d8c9a5225a7bd49b65cc276abf7ce0f48a3730ca74eb57fe0b27467,
d55860b9c11a56cbe92b5d9c992fd95756fe1845be0be7eaa2a291b524cd111a,
```

### bandersnatch_sha-512_ell2_thin - vector-6

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
1f42,
832414b806b4dd6f98117818f1518667c8bb2bd625dfe353b1f2d22d4f32ead6,
a99080c7bb9f8f4ccf68aa2cc8a946b03dbf07735564a5102009f2c8e5013bd2,
d52ea29fddc6c87f38e5d56ef2f5af434f90f28e8e122dd99284076b57d29997,
d415fcd6eff582440fab9c62819b3bb82dd7158a2faf0465512aa095e9e885c2,
f2f59942f122f9566576ff9cfffbc803f1229881044aa69cca96193106b08c0c,
```

### bandersnatch_sha-512_ell2_thin - vector-7

```
9504efbeadf81b20a9cb64c1331915eb3718a574227458230d1d80dfa94e8b13,
704fd3784947de4db4fdcf0b477530d094bf5a656707b7d6cb43edbc4db7336b,
42616e646572736e6174636820766563746f72,
1f42,
832414b806b4dd6f98117818f1518667c8bb2bd625dfe353b1f2d22d4f32ead6,
1617b4fca3d7354fd43ae783bd6d0cfc526a80e257fcccfdf8e4d87e74dd7c6d,
6b279b85a1c55f55db80167e6bee997a5bf25c1767ffc2a34ae696baf606f5a0,
9f9f6670d06734e319a01c6afb72e0e3647085dae2216c707a22643a3ef1a5c2,
74544f931a955eb7f38dab224988f37425b1275b78ed4340f6d5b7c4bc91a60a,
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
f508a4e84812ee3dce73ef72bb9064308128384b4801f81ef8616a7dffc486bc,
54421f7ffc399872f1cb868efbb7eef4034178f1e369cebfb964ca61e4f3f256,
7b89f2aba6af7474694f24f75adf48336e00dcc8f3ac889ef4daa53c859497a6,
afa1000852c300cbf235a6955ec4105b01919fa67ec6cc92ec92100f19c25809,
680539c070ebcaca50c4bf201869c2c355f1467e1b8ece6e0bcafc466872c5cf,
375a8ec2e95f58a41ea09090f9560e580e7a3cc67998129fa98dac1da5d0850e,
5071efbef9428b2a26eb09440891c6829bc0c57b4254ca811ce453a0d5938dea,
7dc8aa043b28383d334ef500fd7d770d35ab1c5ebc28df0807215911f4ab2d10,
045343af67f88d35679beab125c38b80029099b746ea47ef3eb488b1d38d130d,
```

### bandersnatch_sha-512_ell2_pedersen - vector-2

```
0b4259ca1b10c9ed462532639113e1caf26b3a1a2d9e91ecef2fc5c2d23aed0a,
ff341f0c9da793b2d8fef91bcbfd5b55c2185352e4289edc1dd6c64e3fe09b0d,
0a,
-,
8ec04d55a790d47cd32c5062cb44517f164515dac88a8ea6d972db1a7da08abf,
e20e48a14d1ab23cad04e8bc39705d194e87587072fe2e7114d1f85fd7fb6105,
f7f5da876f037509854307d89273b14ef5db4f0971df0879963e1bf0e775636f,
da3304d52c2a64ea75504ac44776e5e4900a38eb9a61f9478285aeccba6ec41c,
a356a2fafe785bc79860ef65534df7c1a2ee7d45ff6db649537dac1687ae4785,
ec546c1932f72e146a0e45d7107c97e99aacc9c72fd6ae6fd0b0417124aa26ca,
1d661c6349b33182ec77b58457f6d45dd9a618017ea021b986cf1eff18c4ef95,
1e8eb9a8cf017c6a50d0f947f9bf02575b60c714c81602a8f06965ec7e67c300,
49c44ad19ea4aaadfc98c2586660dbf3d8a434bb062fa948d82fd4a717ac5f12,
```

### bandersnatch_sha-512_ell2_pedersen - vector-3

```
dd60163595ff312a49aa5849917ba19020038ccd42f8a1d468da0973079bdb15,
fbba8feb488e767b9864726fffdc8595896757430eba9162a1a5d9a03381d5a4,
-,
0b8c,
f508a4e84812ee3dce73ef72bb9064308128384b4801f81ef8616a7dffc486bc,
719ace6342e2c5b3615e33d6e081c6ffbf0813f3f42ccbdf92973869fab0bbe5,
cc87c37551a222fe1207655f20225cb79a3dc2ebcefd7111550911e36423ad62,
3dd321bf1fbbafd76d48c000a28768152e919789bd57cd50d5e17c88a1baec0a,
6d16e2ff7b28a8880499e34cfe6ffbb1d12efc27675af3fef635e8761c893dee,
5311bd0755a2bbc6db01b930526e85120af5189e2fb259fc941f3acb1611d6eb,
3c4ea965693b470b0da4f9c9508da97dfa70e5e85ee78fbd3af377a2298b4864,
a48a2f80da4190ec19e293a50bbc1bc047ebc38a14f4f19f97f5daec48ab4205,
eb91c85fb3b211f1ec63612950d04c78fc19a760294d01bd82f9218e944b640d,
```

### bandersnatch_sha-512_ell2_pedersen - vector-4

```
dfc32f03fe9487f123f2afeeb9487cb6b1eb23efac24a60ae540f5aa632ddd18,
f8487052801a89161424ee745189b5f7fe568819b9f13f44a8b3d173b57e928a,
73616d706c65,
-,
fa6a45172b622ddaccbcf7a3b2d91a36ba504598a83d5a4ed23b416063e4e039,
8f3ee5f3e386775c13093f84678e01594419d747a7037619fa7ea20790044218,
67c6fbdf10f3b5abec5c5ea368662455aa1cac36a6a17621ddb2b526c52fd8dc,
b3f08962012e4f4aa9e6482d7d682275ac98e57f099b991947fad5a53451d51b,
1c48e5ce0ae9b3e7a09626bc1333544f1dbe5033d5efd591a059b04a41830eb6,
17b630103915e544c1b4b1a3e8cbad9cf57e75bf7f02a18ae965db26f0d2189d,
a16224226f643245a4c42ddac28d614fbe46d02ea1f8d1dcab91a26eea0c19bb,
bd55995a3f6bffe519366ea7b891e1d006da5472b8de95c5a8c7db52adf2f91a,
c946c76414f1c4b5f5825e4cb5fcda7a5aacde9fa0ce1c478caec1f3d812c606,
```

### bandersnatch_sha-512_ell2_pedersen - vector-5

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
-,
832414b806b4dd6f98117818f1518667c8bb2bd625dfe353b1f2d22d4f32ead6,
a99080c7bb9f8f4ccf68aa2cc8a946b03dbf07735564a5102009f2c8e5013bd2,
d52ea29fddc6c87f38e5d56ef2f5af434f90f28e8e122dd99284076b57d29997,
08fbea5cbe5af93a1529c222d6b3fcc672599e59261d9ed485ef45146befeb03,
cdf7907e1902ab6989732bd5824171912905725296e86d2d864ed0eea5322d54,
02667d1f512990e80b127eed9139ae5590853fde2469e177fee5fa0908de1fc2,
c2d48dada6adf017c2ed658fd91789e4b63f2d6b894ce98fbfef97c56ed4d5d5,
48c13fd4d2cbe731e7ecbf9cef6b2fa5c1a55f27bc0f34753cc211d7cbff7103,
78c5b906fbbca6466120cd079bf7fcdecedc1db7916ed74dbf3ddc2f5063b81a,
```

### bandersnatch_sha-512_ell2_pedersen - vector-6

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
1f42,
832414b806b4dd6f98117818f1518667c8bb2bd625dfe353b1f2d22d4f32ead6,
a99080c7bb9f8f4ccf68aa2cc8a946b03dbf07735564a5102009f2c8e5013bd2,
d52ea29fddc6c87f38e5d56ef2f5af434f90f28e8e122dd99284076b57d29997,
c8b1ce7a665f75506e6a64ef52aa7d8cbfecde0ad83946eb980ba4d06580f819,
635ccf83a424afe87946a36a532f2f2dd4e72b280f9a8d04e4abe3b7f3cbd89c,
3b15fefece933682d3a92dc57fdaa4da6e76f80c41cb926b00376576bced3668,
4b24cd4a4c25aa29aae4e969cf5be562cb9ea176593f8c06bb7343c8da71eac0,
3278c30b9d2fd950fa1a6e82e98375c8fd651f237806f8eaab44c0817b2cad10,
d59f47aa43f471c63ff9cebbab2aaea14feeeb914a3e1a9589350864f3d7b902,
```

### bandersnatch_sha-512_ell2_pedersen - vector-7

```
9504efbeadf81b20a9cb64c1331915eb3718a574227458230d1d80dfa94e8b13,
704fd3784947de4db4fdcf0b477530d094bf5a656707b7d6cb43edbc4db7336b,
42616e646572736e6174636820766563746f72,
1f42,
832414b806b4dd6f98117818f1518667c8bb2bd625dfe353b1f2d22d4f32ead6,
1617b4fca3d7354fd43ae783bd6d0cfc526a80e257fcccfdf8e4d87e74dd7c6d,
6b279b85a1c55f55db80167e6bee997a5bf25c1767ffc2a34ae696baf606f5a0,
3a19e858c8f2cc41037737c43d23dbf3d124ea7059d30c6ab88aa184e14fe20c,
0a9e31ccc09e5464e53afa2057098da6208478f9334199c60bd4bc7443a3d5c5,
1ce7b8f6bcf3723106588842207b1199b8feaaf3bcc13874c0fa2e82a53b47b3,
7372c8e03008802e1bfdf4ac6b8832aded5b48ddb688af168cb67a882628ba22,
4b61c4d7d6179d8e1fe407a20e1ab22acec0a4834eb36fe03f254480d9d87e1b,
40d1a91ac8b287a2b754e9ba05c7c2091e140f0fb40753ebbd2573b6e9d1f514,
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
f508a4e84812ee3dce73ef72bb9064308128384b4801f81ef8616a7dffc486bc,
54421f7ffc399872f1cb868efbb7eef4034178f1e369cebfb964ca61e4f3f256,
7b89f2aba6af7474694f24f75adf48336e00dcc8f3ac889ef4daa53c859497a6,
afa1000852c300cbf235a6955ec4105b01919fa67ec6cc92ec92100f19c25809,
680539c070ebcaca50c4bf201869c2c355f1467e1b8ece6e0bcafc466872c5cf,
375a8ec2e95f58a41ea09090f9560e580e7a3cc67998129fa98dac1da5d0850e,
5071efbef9428b2a26eb09440891c6829bc0c57b4254ca811ce453a0d5938dea,
7dc8aa043b28383d334ef500fd7d770d35ab1c5ebc28df0807215911f4ab2d10,
045343af67f88d35679beab125c38b80029099b746ea47ef3eb488b1d38d130d,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..5a538209ff1fc7b1c9c8e1da05b3e169acf10a8b1591b3af029fe4eede0bbc71
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
b0b98118b398c44a391065d9ff7d1afb3b7d3ce2c4d81db787ccf6f7d90cf36c
..8e15688183f5e4c1d2688aaaf289a4448c2b9665fc06b8d1fbb42010f1c7b7c6
..1669f4a2922bd9ec90ba95f5bc8e4cc6d3faa1af74a2a83f3a5870c15f4e18cf
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
a88f3e5041ce58a9b730391fdf31004a4eceec666a600ccf443b0ba82c478c88
..fea31f106453618afb82ae847d905cad9107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..9544919af606752d54cabaa6a28c30762a42fb27d7347aa3a7d95e6451d735c7
..db7395793dc4ee1e2a63ab02c0d112baa66816f64eafad9351b9e11386a79abd
..3652805e5244bd13cf00e5d949c252d2977610d9721e05d699bc73b14bf2b5d4
..d9491f72803a1165a82f7ec4c02e177dfec115f10c24980fc1148b20d188c839
..da5923eed4679b688d28225fc9fa01d0b4c8c84c96d318cee216c718a35aef04
..7587f52fb5ff09acf3e109feb54b0d0f34fbf8fec8465b37e478edb5a055cc2d
..d4f01d358a5b3c5f6ba74973e363eb3f58e5b9b59342fb5d34516fc360b9500c
..edc3e7e7182e2800d8599daf5f198c8dd21bab8faf01ba6d7567f26c79b3063a
..621181498e89b13e4954db72cb5a7c5179ef74424a6ccd2b34d9919361565236
..cc3a3d0dd91d680f84d19c9f78a4619bdf127c52e636b5b56726af7644f6c553
..a72102f6b8d96baed533806d665d961a6a999fb8b563c2af2b99381067a2ca27
..48c328ab92bf96d34200d14a3032f46f27106ce65d6fbe17cc47d0574e080536
..da27459afccd64dbbe7d45ba41ed4a64a63604043ca130ed5bf0ab1a179cd7d5
..9c52cc8c088864bb16f9bc2256329448044860fd850c337eb162ce909ca80b89
..aa5e660e1563aaa6c1cc007b5070711fa55d4976548e56c9657c973aae29f3fe
..3485705690bb6718a47a6b1b175b879c,
```

### bandersnatch_sha-512_ell2_ring - vector-2

```
0b4259ca1b10c9ed462532639113e1caf26b3a1a2d9e91ecef2fc5c2d23aed0a,
ff341f0c9da793b2d8fef91bcbfd5b55c2185352e4289edc1dd6c64e3fe09b0d,
0a,
-,
8ec04d55a790d47cd32c5062cb44517f164515dac88a8ea6d972db1a7da08abf,
e20e48a14d1ab23cad04e8bc39705d194e87587072fe2e7114d1f85fd7fb6105,
f7f5da876f037509854307d89273b14ef5db4f0971df0879963e1bf0e775636f,
da3304d52c2a64ea75504ac44776e5e4900a38eb9a61f9478285aeccba6ec41c,
a356a2fafe785bc79860ef65534df7c1a2ee7d45ff6db649537dac1687ae4785,
ec546c1932f72e146a0e45d7107c97e99aacc9c72fd6ae6fd0b0417124aa26ca,
1d661c6349b33182ec77b58457f6d45dd9a618017ea021b986cf1eff18c4ef95,
1e8eb9a8cf017c6a50d0f947f9bf02575b60c714c81602a8f06965ec7e67c300,
49c44ad19ea4aaadfc98c2586660dbf3d8a434bb062fa948d82fd4a717ac5f12,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..ff341f0c9da793b2d8fef91bcbfd5b55c2185352e4289edc1dd6c64e3fe09b0d
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
94f0f18ec9f0593fa1bfff259f33600653fbe62a665e9345bcf5149fbf0cf52d
..9748bfc8b7c40c01a11736a7cf55239dac1956d482d4cd466e1f921e52ae5f0f
..ce92c3bc53844977507630d6add31b2674046761607c3131567fac4ca610e985
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
b1db26d63b3147361513641ced7124d32642eb1246aefd0c25495387ec3e8a1d
..fd1ffe4870e37ce5e3a5ac300a507bc39107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..a9af4c62f6d00e23d85b14c83e8d8ec6948a30871c2171ec2c98b78bd3c542d1
..ad95025cf9e2fdfda6d6926e42e6a2478b80aeedf10a587fe26c1feb19481f7a
..043eab9d3bafdda49ee2b32079524f9c5277df8ff2e976341b009ba470fe04a1
..b720d6cc520eb9b6e15d7d590ce8105ebbd9064bb8c6f10aab02ed91dc1c0430
..f70441bb8375bcf61ecb1b93b1ea8661634b7ebcf379fb16f7565e1fcb889971
..c38ae9824ce3afdf4b0253bcafd1da0240c67a07516e4966fba334cbbb7d5b73
..233c8b0fbdbb229398ebbf0d2d5b993733d2e288d02555b0bd1c78c297d0b62f
..ac56252e2080bcbc1a62f3de4c601995b976957fd1e60a69a8eed5d470405358
..79a4c050ac105812d55ed2d4ec454f1d3ad8b59bec359e2d596f222d837cce31
..efd614b86268d1290911c46c6445590ee5eb7b08f7aef20cbc0ee2c210e24503
..900314cd1cec12f509bebf7256c83d810014348189272f076b2ef91384257827
..899f7c5971c37b8f0f2796979770999a8a4c22e7bdbe138dbd37941b09b1649c
..30e5484b3e73a08bdf92d3a928546722a1d9570ff2a7a6688dac5a7687d48021
..649b9ec86d648f1094cb5fad173cc88b5aad0ff3c26606aa6af9d8c46c491bc6
..91bae6269d202b0fc85bcfe806ffff37a0e9fd9d91d3c75e9be7952042c5d087
..90b01bf994ec674b531323d263a62678,
```

### bandersnatch_sha-512_ell2_ring - vector-3

```
dd60163595ff312a49aa5849917ba19020038ccd42f8a1d468da0973079bdb15,
fbba8feb488e767b9864726fffdc8595896757430eba9162a1a5d9a03381d5a4,
-,
0b8c,
f508a4e84812ee3dce73ef72bb9064308128384b4801f81ef8616a7dffc486bc,
719ace6342e2c5b3615e33d6e081c6ffbf0813f3f42ccbdf92973869fab0bbe5,
cc87c37551a222fe1207655f20225cb79a3dc2ebcefd7111550911e36423ad62,
3dd321bf1fbbafd76d48c000a28768152e919789bd57cd50d5e17c88a1baec0a,
6d16e2ff7b28a8880499e34cfe6ffbb1d12efc27675af3fef635e8761c893dee,
5311bd0755a2bbc6db01b930526e85120af5189e2fb259fc941f3acb1611d6eb,
3c4ea965693b470b0da4f9c9508da97dfa70e5e85ee78fbd3af377a2298b4864,
a48a2f80da4190ec19e293a50bbc1bc047ebc38a14f4f19f97f5daec48ab4205,
eb91c85fb3b211f1ec63612950d04c78fc19a760294d01bd82f9218e944b640d,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..fbba8feb488e767b9864726fffdc8595896757430eba9162a1a5d9a03381d5a4
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
92c975ae43de7bd1bbbcb3ebf6f04e99136472c8e665c48618ab06171f96fe69
..3f2f12089ac66e5f79a68b1bff5b7076b1584cd580607934a1d1e0feb12c9bcd
..60440b83a85d8f142a9a3834b3da1c157fc80f1684ab0eb21e70b8b1ae571768
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
b5aad40d12b343366083f9a84c186d2dfbd6ebd7573f1ef7ff14e49c9e1baaf6
..4b62f751e821188ed13b329dfd4e4d799107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..8e0ac886ab6a40f4e54281fc4698174ddfd2621259950c659c102629b7dae6d0
..5e47219066b2725d95df23e8dee5b1d683e8d9403bdafa74979c83014c7eaad0
..3c96a5eb7966e44f2a46f291fcde1b8074f3a781bdebcf0a16da471c90846f5e
..b7a9bef19b200f0adaefe85adee6cab46adce74aff1133c853cce2ce2a96133c
..e996256dae7b294ff36a6ee0841ccc622f9799c6835ef8c3456232963d1bcf68
..d22d33ca2f73826b94bb365582baf7c69eaaa14f7ae54ec6a28f6a232b34cb5d
..861d411d57a1df938f88ed517cb109c4c8daa4d678cf5aacf3bb391932e9ce65
..111fd51782ce82119806a18fe799238ca4753517ddc2fdb3557fc51d809a9b2b
..8d72462b09ca852d5c146de0f8b3feeaf0528606ef096164af793423b7830342
..234fa6a96a895e27f9ffb37ba9246b29ad4c2db52acde665bd22913b56bdb216
..b2fa26e5b91dfa8d6a2ec1c6f002cb4596d65784e4b283b011f2c9bd1b47ea5c
..4b662b6db72fe2f53cea7ae575ac7c7f9008e7e1f70ad6f29b702fd147e44a15
..c1901edad5b587830e2a847a4fe72264b983933c1ac9cdcd09d5bd7cb6e61600
..c191acf69113095c03dbbe17f6c1d50ba8aca3afc64f9f8cebfddbb05347a760
..a1763564cfb18d1313f48f6484f763ca499bc68b43057969a9ca1e27fb0cf781
..a8f48bcfd3b25b83a5738a35039854e2,
```

### bandersnatch_sha-512_ell2_ring - vector-4

```
dfc32f03fe9487f123f2afeeb9487cb6b1eb23efac24a60ae540f5aa632ddd18,
f8487052801a89161424ee745189b5f7fe568819b9f13f44a8b3d173b57e928a,
73616d706c65,
-,
fa6a45172b622ddaccbcf7a3b2d91a36ba504598a83d5a4ed23b416063e4e039,
8f3ee5f3e386775c13093f84678e01594419d747a7037619fa7ea20790044218,
67c6fbdf10f3b5abec5c5ea368662455aa1cac36a6a17621ddb2b526c52fd8dc,
b3f08962012e4f4aa9e6482d7d682275ac98e57f099b991947fad5a53451d51b,
1c48e5ce0ae9b3e7a09626bc1333544f1dbe5033d5efd591a059b04a41830eb6,
17b630103915e544c1b4b1a3e8cbad9cf57e75bf7f02a18ae965db26f0d2189d,
a16224226f643245a4c42ddac28d614fbe46d02ea1f8d1dcab91a26eea0c19bb,
bd55995a3f6bffe519366ea7b891e1d006da5472b8de95c5a8c7db52adf2f91a,
c946c76414f1c4b5f5825e4cb5fcda7a5aacde9fa0ce1c478caec1f3d812c606,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..f8487052801a89161424ee745189b5f7fe568819b9f13f44a8b3d173b57e928a
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
8f3bd322dd602f42115519028e1261ee1dd456a7a8a92363b4ce733d53a80ba8
..d0414bdbd3634ac75487ec03a4f4458d975014f4832268b15b43cf23c2fb09f6
..056f3a8eb1881ed4d7e2d5e1f0e07dbc0bd7686c04c1a9ab906578736efbbf7e
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
98e9ae043bf407a800c73f16585b9fa74acd7c09038d04af53da2583d62c3b2a
..1ad6ccbe263f6f62547067f35c7bae909107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..b41e837b06a596792ebe4847f044a1c9992b00d425cefd37e7ae8cbb99b8fe8d
..25ef49e0dca6b4b354921967a6f9e03c956a9a5558912ecde5539854c9958692
..566557a9f9a81546baf91617fd41e3c7960848e584e2d1d35a8be5ac5911086d
..d7d1f3b32411b9bdf92b9b9ff47fc0ad5c172662e9eaaccf7300f350b740b239
..c9213c270f1ab0f7b7fd115b4fcf30ddbdbe14b21872cdd4cc3f6260f92e2621
..555fa06619f164d0116d58670925e74e5579140c388b463a39cceef4734ae321
..b7b9c79ec2d4b778c457aff910e27296956483eb1c00fb5df65b6032a7962d71
..8ce87bc2ecfdb519f71a2ef2cf37ce234c065fd820e7d46aa9b4910fca9fcb0f
..e887bd3d99ebdbdaee2dd94c00e1ba286d71da97d804f2eb9e90045974548f18
..59546e0e5603ec3acb11f20cf3aa513ebb45af6e501329654076b8be4eba5f08
..aac72327767b0be36cddd535a4aa866d317cc441c3cae05ab36510aa0080ea4e
..24e1e2e837880ca0cae490f7e9866e92a5ae3904b7cf79a8de01fdc3b2d29284
..0b4b8bb0a50c6d3f84e59c18131db932872ac971a15e0a883e0de6ca79795e0f
..a04adb0d3ce7e2b7517ee8b12a6348f267439319cd1fec9d5977a7d9091b0f34
..aafeae086a35677fb741acb5437d8bd9d64e2649ad0aa62244b90d106d068fc7
..e0859d7bed816a3bef6dcb33dc009459,
```

### bandersnatch_sha-512_ell2_ring - vector-5

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
-,
832414b806b4dd6f98117818f1518667c8bb2bd625dfe353b1f2d22d4f32ead6,
a99080c7bb9f8f4ccf68aa2cc8a946b03dbf07735564a5102009f2c8e5013bd2,
d52ea29fddc6c87f38e5d56ef2f5af434f90f28e8e122dd99284076b57d29997,
08fbea5cbe5af93a1529c222d6b3fcc672599e59261d9ed485ef45146befeb03,
cdf7907e1902ab6989732bd5824171912905725296e86d2d864ed0eea5322d54,
02667d1f512990e80b127eed9139ae5590853fde2469e177fee5fa0908de1fc2,
c2d48dada6adf017c2ed658fd91789e4b63f2d6b894ce98fbfef97c56ed4d5d5,
48c13fd4d2cbe731e7ecbf9cef6b2fa5c1a55f27bc0f34753cc211d7cbff7103,
78c5b906fbbca6466120cd079bf7fcdecedc1db7916ed74dbf3ddc2f5063b81a,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
b4f43f81bf0b79c4b144d8ba8f7975bb12b512aa15ddc53e5eef73647b6fbcde
..47697176d801d29de4270293a68d328891798ba7a2d045a4c403f647619ab997
..54f593d73de9b09e1d65d29cc60a083b9677f9b2c8f6d66142908e6778d29a3d
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
87b659658d78c2d7154006f0592e159386828c8ee3955ad4795ed2751cd061d1
..238b1bb57c402937481854ab9a0e52a09107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..8d75886422670dd4bf46279c1914efae398dc1cd5724b1bfc8780470ed67db63
..932f28ea195e4d836ee4cd58d054ab88a2d5bf2660bb37b0756c9fc8a8bd5d81
..699b208bb25689c9d90142c774f4310404ef03af8a41301c5a7be003edf060f9
..66037ce81d3526a84e86a417df80bb6910f77b801ee82bf2f1a7d593d024ec1b
..e4feacca619ab375e247a6cab09c64dd221d567e649c5735c738d10450388a2e
..72e8d49a4006cb45b0e32439f61d6578cd6700abb863da52a2f078526aa42669
..b524d4626b936ed0e957c711cddc03584a22a2b0fde46f7c3b7a60160c72ef35
..4b1dccbb231d4a2b6a26f28713fa7ffab4deb1141529dede42fd066fc929755a
..7e1c1ef71ed98a5d44ab20176f8c120215444058ac0b8521472a664a33c0d843
..1edfe789f6221ccc33644748d9347bd900f8e1ea008b7cf83ed931bdfd4d9d63
..aab1165d23aa23bfc0f49aba962080de70ff5c3457343858799d7b7a12c48945
..cada1ba8c461586e367f125fee0ec7b0c02efd913b89b80e633bd59a3c6a1d08
..ef98f1aea1f5528b07408981b15a606cb14596953ba42f5b18d681922c3bc3f0
..773d1cf7566d543202c3db456f1f95fd460081ff6759da8c0caf6f90a431df7f
..9171d5ad8046ec651e76c019ae1c5f94e00cc3889dcdc1115cc53fd0fd548c79
..af1ef586376f6447f1224d879a1d393c,
```

### bandersnatch_sha-512_ell2_ring - vector-6

```
04d3da92994eb327893f747b5aee14f82353ca88f909585b492ac6124c52da07,
6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4,
42616e646572736e6174636820766563746f72,
1f42,
832414b806b4dd6f98117818f1518667c8bb2bd625dfe353b1f2d22d4f32ead6,
a99080c7bb9f8f4ccf68aa2cc8a946b03dbf07735564a5102009f2c8e5013bd2,
d52ea29fddc6c87f38e5d56ef2f5af434f90f28e8e122dd99284076b57d29997,
c8b1ce7a665f75506e6a64ef52aa7d8cbfecde0ad83946eb980ba4d06580f819,
635ccf83a424afe87946a36a532f2f2dd4e72b280f9a8d04e4abe3b7f3cbd89c,
3b15fefece933682d3a92dc57fdaa4da6e76f80c41cb926b00376576bced3668,
4b24cd4a4c25aa29aae4e969cf5be562cb9ea176593f8c06bb7343c8da71eac0,
3278c30b9d2fd950fa1a6e82e98375c8fd651f237806f8eaab44c0817b2cad10,
d59f47aa43f471c63ff9cebbab2aaea14feeeb914a3e1a9589350864f3d7b902,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..6be56f1a0c32af7ff857e278dc9a0dfeaf724b5961ab0a0147663f77d3e0dfb4
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
b4f43f81bf0b79c4b144d8ba8f7975bb12b512aa15ddc53e5eef73647b6fbcde
..47697176d801d29de4270293a68d328891798ba7a2d045a4c403f647619ab997
..54f593d73de9b09e1d65d29cc60a083b9677f9b2c8f6d66142908e6778d29a3d
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
875e6616f4d39dcb1bd8dbac51fd6fbf54e2fc24ee641cadd283138cff4dd31b
..a336f7ecc1d29923a6330679a822cc4c9107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..84e134c22a168085546b5d1e770cb1c578a253a6344209aa346a242ff62459fd
..ab5a3024f74ba6842ab2aedbdd25f47d951f863a44c3712e65ee38496cbcacf1
..73560adec3b143ceac2e42cd0ed1beebecbc59ee1bfea5346144b2f9ecc9acd2
..c7be098013600886cf8f8dfecf5775918c843a72ff0d5123161b0baf7f827d53
..00e134fa0e9c02810d598a665c28a69b470c0bb3049f29e2e21604d403d05365
..803065bd1b8887d6f7d73a8bce144fe03c8573978b3891ca67dd254f61e4b444
..b2e54e83e53a0beefb24ec34eba6886fa21ffe3de8eca9a5f8a739f56f5a873d
..85b99984380564f9992b105c5dd9f5df1d5586748abfe52be134071de4ffef23
..368afdc6fdbe75587780b667108599aa4ea4051fcacd83fdc52f31a26fe60d71
..f614c50746be5d68abf785d2e13656744c1463a32f55f6604568d50f9b4af52c
..8ffc4cbdb78b88ccdcc826d32f1b1bb2f44b3fde506dd6379a5bd6dc642202e0
..b220ebcbf7a60fe6045489717bb2b7cef209be9642142e3f88a54d70d12e228e
..9d70c0e400ed72b39b8fa0805bd4a76a8aba88ca324dedb1aa1778ce58527900
..35885e4a2982da28a28044c50e7f2b2e18e473ed76e13c0778bb88128b206bba
..b59b7a2fb6ac7c8b852ec8af45c84bb95f8fa3736d57addea168c2381668067c
..ae4e3cb4c72bb3b2b724e582c62faf45,
```

### bandersnatch_sha-512_ell2_ring - vector-7

```
9504efbeadf81b20a9cb64c1331915eb3718a574227458230d1d80dfa94e8b13,
704fd3784947de4db4fdcf0b477530d094bf5a656707b7d6cb43edbc4db7336b,
42616e646572736e6174636820766563746f72,
1f42,
832414b806b4dd6f98117818f1518667c8bb2bd625dfe353b1f2d22d4f32ead6,
1617b4fca3d7354fd43ae783bd6d0cfc526a80e257fcccfdf8e4d87e74dd7c6d,
6b279b85a1c55f55db80167e6bee997a5bf25c1767ffc2a34ae696baf606f5a0,
3a19e858c8f2cc41037737c43d23dbf3d124ea7059d30c6ab88aa184e14fe20c,
0a9e31ccc09e5464e53afa2057098da6208478f9334199c60bd4bc7443a3d5c5,
1ce7b8f6bcf3723106588842207b1199b8feaaf3bcc13874c0fa2e82a53b47b3,
7372c8e03008802e1bfdf4ac6b8832aded5b48ddb688af168cb67a882628ba22,
4b61c4d7d6179d8e1fe407a20e1ab22acec0a4834eb36fe03f254480d9d87e1b,
40d1a91ac8b287a2b754e9ba05c7c2091e140f0fb40753ebbd2573b6e9d1f514,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..704fd3784947de4db4fdcf0b477530d094bf5a656707b7d6cb43edbc4db7336b
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
b3982b5838293b8fb58f52511cda9ebcab48a5f0932edf817630dccc230eb651
..a8f97ce4fd078b7af816329f5739ee12a2fb2031f85fac1ef27137ad68e5ae0a
..befb844f516a67641847b265eb1a353652fce946342f487d95b0a538e229d6e0
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
8048dbacf65522f4ad29d64c1eaa2e914a308bd0a69de81499436e9b516fd8cc
..ec4512abea7dcf27175f52b9be39f03e9107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..84989a9448a7393c6bf91ee89971748708c643a365b42421005e76c9eefaf024
..5b0d762f85a9fccd4900ed88d4a4ff85b7272746c0f19acc2c729f4b6ac50df5
..f6f3dc464fd39b4c4b8311b87600d9073bcba43577b41970105c75634edd2717
..d74a8975ace0661a7b1bd57765b5a430f6b38eed1f8eaa6e2440537e99f48a2c
..9237209d43328fd9ae447a610e0e4becca103208ee7b4e0bd6acf9ac267b0f13
..2700412904e580ec794b7af75f7d30224502b4facb29ff44ebb4d2fd80db9902
..edbdd1dc1e65466a356f46b1d2132103f86039f13114f3e06c98bab560d2e71d
..2f2dbd01e6b32a220f7ecefd812aed740bc1ef95bbd5b7d49a41ad56de8f3635
..2f2edf247ee7169a5927232c66a889aa11084a36b890582d9951168628cde057
..ab0290cd106583fe09a6c40c581e4b1f269eac69ac5e277911d0d3a41a701b2a
..a8cea5c7bc96efd03bd968045c1aee5e9cfd55c191256aae97445370e7d52ec5
..910a208a47b8cd30ac784acbc0e46cc33321cd7e3ba824206e7ee4de69bcb718
..b02b7514a55b89765a3743de28818b1f95901c7f1465e1287c83fe0f98320047
..4eda63eab68a605438860fe1d8ce88992a04b7bf621fd3c63a462917404d9091
..81c6a5a15e7c8ef381a59b22c3acfd5c66320a413ea393f08bd755e2a9463c3d
..a85ab2ff7e6311f41dc80fe6d0c798c1,
```

# References

[RFC-9380]: <https://datatracker.ietf.org/doc/rfc9380>
[RFC-9381]: <https://datatracker.ietf.org/doc/rfc9381>
[RFC-6234]: <https://datatracker.ietf.org/doc/rfc6234>
[BCHSV23]: <https://eprint.iacr.org/2023/002>
[MSZ21]: <https://eprint.iacr.org/2021/1152>
[CSSV22]: <https://eprint.iacr.org/2022/1205>
[VG24]: <https://github.com/davxy/ring-proof-spec>
