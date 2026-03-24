---
title: Bandersnatch VRF-AD Specification
author:
  - Davide Galassi
  - Seyed Hosseini
date: 9 Mar 2026 - Draft 30
---

\newcommand{\G}{\bold{G}}
\newcommand{\F}{\bold{F}}
\newcommand{\S}{\bold{\Sigma}}

---

# *Abstract*

This specification defines three Verifiable Random Function with Additional Data
(VRF-AD) schemes -- IETF VRF, Thin VRF, and Pedersen VRF -- built on a
transcript-based Fiat-Shamir transform with support for multiple input/output
pairs via delinearization. The IETF VRF extends [RFC-9381] [@RFC9381]; the Thin
VRF and Pedersen VRF follow the constructions introduced by [BCHSV23] [@BCHSV23],
with the Pedersen VRF serving as a building block for anonymized ring signatures
as described in [VG24] [@VG24]. All schemes are instantiated over the
Bandersnatch elliptic curve, constructed over the BLS12-381 scalar field as
specified in [MSZ21] [@MSZ21].


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

## 1.3. Constants

- `suite_id` = `[0x01, 0x01, 0x01, 0x01]` — a 4-byte fixed-width identifier encoding
  the protocol profile:

| Name | Byte | Value | Meaning |
|---|---|---|---|
| version | 0 | 0x01 | Suite version (v1) |
| curve | 1 | 0x01 | Bandersnatch |
| hash | 2 | 0x01 | SHA-512 |
| h2c | 3 | 0x01 | Elligator 2, random oracle |

  The version byte bundles several tightly-coupled choices: transcript construction
  (HashTranscript), nonce algorithm (RFC-8032), challenge derivation (transcript
  squeeze), point encoding (compressed little-endian), and security level (128-bit).
  Bump this byte when any of these changes.

- `challenge_len` = 16 bytes (128-bit security).
- `expanded_scalar_len` = $\lceil(\lceil\log_2(r)\rceil + 128) / 8\rceil$ = 48 bytes.

Domain separation tags used throughout the protocol:

| Tag | Value | Usage |
|-----|-------|-------|
| Challenge | 0x01 | Challenge derivation |
| NonceExpand | 0x02 | Nonce secret expansion |
| Nonce | 0x03 | Nonce derivation |
| PointToHash | 0x04 | VRF output hashing |
| Delinearize | 0x05 | Delinearization scalars |
| PedersenBlinding | 0x80 | Pedersen blinding factor |
| IetfVrf | 0x10 | IETF VRF scheme identifier |
| ThinVrf | 0x11 | Thin VRF scheme identifier |
| PedersenVrf | 0x12 | Pedersen VRF scheme identifier |

## 1.4. Codec

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

## 1.5. Procedures

### 1.5.1. Transcript

The transcript provides a Fiat-Shamir transform with an absorb/squeeze
interface. Data is absorbed into an internal hash state; output bytes are
squeezed from it. After the first squeeze, $\texttt{absorb}$ MUST NOT be called.

**Abstract interface**:

- $\texttt{new\_transcript}() \to T$: Create a fresh transcript instance and absorb $\texttt{suite\_id}$.
- $\texttt{absorb}(data \in \S^*)$: Feed bytes into the hash state. MUST NOT be called after squeeze.
- $\texttt{squeeze}(n \in \mathbb{N}) \to \S^n$: Produce $n$ output bytes.
- $\texttt{fork}() \to T$: Clone the transcript state.

A concrete instantiation (`HashTranscript<SHA-512>`) is given in Appendix B.

### 1.5.2. VRF Input

The VRF input point $I \in \G$ is derived from the input octet-string using the
$\texttt{hash\_to\_curve}$ method defined in section 3 of [RFC-9380] [@RFC9380],
instantiated with the *Elligator 2* map to curve (section 6.8.2) and
$\texttt{expand\_message\_xmd}$ with SHA-512 (section 5.3.1).

This is the random oracle (`_RO_`) construction: the input is hashed to two
independent field elements, each is mapped to a curve point via Elligator 2,
and the results are added.

$$I \gets \texttt{hash\_to\_curve}(DST, i)$$

The domain separation tag is:

$$DST = \text{"ECVRF\_"} \;\Vert\; \texttt{h2c\_suite\_id} \;\Vert\; \texttt{suite\_id}$$

where `h2c_suite_id` = `"Bandersnatch_XMD:SHA-512_ELL2_RO_"` is the RFC-9380
suite identifier string determined by the curve, hash, and h2c bytes of `suite_id`.

Verifiers MUST independently compute each $I_i$ from the corresponding input
octet-string using the procedure above. Accepting prover-supplied input points
without recomputation breaks the VRF security guarantees, and in the case of
Thin VRF (section 3), enables trivial forgery.

### 1.5.3. VRF Output

The VRF output point is generated from the VRF input point and secret key scalar:

$$O \gets x \cdot I$$

The VRF output hash is a fixed-length octet string derived from the output point
using a transcript-based point-to-hash procedure. The procedure is deliberately
independent of the proof scheme: for a given key and input, the output point
$O = x \cdot I$ is unique regardless of whether IETF VRF, Thin VRF, or Pedersen
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
2. $T.\texttt{absorb}(\texttt{PointToHash})$
3. $T.\texttt{absorb}(\texttt{enc\_point}(O))$
4. $o \gets T.\texttt{squeeze}(N)$

### 1.5.4. VRF-AD

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
via $\texttt{enc\_32}$ in the transcript (section 1.5.1).

### 1.5.5. VRF Transcript

Shared transcript construction used by all VRF-AD schemes. Absorbs
input/output pairs, derives delinearization scalars, merges pairs into
a single pair, and absorbs additional data.

**Input**:

- $scheme$: Scheme identifier tag.
- $\overline{io} \in (\G \times \G)^n$: Sequence of input/output pairs.
- $ad \in \S^*$: Additional data octet-string.

**Output**:

- $T$: Transcript state (with $ad$ absorbed).
- $(I_m, O_m) \in \G \times \G$: Merged input/output pair.

**Steps**:

1. $T \gets \texttt{new\_transcript}()$
2. $T.\texttt{absorb}(scheme || \texttt{enc\_32}(n))$
3. For each $(I_i, O_i)$ in $\overline{io}$:
   $T.\texttt{absorb}(\texttt{enc\_point}(I_i) \;\Vert\; \texttt{enc\_point}(O_i))$
4. Delinearize:
     - If $n = 0$: $(I_m, O_m) \gets (\mathcal{O}, \mathcal{O})$
     - If $n = 1$: $(I_m, O_m) \gets (I_0, O_0)$
     - If $n \geq 2$:
       a. $T' \gets T.\texttt{fork}(),\ T'.\texttt{absorb}(\texttt{Delinearize})$
       b. For $i = 0, \ldots, n-1$: $z_i \gets \texttt{dec\_scalar\_mod}(T'.\texttt{squeeze}(\texttt{challenge\_len}))$
       c. $I_m \gets \sum_{i=0}^{n-1} z_i \cdot I_i,\ O_m \gets \sum_{i=0}^{n-1} z_i \cdot O_i$
5. $T.\texttt{absorb}(\texttt{enc\_32}(\texttt{len}(ad)) \;\Vert\; ad)$
6. Return $(T, (I_m, O_m))$

### 1.5.6. Nonce

Deterministic nonce generation inspired by [RFC-8032] section 5.1.6. The
transcript carries shared state from $\texttt{vrf\_transcript}$, binding the
nonce to the I/O pairs and additional data.

**Input**:

- $d \in \F$: Secret scalar.
- $T$: Transcript state (consumed).

**Output**:

- $k \in \F$: Nonce scalar.

**Steps**:

1. $T' \gets T.\texttt{fork}()$
2. $T'.\texttt{absorb}(\texttt{NonceExpand} \;\Vert\; \texttt{enc\_scalar}(d))$
3. $h \gets T'.\texttt{squeeze}(64)$
4. $T.\texttt{absorb}(\texttt{Nonce} \;\Vert\; h)$
5. $k \gets \texttt{dec\_scalar\_mod}(T.\texttt{squeeze}(\text{expanded\_scalar\_len}))$
6. If $k = 0$: abort (implementation error; probability $\approx 2^{-253}$).

Note: $T$ is consumed (mutated then squeezed). Callers must pass forks where
the transcript is needed afterwards.

### 1.5.7. Challenge

Derives a challenge scalar by absorbing curve points into the transcript and
squeezing.

**Input**:

- $\bar{P} \in \G^m$: Sequence of $m$ points.
- $T$: Transcript state (consumed).

**Output**:

- $c \in \F$: Challenge scalar.

**Steps**:

1. $T.\texttt{absorb}(\texttt{Challenge})$
2. For each $P_i$ in $\bar{P}$: $T.\texttt{absorb}(\texttt{enc\_point}(P_i))$
3. $c \gets \texttt{dec\_scalar\_mod}(T.\texttt{squeeze}(\texttt{challenge\_len}))$


# 2. IETF VRF

Based on IETF [RFC-9381] which is extended with a transcript-based Fiat-Shamir
transform, support for additional data ($ad$), and multiple I/O pairs via
delinearization. These changes make this scheme incompatible with standard
RFC-9381 implementations and test vectors.

## 2.1. Prove

**Input**:

- $x \in \F$: Secret key.
- $\overline{io} \in (\G \times \G)^n$: VRF input/output pairs.
- $ad \in \S^*$: Additional data octet-string.

**Output**:

- $\pi = (c, s) \in (\F, \F)$: Schnorr-like proof.

**Steps**:

1. $Y \gets x \cdot G$
2. $(T, (I_m, O_m)) \gets \texttt{vrf\_transcript}(\texttt{IetfVrf}, \overline{io}, ad)$
3. $k \gets \texttt{nonce}(x, T.\texttt{fork}())$
4. $U \gets k \cdot G$, $\quad V \gets k \cdot I_m$
5. $c \gets \texttt{challenge}([Y, U, V], T)$
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
2. $(T, (I_m, O_m)) \gets \texttt{vrf\_transcript}(\texttt{IetfVrf}, \overline{io}, ad)$
3. $U \gets s \cdot G - c \cdot Y$
4. $V \gets s \cdot I_m - c \cdot O_m$
5. $c' \gets \texttt{challenge}([Y, U, V], T)$
6. $\theta \gets \top \text{ if } c = c' \text{ else } \bot$

# 3. Thin VRF

Thin VRF is derived from the PedVRF construction in section 4 of
[BCHSV23] [@BCHSV23] by removing the blinding mechanism entirely (see remark
on page 13 of the paper). Without blinding, Pedersen VRF reduces to two
independent DLEQ checks on $(G, Y)$ and $(I_m, O_m)$ with the same secret $x$.
Thin VRF merges these into a single DLEQ relation by prepending $(G, Y)$ to
the I/O pairs and applying delinearization, then proves it with a Schnorr-like
proof $(R, s)$. Storing the nonce commitment $R$ (rather than the challenge $c$)
enables batch verification.

**Security**: VRF input points MUST be constructed via hash-to-curve. If a
prover knows $d$ such that $I = d \cdot G$, they can forge arbitrary outputs
for that input, because the delinearization merges the Schnorr and VRF pairs
into a single check that collapses when all points are multiples of $G$.

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
   b. $T_w.\texttt{absorb}(\texttt{"thin-batch"})$
   c. For each $j$: $T_w.\texttt{absorb}(\texttt{enc\_scalar}(c_j) \;\Vert\; \texttt{enc\_scalar}(s_j))$

3. Check the combined equation:
   $$\sum_{j=0}^{N-1} w_j \cdot (s_j \cdot I_{m,j} - R_j - c_j \cdot O_{m,j}) = \mathcal{O}$$
   where $w_j \gets \texttt{dec\_scalar\_mod}(T_w.\texttt{squeeze}(\texttt{challenge\_len}))$.


# 4. Pedersen VRF

Pedersen VRF resembles IETF EC-VRF but replaces the public key with a Pedersen
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
x &= 5226425992571220769365843487102064307101272980791993134273780736997544949382 \\
y &= 46544868206883149332782258938702216106598247683423727002885664111567608220426
\end{aligned}$$

A point with unknown discrete logarithm derived using the `hash_to_curve` function
as described in section 1.5.2 with input the string: `"pedersen-blinding"`.

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
2. $b \gets \texttt{blinding}(x, T.\texttt{fork}())$ (see Appendix A.2)
3. $\bar{Y} \gets x \cdot G + b \cdot B$
4. $T_k \gets T.\texttt{fork}()$, $\quad T_k.\texttt{absorb}(\texttt{enc\_scalar}(b))$, $\quad k \gets \texttt{nonce}(x, T_k)$
5. $T_{kb} \gets T.\texttt{fork}()$, $\quad T_{kb}.\texttt{absorb}(\texttt{enc\_scalar}(x))$, $\quad k_b \gets \texttt{nonce}(b, T_{kb})$
6. $R \gets k \cdot G + k_b \cdot B$
7. $O_k \gets k \cdot I_m$
8. $c \gets \texttt{challenge}([\bar{Y}, R, O_k], T)$
9. $s \gets k + c \cdot x$
10. $s_b \gets k_b + c \cdot b$
11. $\pi \gets (\bar{Y}, R, O_k, s, s_b)$

The nonce cross-binding is critical: $k$ is bound to $b$ (step 4) and $k_b$
is bound to $x$ (step 5). This prevents secret/blinding recovery from two
proofs with the same (secret, input, ad) but different blinding factors.

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
3. $c \gets \texttt{challenge}([\bar{Y}, R, O_k], T)$
4. $\theta_0 \gets \top \text{ if } O_k + c \cdot O_m = s \cdot I_m \text{ else } \bot$
5. $\theta_1 \gets \top \text{ if } R + c \cdot \bar{Y} = s \cdot G + s_b \cdot B \text{ else } \bot$
6. $\theta = \theta_0 \land \theta_1$

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
   c. $c_j \gets \texttt{challenge}([\bar{Y}_j, R_j, O_{k,j}], T_j)$

2. Derive random weights:
   a. $T_w \gets \texttt{new\_transcript}()$
   b. $T_w.\texttt{absorb}(\texttt{"pedersen-batch"})$
   c. For each $j$: $T_w.\texttt{absorb}(\texttt{enc\_scalar}(c_j) \;\Vert\; \texttt{enc\_scalar}(s_j) \;\Vert\; \texttt{enc\_scalar}(s_{b,j}))$

3. Check the combined equations:
   $$\sum_{j=0}^{N-1} t_j \cdot (O_{k,j} + c_j \cdot O_{m,j} - s_j \cdot I_{m,j}) + u_j \cdot (R_j + c_j \cdot \bar{Y}_j - s_j \cdot G - s_{b,j} \cdot B) = \mathcal{O}$$
   where $buf_j \gets T_w.\texttt{squeeze}(32)$, $t_j \gets \texttt{dec\_scalar\_mod}(buf_j[0..16])$, $u_j \gets \texttt{dec\_scalar\_mod}(buf_j[16..32])$.

# 5. Ring VRF

Anonymized ring VRF based on Pedersen VRF (section 4) and Ring Proof as proposed in [VG24].

The following configuration specializes [VG24] for the concrete scheme:

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
x &= 42303668360647658687880456753606405401141031996216729331450763906967498848487 \\
y &= 41898972259388202032055565840730004413653698329702630697317353721966090663285
\end{aligned}$$

A point with unknown discrete logarithm derived using the `hash_to_curve` function
as described in section 1.5.2 with input the string: `"ring-accumulator"`.

- Padding point $\square \in \G$ is defined as:
$$\footnotesize\begin{aligned}
x &= 29586100106858075217954567072572265001347911471605742544678436487322334776392 \\
y &= 21753411410084671346581650250322348778806357231808407562422401169820213423498
\end{aligned}$$

A point with unknown discrete logarithm derived using the `hash_to_curve` function
as described in section 1.5.2 with input the string: `"ring-padding"`.

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


# Appendix A. Recommendations

## A.1. Deterministic Secret Key Scalar Generation

The following method derives a secret scalar from a 32-byte seed. It is
provided primarily for test vector generation and is not mandated by the
specification. Any secure method that produces uniformly distributed scalars
in $\F$ is acceptable.

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
$\texttt{nonce}$ procedure (section 1.5.6), ensuring seed entropy flows through
both the transcript state and the secret scalar input paths.

## A.2. Deterministic Blinding Factor Generation

The following method generates the Pedersen VRF blinding factor deterministically
from the secret key and the VRF transcript state, using the nonce function
(section 1.5.6) with a distinct domain separator. It is provided primarily for
test vector generation; implementations may use any method that produces a
uniformly random scalar in $\F$.

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

# Appendix B. HashTranscript Construction

Concrete instantiation of the transcript interface (section 1.5.1) using SHA-512.

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

$$block_i = \text{SHA-512}(seed \;\Vert\; \texttt{enc\_32}(i)) \quad \text{for } i = 0, 1, 2, \ldots$$

Each block yields 64 bytes. Output is read sequentially across blocks; partial
block state is preserved between squeeze calls.

**Fork**: duplicates the full internal state (including any partial block position
if squeezing has begun).


# Appendix C. Behavior with Zero I/O Pairs

When $n = 0$, the $\texttt{vrf\_transcript}$ procedure (section 1.5.5) sets the
merged pair to the identity: $(I_m, O_m) = (\mathcal{O}, \mathcal{O})$. This
causes the VRF-specific verification checks to become trivially satisfied, since
any scalar multiplication with $\mathcal{O}$ yields $\mathcal{O}$. The
Schnorr proof-of-knowledge component, however, remains sound: a valid proof
still requires knowledge of the secret key $x$.

The per-scheme behavior is as follows:

- **IETF VRF**: The verifier computes $U = s \cdot G - c \cdot Y$ (non-trivial)
  and $V = s \cdot \mathcal{O} - c \cdot \mathcal{O} = \mathcal{O}$ (vacuous).
  The scheme degenerates to a Schnorr signature on the additional data $ad$,
  proving knowledge of $x$ for public key $Y$.

- **Thin VRF**: The Schnorr pair $(G, Y)$ is always prepended (section 3.1,
  step 2), so the internal pair count is at least 1 regardless of the
  user-supplied $n$. The scheme remains a well-formed Schnorr proof even with
  zero VRF pairs.

- **Pedersen VRF**: The VRF output check
  $O_k + c \cdot O_m = s \cdot I_m$ is vacuously satisfied
  ($\mathcal{O} = \mathcal{O}$), but the commitment check
  $R + c \cdot \bar{Y} = s \cdot G + s_b \cdot B$ still proves knowledge
  of the Pedersen commitment opening $(x, b)$.

No VRF output can be derived when $n = 0$, since there are no output points
to hash.

# Appendix D. Test Vectors

The test vectors in this section were generated using `ark-vrf` libraries
revision `c01eee3`.

## D.1. IETF VRF Test Vectors

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

### bandersnatch_sha-512_ell2_ietf - vector-1

```
58459215c189331d33521ddcb48565d61ce604f6dba881c9736222094d445e15,
6ea33200f135837e4f5ad97f0e940416f0943c114acd2e2405e2776cef169d6f,
-,
-,
9646c575af23c811c5d4691a26121c845b80a3805452c7267c2dbe2110baa6e3,
ba004f4c74f7f55bab8c67d3dc38954d5d6f3155356028541d97b9bbb9762c03,
8f62d23d0275c7fbe1dcb412a6b6740a3626178bf78078892936c1530436d525,
04ca9f155939141f5d2abdf6e31f0c78,
9a8a4123abfd8bdde07edc7c046eb302f10c83bb2d1fe0fdc5e1c7433e60b610,
```

### bandersnatch_sha-512_ell2_ietf - vector-2

```
dde067b9b5427a0f84877aadd2bddfb3d2778e01c1d58b224ab2bb8d879d3e11,
22a7ef51153fc3fac9af2e12c7cc8b56908d4f07090d91f75eace2998e3bb14e,
0a,
-,
a208afb3b276ef91530ce906abe1e64917b612b6e062a0bb93090c77d9c5ba95,
e7bce7bf0721b64ebfe3586a08f5334c87afa2a7a787230e421b556abe9807db,
1b71fd7287039cdb377fd3eb15792d0e50f2286ceaff7dfb4864341ab607c63e,
2f6a518662272dd1ed5dcf025b795699,
6925c5e724b53f1ecda80ec7aff1c9d5c3e9ec7bf02c3458f40b2a5980769819,
```

### bandersnatch_sha-512_ell2_ietf - vector-3

```
00789d0d6efefcab4b2915ec93a09ff3ce4556ae876ab476cd9d984b277d2d13,
6dd61b52fefddbf756af8b6119926626911a029f8afb288a21fb2e3b17687cde,
-,
0b8c,
9646c575af23c811c5d4691a26121c845b80a3805452c7267c2dbe2110baa6e3,
951fc558e4cee0e02f1bf6e4c95b12e3d5101b5e2e4ec9635443943cf58e9d83,
91069a31fb87cca70398eb4206c5ea408b167a5ed7ca1d68f5ecf1666c0c7954,
de8935bbceb908dc15d85e57086519a6,
98b5e53e4f6ac575590a196e7706d5c75afbf673dd1602493c3055bacbed590a,
```

### bandersnatch_sha-512_ell2_ietf - vector-4

```
6533eb80a6539841c34abbc41e0579445816104e2acbd25a28f94a9a81bd7318,
fcac843725cc94efb96909a688d24c0019177d94b39154a42b1b654dce45d36d,
73616d706c65,
-,
f534e99a16886cb60e3672a9bcd65b57ec8a76a3d3f005850e9b38ea17d81636,
d7d3b99dbdef1e16fa1ca992dac684686cf4b16c5a3ed39fd353cd049337c9c6,
2fa4933f445d9b3e6eec45bd35f56a40ca18d6f385e8f7d50981aeab63f2b818,
d1922c21eec05cd2aab63dafab9fd3a7,
29738df3fda8b65e9464aa7794eedf1fdd3c765ff35d00c956e05cf136e3310b,
```

### bandersnatch_sha-512_ell2_ietf - vector-5

```
0e5e44de0eae0fbe819d5a2f8b913dc428e3f5486ec7188627f80d927009ca05,
f2743329156635b8f95586bcfa1c2704044fa62af7c8d0a5e51d2cb9397cefbd,
42616e646572736e6174636820766563746f72,
-,
47a25c71b9fccb60c72c2f5f9851df8594a9d346cda259dcef6ab5e6e441b795,
6c558345591f2d52eba804ff1bab56c9fa4bac85ab661b16b2c68a891954e4ce,
671ed2923f25bc913b1905c026412876297b2736fe056376b0e4af800ad10958,
0c24fd703d9bfffb2d7a7a8599e86196,
9f683f933cb5f1810fd34632b82465a48d960079fb949cd7b01608b0c485d206,
```

### bandersnatch_sha-512_ell2_ietf - vector-6

```
0e5e44de0eae0fbe819d5a2f8b913dc428e3f5486ec7188627f80d927009ca05,
f2743329156635b8f95586bcfa1c2704044fa62af7c8d0a5e51d2cb9397cefbd,
42616e646572736e6174636820766563746f72,
1f42,
47a25c71b9fccb60c72c2f5f9851df8594a9d346cda259dcef6ab5e6e441b795,
6c558345591f2d52eba804ff1bab56c9fa4bac85ab661b16b2c68a891954e4ce,
671ed2923f25bc913b1905c026412876297b2736fe056376b0e4af800ad10958,
7f6028091eab9338d1f64885a1b004b7,
de5420c744dd1cfef46c834e29ccf75e3a0fc179fd7203529fef5c517027db09,
```

### bandersnatch_sha-512_ell2_ietf - vector-7

```
8b776a316d705cfb06421427e66d1e94fa3744a2a2c4a091a90b84a272dc8216,
b234d14dd177bd490ac2c73f3c2ae69bc3c4189f18f6dfdeade33cd5c06b6d89,
42616e646572736e6174636820766563746f72,
1f42,
47a25c71b9fccb60c72c2f5f9851df8594a9d346cda259dcef6ab5e6e441b795,
12ac0121bf3b2662596c88f0df13cf947911815fc794dd241db2f35ba2b5edbf,
90c458cf7f33035689ea4b60df842a51bbc5f3c42112023e0b2e03fa617939bc,
b0928e26be7ac81ae06060736aeac044,
93d20ab13c5a887ddef7d561bdbbd0d04abd37953c8508936b610b1ccd9b5d0a,
```

## D.2. Thin VRF Test Vectors

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
58459215c189331d33521ddcb48565d61ce604f6dba881c9736222094d445e15,
6ea33200f135837e4f5ad97f0e940416f0943c114acd2e2405e2776cef169d6f,
-,
-,
9646c575af23c811c5d4691a26121c845b80a3805452c7267c2dbe2110baa6e3,
ba004f4c74f7f55bab8c67d3dc38954d5d6f3155356028541d97b9bbb9762c03,
8f62d23d0275c7fbe1dcb412a6b6740a3626178bf78078892936c1530436d525,
ae6ef1030e985a18f30ad5e126b6847df0700241e72b18c8f818501c31ccd154,
e513476a9044873666202418d73651fb002f592659a04a1b711b958d2dba1110,
```

### bandersnatch_sha-512_ell2_thin - vector-2

```
dde067b9b5427a0f84877aadd2bddfb3d2778e01c1d58b224ab2bb8d879d3e11,
22a7ef51153fc3fac9af2e12c7cc8b56908d4f07090d91f75eace2998e3bb14e,
0a,
-,
a208afb3b276ef91530ce906abe1e64917b612b6e062a0bb93090c77d9c5ba95,
e7bce7bf0721b64ebfe3586a08f5334c87afa2a7a787230e421b556abe9807db,
1b71fd7287039cdb377fd3eb15792d0e50f2286ceaff7dfb4864341ab607c63e,
ed49d4ebf760ee95593c8dbe5cf52638335513ef40bdddbc4dfadaacb5568857,
69310f568b0fdaa921f4ef313e15895bc7944f3dd818b379f9295cad65af7c1b,
```

### bandersnatch_sha-512_ell2_thin - vector-3

```
00789d0d6efefcab4b2915ec93a09ff3ce4556ae876ab476cd9d984b277d2d13,
6dd61b52fefddbf756af8b6119926626911a029f8afb288a21fb2e3b17687cde,
-,
0b8c,
9646c575af23c811c5d4691a26121c845b80a3805452c7267c2dbe2110baa6e3,
951fc558e4cee0e02f1bf6e4c95b12e3d5101b5e2e4ec9635443943cf58e9d83,
91069a31fb87cca70398eb4206c5ea408b167a5ed7ca1d68f5ecf1666c0c7954,
7f58733f2e19fbb9f9b89520df86a331b1581240a923002ee07f550b2feb3e34,
f6eb44921e68b8d3a525d5a72f01ae994564fd9e914a0494e9f46465633a500f,
```

### bandersnatch_sha-512_ell2_thin - vector-4

```
6533eb80a6539841c34abbc41e0579445816104e2acbd25a28f94a9a81bd7318,
fcac843725cc94efb96909a688d24c0019177d94b39154a42b1b654dce45d36d,
73616d706c65,
-,
f534e99a16886cb60e3672a9bcd65b57ec8a76a3d3f005850e9b38ea17d81636,
d7d3b99dbdef1e16fa1ca992dac684686cf4b16c5a3ed39fd353cd049337c9c6,
2fa4933f445d9b3e6eec45bd35f56a40ca18d6f385e8f7d50981aeab63f2b818,
9aad12b98afc797e179a633a28edfcab6fe0fb744e681697abefbbf544c5a2c5,
0a6e62617c370eb693fffc1132033535d782830f7bdd0440eebd42d8092df604,
```

### bandersnatch_sha-512_ell2_thin - vector-5

```
0e5e44de0eae0fbe819d5a2f8b913dc428e3f5486ec7188627f80d927009ca05,
f2743329156635b8f95586bcfa1c2704044fa62af7c8d0a5e51d2cb9397cefbd,
42616e646572736e6174636820766563746f72,
-,
47a25c71b9fccb60c72c2f5f9851df8594a9d346cda259dcef6ab5e6e441b795,
6c558345591f2d52eba804ff1bab56c9fa4bac85ab661b16b2c68a891954e4ce,
671ed2923f25bc913b1905c026412876297b2736fe056376b0e4af800ad10958,
27403edaf7416f82efbf7785238fda9830bfebd6eabf77fead8ebf5a28c9b49a,
14a8186950b832c33f6052ceff0ea5f190cb87dd65490060c479f5cf0264ab02,
```

### bandersnatch_sha-512_ell2_thin - vector-6

```
0e5e44de0eae0fbe819d5a2f8b913dc428e3f5486ec7188627f80d927009ca05,
f2743329156635b8f95586bcfa1c2704044fa62af7c8d0a5e51d2cb9397cefbd,
42616e646572736e6174636820766563746f72,
1f42,
47a25c71b9fccb60c72c2f5f9851df8594a9d346cda259dcef6ab5e6e441b795,
6c558345591f2d52eba804ff1bab56c9fa4bac85ab661b16b2c68a891954e4ce,
671ed2923f25bc913b1905c026412876297b2736fe056376b0e4af800ad10958,
24fdc20c0d1cb8b4f483f8698be009ccfd0af0cc984eb5020103ca8e7948e3c9,
41f8e56ae6771dfdfac8a90e9df08d553c434b3ec51d6d5569d81c3f0f685012,
```

### bandersnatch_sha-512_ell2_thin - vector-7

```
8b776a316d705cfb06421427e66d1e94fa3744a2a2c4a091a90b84a272dc8216,
b234d14dd177bd490ac2c73f3c2ae69bc3c4189f18f6dfdeade33cd5c06b6d89,
42616e646572736e6174636820766563746f72,
1f42,
47a25c71b9fccb60c72c2f5f9851df8594a9d346cda259dcef6ab5e6e441b795,
12ac0121bf3b2662596c88f0df13cf947911815fc794dd241db2f35ba2b5edbf,
90c458cf7f33035689ea4b60df842a51bbc5f3c42112023e0b2e03fa617939bc,
8c7939699fc35c5210492bbf43c8ad1ae8c490a4f8bf0ef7f1e2a9c76b347abb,
40e4e19eb70c38f95befc631ec7fc17c4854738826487a202843d54cbb138107,
```

## D.3. Pedersen VRF Test Vectors

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
58459215c189331d33521ddcb48565d61ce604f6dba881c9736222094d445e15,
6ea33200f135837e4f5ad97f0e940416f0943c114acd2e2405e2776cef169d6f,
-,
-,
9646c575af23c811c5d4691a26121c845b80a3805452c7267c2dbe2110baa6e3,
ba004f4c74f7f55bab8c67d3dc38954d5d6f3155356028541d97b9bbb9762c03,
8f62d23d0275c7fbe1dcb412a6b6740a3626178bf78078892936c1530436d525,
7abefc4102497859386be56a691ccffd8facf713cb9714391022dde0f9b2890f,
a5a5017dd9a0a18173a53877c65029524d66b15baf8e527731e9637627c4f003,
04256d42c11c285e1b6dc209e90da8f215cb21ab67fca25fba5a9766ec219b1d,
0f09d6ffedfbd504e1d181cb318051760bbd6ac6981a50cad0bee10eb529ba58,
0f87aa28fa80465ca0dc0aa8791c33f47da3190623168dfd3ef398feb7861008,
359161b3ba2052b7a5ddbfb317c616c83e2a55211d004daf9e98377f7525a608,
```

### bandersnatch_sha-512_ell2_pedersen - vector-2

```
dde067b9b5427a0f84877aadd2bddfb3d2778e01c1d58b224ab2bb8d879d3e11,
22a7ef51153fc3fac9af2e12c7cc8b56908d4f07090d91f75eace2998e3bb14e,
0a,
-,
a208afb3b276ef91530ce906abe1e64917b612b6e062a0bb93090c77d9c5ba95,
e7bce7bf0721b64ebfe3586a08f5334c87afa2a7a787230e421b556abe9807db,
1b71fd7287039cdb377fd3eb15792d0e50f2286ceaff7dfb4864341ab607c63e,
74880bfba82106371a1e4ffb26855c370d8e75c1dc7af04e68cdc34d6967cd17,
0111db0a02c1ea1ab70907e1f26d448204f782ad8cb3084c7081181fe967544a,
b73c803568904e344d972342f277b3e9379750bb858b8f418ecf6a8c26dce38a,
58deda6f12ff8eb9116d70d14a37f4964d932893901a20ab8f35f5d6faf048a9,
4393556d2f74a2deddfd5656f2b0b8ba69e22dfa136aecbb5d9ed92fe248cf12,
0b2fdc1dff9ad709dd071e3b72c80bdb724400f8935ab8615771db0c4d1dfb07,
```

### bandersnatch_sha-512_ell2_pedersen - vector-3

```
00789d0d6efefcab4b2915ec93a09ff3ce4556ae876ab476cd9d984b277d2d13,
6dd61b52fefddbf756af8b6119926626911a029f8afb288a21fb2e3b17687cde,
-,
0b8c,
9646c575af23c811c5d4691a26121c845b80a3805452c7267c2dbe2110baa6e3,
951fc558e4cee0e02f1bf6e4c95b12e3d5101b5e2e4ec9635443943cf58e9d83,
91069a31fb87cca70398eb4206c5ea408b167a5ed7ca1d68f5ecf1666c0c7954,
b59661230b43692d4d7a95b29f00397573409abebb208de268fa5e0d6f6be714,
0be163d9317188fa77130bc06456a209900ea52cd511e4077f4f989c0b8f5910,
14f6b03b13aef7c33370dc6ad3e6ec0150e63dbcb2108b1d369b229b5a443705,
24e6c09d9e1c48591cfaeebeb6e4c0fa02868e8a820c1b616b0fc19306ce89b3,
b940cddffcd79940e6ea4dcb1072417f5fe7171d625af7956547fc65fabcee02,
466f582202e921fdacf0a259861b370bb466a7eacf4863c8229fca1f63ee7e17,
```

### bandersnatch_sha-512_ell2_pedersen - vector-4

```
6533eb80a6539841c34abbc41e0579445816104e2acbd25a28f94a9a81bd7318,
fcac843725cc94efb96909a688d24c0019177d94b39154a42b1b654dce45d36d,
73616d706c65,
-,
f534e99a16886cb60e3672a9bcd65b57ec8a76a3d3f005850e9b38ea17d81636,
d7d3b99dbdef1e16fa1ca992dac684686cf4b16c5a3ed39fd353cd049337c9c6,
2fa4933f445d9b3e6eec45bd35f56a40ca18d6f385e8f7d50981aeab63f2b818,
8253f88e6595775230f44129f1ad7ae74279c317033903b65ce7f460f99ed803,
4a1f2a6ffea1374c277faad979c56da18b855cf95fe338523cd45841d138d81b,
302664d0483469eabf9408672d8a6d243a2960ef117e203b6c57a8e9112f86e8,
c8f76d70d11fc6fbe99e60b23c90fe6c332281f58734dbaf153e1e6149881a1b,
bb7bd610195d1a7bb221369cabecb9805fe48c95e849e89df530693998407504,
a1703ba1516b708505a3140bcd419e90b3f74562efa042393f9b005259a55b0d,
```

### bandersnatch_sha-512_ell2_pedersen - vector-5

```
0e5e44de0eae0fbe819d5a2f8b913dc428e3f5486ec7188627f80d927009ca05,
f2743329156635b8f95586bcfa1c2704044fa62af7c8d0a5e51d2cb9397cefbd,
42616e646572736e6174636820766563746f72,
-,
47a25c71b9fccb60c72c2f5f9851df8594a9d346cda259dcef6ab5e6e441b795,
6c558345591f2d52eba804ff1bab56c9fa4bac85ab661b16b2c68a891954e4ce,
671ed2923f25bc913b1905c026412876297b2736fe056376b0e4af800ad10958,
7a34979d243ac35a2a75a1539e43a9904bf62e01e2850294699e344a657d4e12,
b27a984c45a103e90d17cae96dc0e7a3641c25088e8daae74485785497149a1d,
1b6d9c8c8e22786977fc76f10c7630175bd0f9a01cff37640dc404661f05ed0e,
a1012ca0a1383b957c7b6d14bbce9cfaa28fe86cef2363df213bd368ec66f50a,
01f4fae1a21b0f26c926751bf26a06874baf8faf987e71ec8bec13411642c00f,
842fabd8aaee6022e02c34e031776d5e1aa4c3741581163254a783e8d787550c,
```

### bandersnatch_sha-512_ell2_pedersen - vector-6

```
0e5e44de0eae0fbe819d5a2f8b913dc428e3f5486ec7188627f80d927009ca05,
f2743329156635b8f95586bcfa1c2704044fa62af7c8d0a5e51d2cb9397cefbd,
42616e646572736e6174636820766563746f72,
1f42,
47a25c71b9fccb60c72c2f5f9851df8594a9d346cda259dcef6ab5e6e441b795,
6c558345591f2d52eba804ff1bab56c9fa4bac85ab661b16b2c68a891954e4ce,
671ed2923f25bc913b1905c026412876297b2736fe056376b0e4af800ad10958,
377a4ddfd0beb8d1a96f8ea27bd0fac50fd4102c9b86815092ae7fec3435cb18,
e57fa4bee5c34eb157c46d758589742607f83409fbd05abd853a3a961d92558e,
460ca337a201841677244d2fe64991dbc7cc7c94aec33b94b26824820088bd33,
001cba6a53f9a185f9aaec2d8dc9532ea803dcd1e7315525e0b299b91df7f3dc,
0602a2b2e75eb0f2c04f81e2c0ade335d1d84902269491fd12aeeb3b739ea512,
03cfe096e78a76664933bb6c1e4c509397142bd1222154e88b2bf3159db3700e,
```

### bandersnatch_sha-512_ell2_pedersen - vector-7

```
8b776a316d705cfb06421427e66d1e94fa3744a2a2c4a091a90b84a272dc8216,
b234d14dd177bd490ac2c73f3c2ae69bc3c4189f18f6dfdeade33cd5c06b6d89,
42616e646572736e6174636820766563746f72,
1f42,
47a25c71b9fccb60c72c2f5f9851df8594a9d346cda259dcef6ab5e6e441b795,
12ac0121bf3b2662596c88f0df13cf947911815fc794dd241db2f35ba2b5edbf,
90c458cf7f33035689ea4b60df842a51bbc5f3c42112023e0b2e03fa617939bc,
03f08a3679d09765326c9f706b07e06abb2ec4b4e6d137d24d84fb8feec63318,
82f2ea4b08a54c7cd9ac06c314bbf4918a2786212ef723738d650a0d941771c3,
3b33f7da409f2df86d35478467b063bc6bfb4de85fb331265faa11145408b54e,
d7b424256e8b38964d22aae8f505d613c3b30f512663b30f16b8c2664a90eb87,
c6919d3724f80a1533d61d4fccc4073fadc109939af4aa608883a8d9dda4fb17,
a2c836e57a791ed9344c781393915158caaaee95fa897e906f7c5a310a44e31b,
```

## D.4. Ring VRF Test Vectors

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
58459215c189331d33521ddcb48565d61ce604f6dba881c9736222094d445e15,
6ea33200f135837e4f5ad97f0e940416f0943c114acd2e2405e2776cef169d6f,
-,
-,
9646c575af23c811c5d4691a26121c845b80a3805452c7267c2dbe2110baa6e3,
ba004f4c74f7f55bab8c67d3dc38954d5d6f3155356028541d97b9bbb9762c03,
8f62d23d0275c7fbe1dcb412a6b6740a3626178bf78078892936c1530436d525,
7abefc4102497859386be56a691ccffd8facf713cb9714391022dde0f9b2890f,
a5a5017dd9a0a18173a53877c65029524d66b15baf8e527731e9637627c4f003,
04256d42c11c285e1b6dc209e90da8f215cb21ab67fca25fba5a9766ec219b1d,
0f09d6ffedfbd504e1d181cb318051760bbd6ac6981a50cad0bee10eb529ba58,
0f87aa28fa80465ca0dc0aa8791c33f47da3190623168dfd3ef398feb7861008,
359161b3ba2052b7a5ddbfb317c616c83e2a55211d004daf9e98377f7525a608,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..6ea33200f135837e4f5ad97f0e940416f0943c114acd2e2405e2776cef169d6f
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
ad967cbeb9ef2750ef5e5ce96a8b2a5421bc6529a3907aee20ea434a495263f5
..a5f09aba4678d917a78ec0be6dc04efa8242efad1856585214d10992aca53680
..d51e99d3cc95dd61c9047cf3b5a75723495677d33c166dc83ed3500ececb618a
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
b71bb08fbfa40cd39e7a5f24cb68e196ad2ad17a21c1d46b412ea832e3122203
..023577b54071753c74b182ceff49f6c49107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..aeb8152d1bd99c3a7a7d03f741d90ab5be45f58dd7c56ab159e8fd5bb71f7c71
..0fca8e0307dd9817c1ceb2560d4909c792ece8e636a6428488f7204e169952c3
..515e3832bfa14a790179ccde5fc1fba0eeb7c8a7ef9822e4154adf38199b14f0
..49d81b6f317d29d8b4d6cef9ea20e67835bb6670bf832cc62071b775333fb209
..18d5d29cad80c7f7b2a9d31e1bd9665fec7c322579890f39e0f9d7d2ab638a67
..9f9df1d0fa6177834fa4476da6e54a6aa5bea2e21aff1edc079110dee3f6f52b
..80b4319f6646d689b59576ae32b55e38f6a9998785988f2f21b41ae3a154af44
..5da3b1dcb7a37e43d7b2669ac412f1cd647ccee3e246f71d4a16f97d4daa3645
..323c3b86fc9b20ad2fac5b7541a744739c2c58b0a1ba116e6d1d49b57918b227
..00d0ceeb5826851cae32cbfa536e35be130493e74bbb91ea0cb06a1c1a969c70
..8950b250b542b8daf5789951e76b5d214f84aaf72e4630fc2e4d8fd105c228cd
..c7ca73340aee967de53a673bdbdbea1f2754a29fe4465c110aa7256310f0fcd9
..dd0214429268b2f3b460ecc0adf85305aa71ed567c6612f0b89a16c2a0fb3a44
..bcaedf65f545ca9633ab32a64a5e92870a8a5b0e8630a4aa0bb778ba795ea06e
..a0b7f268299702401194e8d161550802d0124876167fd5d1d4e683eece8f4f03
..46d35c08e2babf8aadecad9b6985a80e,
```

### bandersnatch_sha-512_ell2_ring - vector-2

```
dde067b9b5427a0f84877aadd2bddfb3d2778e01c1d58b224ab2bb8d879d3e11,
22a7ef51153fc3fac9af2e12c7cc8b56908d4f07090d91f75eace2998e3bb14e,
0a,
-,
a208afb3b276ef91530ce906abe1e64917b612b6e062a0bb93090c77d9c5ba95,
e7bce7bf0721b64ebfe3586a08f5334c87afa2a7a787230e421b556abe9807db,
1b71fd7287039cdb377fd3eb15792d0e50f2286ceaff7dfb4864341ab607c63e,
74880bfba82106371a1e4ffb26855c370d8e75c1dc7af04e68cdc34d6967cd17,
0111db0a02c1ea1ab70907e1f26d448204f782ad8cb3084c7081181fe967544a,
b73c803568904e344d972342f277b3e9379750bb858b8f418ecf6a8c26dce38a,
58deda6f12ff8eb9116d70d14a37f4964d932893901a20ab8f35f5d6faf048a9,
4393556d2f74a2deddfd5656f2b0b8ba69e22dfa136aecbb5d9ed92fe248cf12,
0b2fdc1dff9ad709dd071e3b72c80bdb724400f8935ab8615771db0c4d1dfb07,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..22a7ef51153fc3fac9af2e12c7cc8b56908d4f07090d91f75eace2998e3bb14e
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
803c84c4c73c4b34e0a274a7d41a22910516be3a05a7a182355cd36d208ac09a
..3a4830310b1646d88a80610c008cd0eea8401306d2544f672dc0691ee63d8426
..667156195822e720c3464c1dbce7094802747332a4859a67ea7c56f8ba056871
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
b84523b5f66554448b6faef263c3b9726d95595e50588c36c9d1d9c7b566b64f
..b7d5fd3af4ea40d3346e8df650f316889107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..8ca10c5794c22200053bdd4b878ca9a2081ab3270d1913b6449c9b4fe220cb13
..fa5309b990949d776e8aa9ddfcf94887b7631c44b63af26b5b20308b27c599c5
..6539b433d609451891b78fccf9700e2282d66eaa0804ced0a6b0ccb6bd07d47c
..44c33f0d933640abc261ff2f0c628a7a0cf389d9e41b93cb997d79125f4f5359
..cfe696cd59775c0605940b3386c07889c207801cd0805d97ba69308bbdeeee5d
..8eed8e3e7b5958c70610113b849f073583c288dfcf2ca355dcdc0c3a45745934
..094015bdb8048e9fd215d9f78a162465e05b2d55649b1578cf78da6dbdc2b54a
..9e4e6f7352bb4fff510fe26a2d1a8521c748bf8dbb0a3e6410b6c7ffe4a58b6e
..57b052bb27e0640deda5688d5408d60b9e8fc2b5495baf9062fb8f60f886980b
..c2cc95f922a714244f80c9cd7b09c05684611f19a2de54ed2d0ccdc88815b662
..b151dfb9df778dffd343ec80578557c448ce912a0530d1d25693382d8730db53
..1d89540cb13a72928eb86a1b477d59ce72614fdc277fca42e824e2162aca4e5d
..20495cb66bd7a5474867992bd4ac723ba35143fa341a040bd063dfd2ddce018c
..a916caca01f438f77f61bbedf25362ab2498bc7d7578ba48302b6825bdc9d7fd
..8e09b2d68dea5e1d1f287cccffb85ac3946c725c2fd76d0f8e0a679733796571
..76f7ef5028ae424cdf5fc9e1fa04c991,
```

### bandersnatch_sha-512_ell2_ring - vector-3

```
00789d0d6efefcab4b2915ec93a09ff3ce4556ae876ab476cd9d984b277d2d13,
6dd61b52fefddbf756af8b6119926626911a029f8afb288a21fb2e3b17687cde,
-,
0b8c,
9646c575af23c811c5d4691a26121c845b80a3805452c7267c2dbe2110baa6e3,
951fc558e4cee0e02f1bf6e4c95b12e3d5101b5e2e4ec9635443943cf58e9d83,
91069a31fb87cca70398eb4206c5ea408b167a5ed7ca1d68f5ecf1666c0c7954,
b59661230b43692d4d7a95b29f00397573409abebb208de268fa5e0d6f6be714,
0be163d9317188fa77130bc06456a209900ea52cd511e4077f4f989c0b8f5910,
14f6b03b13aef7c33370dc6ad3e6ec0150e63dbcb2108b1d369b229b5a443705,
24e6c09d9e1c48591cfaeebeb6e4c0fa02868e8a820c1b616b0fc19306ce89b3,
b940cddffcd79940e6ea4dcb1072417f5fe7171d625af7956547fc65fabcee02,
466f582202e921fdacf0a259861b370bb466a7eacf4863c8229fca1f63ee7e17,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..6dd61b52fefddbf756af8b6119926626911a029f8afb288a21fb2e3b17687cde
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
987faec63ecb9ecaff3cdb82794b6ba3ee7db0627be0eb0e53af152c6c7fda11
..ebd8007a3c75f44ec5ad7d5ed4971796adf19676d31b8d8fbf6fa993d22d6c36
..c6a83f3b5451a586a7bd7e9d3b1f1e0261d1cd9d2ac6aae52cfca8532f25c6bf
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
b6586e555ee34dd1897514aea7c6eb041e1f68faac04ca4f5c10bc1488ce8be9
..f5a146ee0cabe5197813a65164d4ef399107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..b7e49cfb7f8a21e00add078252161a90ed3f82a0788e09802443e2f1151f6445
..e81bf15ae3bd747a778895f2d23c802db82a291ad614896f6b8a30c655dc0d1b
..ec6c71059c0ba0c76defdb8dc0a54f683dddfc526933434f4ba9a6a3e4726192
..3987340045426ba2521c18fa20f93b691a8daebbc0d3e4d9726ffe8475601959
..15f53b037d63bebd55004d62c0a94915ab6f19fb2fa83a3e13b693e98b3dad35
..4568c6d7d4cb7ccd98a1c513c304b05b4b66992cd9baee5816f2da10a33f5872
..ee690fdafc4adae006eef2ee44dabe77b96c2962ce6e420e308f64bd3c237733
..91131298a9c501c85a33910bb8e48bc2297bfd9f1a80274d6fa9406532a53a2d
..2e63bdd1a23278c2b1c22af382dc7b246ea7b1123ece1d1b02cbaeb8a9eca43a
..0afd5f0cf2458efd1b759c84583996743f4818d710fc7396f55f55fc1ae4b44b
..989fa4f6ab4e9439f28cfaee80f048d544792c8773741d484eb7f5ffa83a5ece
..233abeaa1a103f92067b6d0f49fecb37081cc4742ad836c36872f9b8e52323a0
..8dfa4ba7c8bbaadda9d3980fe635473eb16a570db43ad8d3ecf87e29e70d745f
..3c095e31f365b89e524a80b495b0bcacc85483a5dfb82fccf1e6e69192847f3c
..b50b477c76392bef70eb5f3915cdc4507dbe8b8518ded2632604c2842d02faa8
..e43c75f437aa1f48ff154be001289ea7,
```

### bandersnatch_sha-512_ell2_ring - vector-4

```
6533eb80a6539841c34abbc41e0579445816104e2acbd25a28f94a9a81bd7318,
fcac843725cc94efb96909a688d24c0019177d94b39154a42b1b654dce45d36d,
73616d706c65,
-,
f534e99a16886cb60e3672a9bcd65b57ec8a76a3d3f005850e9b38ea17d81636,
d7d3b99dbdef1e16fa1ca992dac684686cf4b16c5a3ed39fd353cd049337c9c6,
2fa4933f445d9b3e6eec45bd35f56a40ca18d6f385e8f7d50981aeab63f2b818,
8253f88e6595775230f44129f1ad7ae74279c317033903b65ce7f460f99ed803,
4a1f2a6ffea1374c277faad979c56da18b855cf95fe338523cd45841d138d81b,
302664d0483469eabf9408672d8a6d243a2960ef117e203b6c57a8e9112f86e8,
c8f76d70d11fc6fbe99e60b23c90fe6c332281f58734dbaf153e1e6149881a1b,
bb7bd610195d1a7bb221369cabecb9805fe48c95e849e89df530693998407504,
a1703ba1516b708505a3140bcd419e90b3f74562efa042393f9b005259a55b0d,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..fcac843725cc94efb96909a688d24c0019177d94b39154a42b1b654dce45d36d
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
98e8f01f880ac5e565caebd31b80dc91920984ab67f0bb6cf965b6d0cb3d2c41
..e0bdbd14ebc5098d479e6c4e3c830ec18def5837933b287c75251b85697ce7fe
..717c57a070f3a30ddf51a6cc41cefaaf359ba179061e71787b89fed324a7d18e
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
ad9f62e6d8c6966f7a3a46edb7025fb59b70eaa89f2e9e0c1ee73e8148ba9bb8
..f8fe5ea3fcb750c8df094a33c244a0309107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..b00ba6a7ded541b82a779048597ac2b4b6eda45ad5a5e3bedb8ada068d3ccafa
..0804c21106dd1e862473b81e41231327b301aa5ee114aae3b32b566366eade5d
..6224fbb0984c575078ee52aae51331c328580a2d3ec9813e3a2a0717b3e79936
..7f0dbb02fdef6fb9f75e05bfccc1794be3b3a448f2177350812025d4e929712b
..72821b07a43ae721a95edc20aa3492de85f8d0e7b7f4a4994eac84a40b87ce4f
..f471864db87efc4e005bcc53c4aabc3713944474ab7ba1e3629ac260119f165d
..11ea77dacf7b22613649fdc6c2b986fea5ee4d465c891fcd1686c32f93b9203b
..1db39afbc762a56e23b67ca331bd8f91b4647a60bf8ef76c5d4f671e1c64d920
..a0635302f48be5598e6c2ca300bdd08faed327257721cbd7c1d99bb427ba2820
..981636ccd2f179e78a6ef09ed258d9a6a8f439f6c23f6da3847783ae3886195f
..ae9d847daf3c1b6311b66befcd989f86a920d40222ad9fea894476d7662ec91f
..64d946a55a4c5068036294a54557d2e3381c68f7b9191c7a95765878bec88d77
..50c6ccaba2f960b4aaf8ab9ae23183408eaaa1d757de59aed302f58e75d4e275
..7318cc4aa47b4ffcc8a58ea093a11e7e5bed7e4c4596fd3728fa49c377963d5d
..82f443ec76598f89554729646bf7649c8ca9c79c00374d5dacfc7d8a7711d828
..e607c9b89fb548b2ba4e9aacd824a7bc,
```

### bandersnatch_sha-512_ell2_ring - vector-5

```
0e5e44de0eae0fbe819d5a2f8b913dc428e3f5486ec7188627f80d927009ca05,
f2743329156635b8f95586bcfa1c2704044fa62af7c8d0a5e51d2cb9397cefbd,
42616e646572736e6174636820766563746f72,
-,
47a25c71b9fccb60c72c2f5f9851df8594a9d346cda259dcef6ab5e6e441b795,
6c558345591f2d52eba804ff1bab56c9fa4bac85ab661b16b2c68a891954e4ce,
671ed2923f25bc913b1905c026412876297b2736fe056376b0e4af800ad10958,
7a34979d243ac35a2a75a1539e43a9904bf62e01e2850294699e344a657d4e12,
b27a984c45a103e90d17cae96dc0e7a3641c25088e8daae74485785497149a1d,
1b6d9c8c8e22786977fc76f10c7630175bd0f9a01cff37640dc404661f05ed0e,
a1012ca0a1383b957c7b6d14bbce9cfaa28fe86cef2363df213bd368ec66f50a,
01f4fae1a21b0f26c926751bf26a06874baf8faf987e71ec8bec13411642c00f,
842fabd8aaee6022e02c34e031776d5e1aa4c3741581163254a783e8d787550c,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..f2743329156635b8f95586bcfa1c2704044fa62af7c8d0a5e51d2cb9397cefbd
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
92bfc74e9a3f1902511adf62f0fbf6bdbd5e19a14e66a05f5cb9c9895d865027
..75fde1882864cb3a61d895a3e07f7f708a211bb2d73d5791e3190c68caf958a8
..09a1fa465b64d7533882c4d8d7a63453e2d62797f75bb5168396f33bb6fd460b
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
9872e8978ca6e4b7a9027ae42bd0b9c6dddbae590f0959d9f26767a641a78fe9
..053e2bf368d7b3920311e5660f27877f9107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..93ade5ef4cddb480be7fe2dd9539b5315ac53cd7e46187a076acd8857c1778c9
..7c840679361653d3a3bcfc1708c872b19170d1a3a0b5a577a871abdc21fbb1f4
..d1b33c3dd3e316284d7bfc60b233c85c4bbb8422cde31b598886c14fcd010c1c
..e8d1abf193cdb66f5049a0f44199252bed86d0f3c456f66cae900b0094676447
..51a2fe713aac04f5cbf0de8446cf07f9ec13232995db086dc05d40a1650fc43f
..3f4ead659307ad0cf82382e999af792d1dd36e7cb747b0b5895adc43f5b94912
..460cc7f7228091a3b57a57ac00442a5575a6fc8055f4275bd8b782fe58dc3019
..32d4cfbfe37421a6d22b6f9d66fe0b4051ff6b57ae33914e9ea91b7f3efb096e
..462c431de2bc027b877f72193113138525ff7cb8bcf8dc91889b044c0b236b03
..3ca4b685f7e886faa5b0b908f501d2c184031fa09daadd1e645b1de89924d26e
..b55329adb1c1d7ce170e55b402ef74090c2396fee125dc362f591936a29715df
..355053d334da6f01d1ce3cd393d761d2317fb430d832cf19c524a135f8ab3839
..aba1c2117b37cc09060fefee4f380c3cae9a256aaec88d45062a42e149b83bd7
..1e27beef463519b83b7f0e0e7c3c863db8a2743dcb243a091141c579b8cf0fb0
..b36e4df028ec21b42e30068aed30ec91d69a1a470cefe15dc3b8ae33e3f7b68f
..9395c0801c06834e2be1c2ae08f58c04,
```

### bandersnatch_sha-512_ell2_ring - vector-6

```
0e5e44de0eae0fbe819d5a2f8b913dc428e3f5486ec7188627f80d927009ca05,
f2743329156635b8f95586bcfa1c2704044fa62af7c8d0a5e51d2cb9397cefbd,
42616e646572736e6174636820766563746f72,
1f42,
47a25c71b9fccb60c72c2f5f9851df8594a9d346cda259dcef6ab5e6e441b795,
6c558345591f2d52eba804ff1bab56c9fa4bac85ab661b16b2c68a891954e4ce,
671ed2923f25bc913b1905c026412876297b2736fe056376b0e4af800ad10958,
377a4ddfd0beb8d1a96f8ea27bd0fac50fd4102c9b86815092ae7fec3435cb18,
e57fa4bee5c34eb157c46d758589742607f83409fbd05abd853a3a961d92558e,
460ca337a201841677244d2fe64991dbc7cc7c94aec33b94b26824820088bd33,
001cba6a53f9a185f9aaec2d8dc9532ea803dcd1e7315525e0b299b91df7f3dc,
0602a2b2e75eb0f2c04f81e2c0ade335d1d84902269491fd12aeeb3b739ea512,
03cfe096e78a76664933bb6c1e4c509397142bd1222154e88b2bf3159db3700e,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..f2743329156635b8f95586bcfa1c2704044fa62af7c8d0a5e51d2cb9397cefbd
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
92bfc74e9a3f1902511adf62f0fbf6bdbd5e19a14e66a05f5cb9c9895d865027
..75fde1882864cb3a61d895a3e07f7f708a211bb2d73d5791e3190c68caf958a8
..09a1fa465b64d7533882c4d8d7a63453e2d62797f75bb5168396f33bb6fd460b
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
b54aa2fec0c75418fdc3ec0a03674011796fe8cbdd2cd226f8ce6f7936b5919d
..24dd580faa6b38d899e5ed74d68499d39107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..8252a1a73f21c9b93c99fcabc47b780e881700a33fa80301f7b0f93e0e8bc376
..bfe3718f19596c73747538c3e8acd598a7a82db2f3dc20ba992c8e64b791c2cb
..cc11a40878f5706542dd685030188e35b1f5e9eb60f95c4f58a1dab957a7d263
..4810c42ed87bb9e710d2e27853f0ddbac9215c2dda780a07b8f4c6b30a389b1b
..92d261a70827a4c1278c6e7408d08152e641856565024fbc15a919f6d1037123
..8a91a3a771e7c9ca11b5754e2e5d07240c4184fa072e67d60a64ce2169c7c53d
..a786c11ffbe554edfea43330da1c30f92f90f7e8c53b0a3caab184ef8cc3cf47
..974b899eb3013c209c710207ee145acedf034ab53dd59690b8d7ec8bfb61eb16
..4827a4f23d6ae348c43f7ffaa30ac397af7be220a9742b38af5fcd02c93b4127
..ba2563c316d80bc234b5da6f41f5a21ca81a7143c9d0cafa1b834aa16f8ca865
..979098c491cf79c425e4f2857aca45354b7f940db516318426459119c6bb8a6c
..834629f84102933a32aaa194f4a887177db3b71f658a82c93449ff1808e30ba8
..9741fa8718db154104080cb572d02f64911d3823924057df1ad406a82e335a05
..e4fde69a3336c604878ee00f4998a9737685d890bacc86bcb9c5f01487f81eaf
..b625c6f07305bb2786d6a690c1fee4851ea10218a2909766c79af2c369098429
..c68b0cdc858ffdb77cee2ccd4da38032,
```

### bandersnatch_sha-512_ell2_ring - vector-7

```
8b776a316d705cfb06421427e66d1e94fa3744a2a2c4a091a90b84a272dc8216,
b234d14dd177bd490ac2c73f3c2ae69bc3c4189f18f6dfdeade33cd5c06b6d89,
42616e646572736e6174636820766563746f72,
1f42,
47a25c71b9fccb60c72c2f5f9851df8594a9d346cda259dcef6ab5e6e441b795,
12ac0121bf3b2662596c88f0df13cf947911815fc794dd241db2f35ba2b5edbf,
90c458cf7f33035689ea4b60df842a51bbc5f3c42112023e0b2e03fa617939bc,
03f08a3679d09765326c9f706b07e06abb2ec4b4e6d137d24d84fb8feec63318,
82f2ea4b08a54c7cd9ac06c314bbf4918a2786212ef723738d650a0d941771c3,
3b33f7da409f2df86d35478467b063bc6bfb4de85fb331265faa11145408b54e,
d7b424256e8b38964d22aae8f505d613c3b30f512663b30f16b8c2664a90eb87,
c6919d3724f80a1533d61d4fccc4073fadc109939af4aa608883a8d9dda4fb17,
a2c836e57a791ed9344c781393915158caaaee95fa897e906f7c5a310a44e31b,
8b3031022897595ba3a280d6af047a46498f6fbfd62081d1df6a2e4b713014df
..bd7fcb7c0956648c043bc345a8fb3e1a2c73815bf87f6c3cb985a00c9e95e991
..307d3bef5e82f857b97f987da190e5fc6d77a9d24ac2068b701df1ab0487a1d8
..b234d14dd177bd490ac2c73f3c2ae69bc3c4189f18f6dfdeade33cd5c06b6d89
..72ce1e7899c633b92709702bdfbe74347d9bdcd1ad62b13f960ade3d1df899b3
..73154c7a701d5d6d38216c4be09800c024c35e4739e43f2b7aa5e0b55a281757
..a4cc78b2e3eb6a19a777ff20bb801c043f73d836aab81038e286560e260922b4
..0c5335e7855f8a38e9ffada8eadb2415f82b5822319fa53b66ef1c0469048ec3,
90f6b9cc6ebe834f4c605f64343425096401ad2cdd6c6f993bc7dd1cfac9a6e4
..d780f9e7cee1603dfde4a64c0e001cb5a2a6af6f6c4ded1489c127dc324f4aea
..169fe0a0a55859c636c05affe64a9cfb118763c8283076676772d84a17ea00e5
..92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29
..fe0e9c85ec450505dde7f5ac038274cf,
ab6d158a162f67abdf4b9cc361619a1b3a148d5468364bc1394f757723110012
..f1f214f5b5409f1131d32e408f7042849107bd20fe94a01157764aab5f300d7e
..2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd
..a4a1a024cf58406e2dce3dd2be4eabc6ce845636ba8c08466eb73ff4c34d29a4
..d978d0232ca7a19a9b40905693282ab7afe3c68f82588662aa24870e2b87f407
..76e9306aca5e92e570a446758e47f7022345ee123172e382a03800df9e4be6cc
..13e2188011e1fe613a6af4f1b2472c0074cf570b5dca97abd26e603d7a2c003a
..743f2f6aebd7c9f07167d69a8dfc18ac5a52454ce9915d8f7567d0f6e5c5a926
..0d0c65b188f1f1fa0a0ea62805704d693252a88ee5a6dcc83b08d858810e653a
..cb92141b7a263d6c6c7439d96779a8d1f6ddc1d0d045e182ca3cff723c6ac152
..b057a13feda59864920594b7e664293d40b7a7a30b5aa0958bcc14a54c75b040
..f4da3e3be69662d1066cc518181c1dc5fc84e933b3aa619151f2ddb683285120
..a50cc98b95647cbb9926dd4c544f1f0e3133b3cfd1f97be4ead9f5aef5272556
..aaf9b7444d60debc71f97a049b9d8eb11dba91877be41f30f0fb64ff172cf2a5
..83014518f8155d893f471acf7305804f6d2fc6b94803eef7bf55a91c16fb5794
..23385bd285d8a0515bf6b2bdb0541d5c934fac62ac8f17ab75cb588cd64b289c
..80f770de9d7a4b6a9f04ed31d5e3be10e70bf03afb4d1f98014221228ae11461
..a805a0bbc3df00f2f771296a50fcd3c181c06b644fcd8c3967ec2c598e42b640
..a22eb21c2cd740d3a2b009c3f9f735c9,
```

# References

[RFC-9380]: <https://datatracker.ietf.org/doc/rfc9380>
[RFC-9381]: <https://datatracker.ietf.org/doc/rfc9381>
[RFC-6234]: <https://datatracker.ietf.org/doc/rfc6234>
[BCHSV23]: <https://eprint.iacr.org/2023/002>
[MSZ21]: <https://eprint.iacr.org/2021/1152>
[VG24]: <https://github.com/davxy/ring-proof-spec>
