# Assets

Support files for the Bandersnatch VRF specification.

| Folder | Content |
| --- | --- |
| `vectors/` | Test vectors for the four schemes. |
| `srs/` | KZG reference strings for the ring proof. |
| `example/` | A small Rust program that drives the reference implementation. |

## vectors/

One file per scheme. Each file holds 7 test vectors. Appendix C of
`specification.md` prints the same values and gives the field schema.

| File | Scheme | Spec sections |
| --- | --- | --- |
| `bandersnatch_sha-512_ell2_tiny.json` | Tiny VRF | 2, C.1 |
| `bandersnatch_sha-512_ell2_thin.json` | Thin VRF | 3, C.2 |
| `bandersnatch_sha-512_ell2_pedersen.json` | Pedersen VRF | 4, C.3 |
| `bandersnatch_sha-512_ell2_ring.json` | Ring VRF | 5, C.4 |

All values are hex strings with no `0x` prefix. The `comment` field names the
suite and the vector index.

`ark-vrf` 0.6.0 generates and verifies these files. The four files are
byte-identical to the same-named files in `data/vectors/` of that crate.

In the Pedersen and Ring files, the `blinding` field is the Pedersen blinding
factor of Appendix A.4. That factor is deterministic by design. It differs from
the column blinding of the ring proof, below.

### Ring vectors: the prover runs with no blinding

**WARNING: never disable blinding in production.**

Column blinding makes the ring proof zero-knowledge. The prover sets the highest
three Lagrange coefficients of each witness column, the zk rows, to random
values. Those values differ at each call, so the proof bytes also differ. A
random proof cannot serve as a test vector.

The shipped ring vectors come from a prover with blinding off. The zk rows hold
zeros in place of random values. `ark-vrf` exposes this as
`RingContext::new_without_blinding`. Appendix C.4 of `specification.md` records
the same fact.

The result:

- The proof is deterministic. The same inputs give the same proof bytes.
- The proof is not zero-knowledge. The anonymity that section 5 promises does
  not hold. Treat such a proof as a proof that names its signer.
- The proof is still valid. A verifier with normal parameters for the same ring
  size accepts it. Only the content of the zk rows changes, not the domain
  layout.

A production prover MUST keep blinding on, through `RingContext::new`.

Ring parameters of the vectors: a ring of 8 public keys, with the signer at index
3. The `ring_pks` field holds the 8 keys in that order.

## srs/

KZG structured reference strings over BLS12-381, for the ring proof of section 5.
The parameters come from the Zcash powers of tau ceremony, as section 5 and
Appendix C.4 state:
<https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony>.

| File | G1 powers | Domain | Max ring size | Bytes |
| --- | --- | --- | --- | --- |
| `zcash-srs-2-11-compressed.bin` | 6145 | 2048 | 1791 | 295168 |
| `zcash-srs-2-11-uncompressed.bin` | 6145 | 2048 | 1791 | 590320 |
| `zcash-srs-2-16-compressed.bin` | 196609 | 65536 | 65279 | 9437440 |
| `zcash-srs-2-16-uncompressed.bin` | 196609 | 65536 | 65279 | 18874864 |

Each file also holds 2 G2 powers. A compressed file and its uncompressed
counterpart hold the same parameters. Pick the form that matches the
deserializer. The uncompressed form needs no point decompression at load time,
and the compressed form is half the size.

The `2-11` files are a truncation of the `2-16` files. All four files hold the
same powers of tau.

The name of a file gives the base 2 logarithm of the polynomial domain size.
`ark-vrf` derives the rest in `ring::dom_utils`:

    G1 powers     = 3 * domain + 1
    max ring size = domain - (4 + 253)

The 4 counts three points for blinding plus one point that the proof system
reserves. The 253 bits carry the blinding factor, and 253 is the bit size of the
Bandersnatch scalar field modulus.

Section 5 of `specification.md` fixes the domain size to 2048, so the `2-11`
files match that configuration. The `2-16` files serve larger rings.

## example/

A standalone crate that drives the reference implementation. It belongs to no
workspace, and it is not part of the specification.

    cd example
    cargo run --release

The program prints the group generator, the blinding base, the accumulator base
and the ring padding point. Then it signs one input twice over a ring of 1023
keys, once with the ring VRF and once with the tiny VRF, and it verifies both.
The two paths give the same VRF output hash, and the program asserts it. The ring
holds the padding point at two positions, which shows that a padding point can
replace an unused key.

`example/data/` holds a second copy of the two `2-11` files, because the program
reads the reference string relative to `CARGO_MANIFEST_DIR`.
