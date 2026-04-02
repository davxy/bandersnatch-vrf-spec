# Bandersnatch VRF Specification

This specification defines three Verifiable Random Function with Additional Data
(VRF-AD) schemes -- Tiny VRF, Thin VRF, and Pedersen VRF -- built on a
transcript-based Fiat-Shamir transform with support for multiple input/output
pairs via delinearization. Tiny VRF and Thin VRF are loosely inspired by IETF
ECVRF [RFC-9381]. Pedersen VRF follows the construction introduced by [BCHSV23]
and serves as a building block for anonymized ring signatures based on the ring
proof scheme derived from [CSSV22].

All schemes are instantiated over the Bandersnatch elliptic curve, constructed
over the BLS12-381 scalar field as specified in [MSZ21].

## Test Vectors

* [Tiny](vectors/bandersnatch_ed_sha512_ell2_tiny_vectors.json)
* [Thin](vectors/bandersnatch_ed_sha512_ell2_thin_vectors.json)
* [Pedersen](vectors/bandersnatch_ed_sha512_ell2_pedersen_vectors.json)
* [Ring](vectors/bandersnatch_ed_sha512_ell2_ring_vectors.json)

## References

* [Reference Implementation](https://github.com/davxy/ark-vrf)
* [RFC-9380](https://datatracker.ietf.org/doc/rfc9380)
* [RFC-9381](https://datatracker.ietf.org/doc/rfc9381)
* [BCHSV23](https://eprint.iacr.org/2023/002)
* [CSSV22](https://eprint.iacr.org/2022/1205)
* [MSZ21](https://eprint.iacr.org/2021/1152)
