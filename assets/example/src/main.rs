use ark_vrf::reexports::{
    ark_ec::AffineRepr,
    ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize},
};
use ark_vrf::{pedersen::PedersenSuite, ring::RingSuite, suites::bandersnatch};
use bandersnatch::{
    AffinePoint, BandersnatchSha512Ell2, IetfProof, Input, Output, Public, RingProof,
    RingProofParams, Secret,
};

use hex_literal::hex;
use sp_core::H256;

const RING_SIZE: usize = 1023;

// This is the IETF `Prove` procedure output as described in section 2.2
// of the Bandersnatch VRF specification
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct IetfVrfSignature {
    output: Output,
    proof: IetfProof,
}

// This is the IETF `Prove` procedure output as described in section 4.2
// of the Bandersnatch VRF specification
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct RingVrfSignature {
    output: Output,
    // This contains both the Pedersen proof and actual ring proof.
    proof: RingProof,
}

// "Static" ring proof parameters.
fn ring_proof_params() -> &'static RingProofParams {
    use std::sync::OnceLock;
    static PARAMS: OnceLock<RingProofParams> = OnceLock::new();
    PARAMS.get_or_init(|| {
        use bandersnatch::PcsParams;
        use std::{fs::File, io::Read};
        let manifest_dir =
            std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set");
        let filename = format!("{}/data/zcash-srs-2-11-uncompressed.bin", manifest_dir);
        let mut file = File::open(filename).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        let pcs_params = PcsParams::deserialize_uncompressed_unchecked(&mut &buf[..]).unwrap();
        RingProofParams::from_pcs_params(RING_SIZE, pcs_params).unwrap()
    })
}

// Construct VRF Input Point from arbitrary data (section 1.2)
fn vrf_input_point(vrf_input_data: &[u8]) -> Input {
    Input::new(vrf_input_data).unwrap()
}

// Prover actor.
struct Prover {
    pub prover_idx: usize,
    pub secret: Secret,
    pub ring: Vec<Public>,
}

impl Prover {
    pub fn new(ring: Vec<Public>, prover_idx: usize) -> Self {
        Self {
            prover_idx,
            secret: Secret::from_seed(&prover_idx.to_le_bytes()),
            ring,
        }
    }

    /// VRF output hash.
    pub fn vrf_output(&self, vrf_input_data: &[u8]) -> Vec<u8> {
        let input = vrf_input_point(vrf_input_data);
        let output = self.secret.output(input);
        output.hash()[..32].try_into().unwrap()
    }

    /// Anonymous VRF signature.
    ///
    /// Used for tickets submission.
    pub fn ring_vrf_sign(&self, vrf_input_data: &[u8], aux_data: &[u8]) -> Vec<u8> {
        use ark_vrf::ring::Prover as _;

        let input = vrf_input_point(vrf_input_data);
        let output = self.secret.output(input);

        // Backend currently requires the wrapped type (plain affine points)
        let pts: Vec<_> = self.ring.iter().map(|pk| pk.0).collect();

        // Proof construction
        let params = ring_proof_params();
        let prover_key = params.prover_key(&pts);
        let prover = params.prover(prover_key, self.prover_idx);
        let proof = self.secret.prove(input, output, aux_data, &prover);

        // Output and Ring Proof bundled together (as per section 2.2)
        let signature = RingVrfSignature { output, proof };
        let mut buf = Vec::new();
        signature.serialize_compressed(&mut buf).unwrap();
        buf
    }

    /// Non-Anonymous VRF signature.
    ///
    /// Used for ticket claiming during block production.
    /// Not used with Safrole test vectors.
    pub fn ietf_vrf_sign(&self, vrf_input_data: &[u8], aux_data: &[u8]) -> Vec<u8> {
        use ark_vrf::ietf::Prover as _;

        let input = vrf_input_point(vrf_input_data);
        let output = self.secret.output(input);

        let proof = self.secret.prove(input, output, aux_data);

        // Output and IETF Proof bundled together (as per section 2.2)
        let signature = IetfVrfSignature { output, proof };
        let mut buf = Vec::new();
        signature.serialize_compressed(&mut buf).unwrap();
        buf
    }
}

type RingCommitment = ark_vrf::ring::RingCommitment<BandersnatchSha512Ell2>;

// Verifier actor.
struct Verifier {
    pub commitment: RingCommitment,
    pub ring: Vec<Public>,
}

impl Verifier {
    fn new(ring: Vec<Public>) -> Self {
        // Backend currently requires the wrapped type (plain affine points)
        let pts: Vec<_> = ring.iter().map(|pk| pk.0).collect();
        let verifier_key = ring_proof_params().verifier_key(&pts);
        let commitment = verifier_key.commitment();
        Self { ring, commitment }
    }

    /// Anonymous VRF signature verification.
    ///
    /// Used for tickets verification.
    ///
    /// On success returns the VRF output hash.
    pub fn ring_vrf_verify(
        &self,
        vrf_input_data: &[u8],
        aux_data: &[u8],
        signature: &[u8],
    ) -> Result<[u8; 32], ()> {
        use ark_vrf::ring::Verifier as _;

        let signature = RingVrfSignature::deserialize_compressed(signature).unwrap();

        let input = vrf_input_point(vrf_input_data);
        let output = signature.output;

        let params = ring_proof_params();

        // The verifier key is reconstructed from the commitment and the constant
        // verifier key component of the SRS in order to verify some proof.
        // As an alternative we can construct the verifier key using the
        // RingProofParams::verifier_key() method, but is more expensive.
        // In other words, we prefer computing the commitment once, when the keyset changes.
        let verifier_key = params.verifier_key_from_commitment(self.commitment.clone());
        let verifier = params.verifier(verifier_key);
        if Public::verify(input, output, aux_data, &signature.proof, &verifier).is_err() {
            println!("Ring signature verification failure");
            return Err(());
        }
        println!("Ring signature verified");

        // This truncated hash is the actual value used as ticket-id/score in JAM
        let vrf_output_hash: [u8; 32] = output.hash()[..32].try_into().unwrap();
        println!(" vrf-output-hash: {}", hex::encode(vrf_output_hash));
        Ok(vrf_output_hash)
    }

    /// Non-Anonymous VRF signature verification.
    ///
    /// Used for ticket claim verification during block import.
    /// Not used with Safrole test vectors.
    ///
    /// On success returns the VRF output hash.
    pub fn ietf_vrf_verify(
        &self,
        vrf_input_data: &[u8],
        aux_data: &[u8],
        signature: &[u8],
        signer_key_index: usize,
    ) -> Result<[u8; 32], ()> {
        use ark_vrf::ietf::Verifier as _;

        let signature = IetfVrfSignature::deserialize_compressed(signature).unwrap();

        let input = vrf_input_point(vrf_input_data);
        let output = signature.output;

        let public = &self.ring[signer_key_index];
        if public
            .verify(input, output, aux_data, &signature.proof)
            .is_err()
        {
            println!("Ring signature verification failure");
            return Err(());
        }
        println!("Ietf signature verified");

        // This is the actual value used as ticket-id/score
        // NOTE: as far as vrf_input_data is the same, this matches the one produced
        // using the ring-vrf (regardless of aux_data).
        let vrf_output_hash: [u8; 32] = output.hash()[..32].try_into().unwrap();
        println!(" vrf-output-hash: {}", hex::encode(vrf_output_hash));
        Ok(vrf_output_hash)
    }
}

macro_rules! measure_time {
    ($func_name:expr, $func_call:expr) => {{
        let start = std::time::Instant::now();
        let result = $func_call;
        let duration = start.elapsed();
        println!("* Time taken by {}: {:?}", $func_name, duration);
        result
    }};
}

fn print_point(name: &str, p: AffinePoint) {
    println!("------------------------------");
    println!("[{name}]");
    println!("X: {}", p.x);
    println!("Y: {}", p.y);
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).unwrap();
    println!("Compressed: 0x{}", hex::encode(buf));
}

fn print_points() {
    println!("==============================");
    print_point("Group Base", AffinePoint::generator());
    print_point("Blinding Base", BandersnatchSha512Ell2::BLINDING_BASE);
    print_point("Ring Padding", BandersnatchSha512Ell2::PADDING);
    print_point("Accumulator Base", BandersnatchSha512Ell2::ACCUMULATOR_BASE);
    println!("==============================");
}

fn main() {
    print_points();

    let mut ring: Vec<_> = (0..RING_SIZE)
        .map(|i| Secret::from_seed(&i.to_le_bytes()).public())
        .collect();
    let prover_key_index = 3;

    // NOTE: any key can be replaced with the padding point
    let padding_point = Public::from(RingProofParams::padding_point());
    ring[2] = padding_point;
    ring[7] = padding_point;


    let bandersnatch_public_keys: [H256; 6] = [
        H256(hex!("ff71c6c03ff88adb5ed52c9681de1629a54e702fc14729f6b50d2f0a76f185b3")),
        H256(hex!("dee6d555b82024f1ccf8a1e37e60fa60fd40b1958c4bb3006af78647950e1b91")),
        H256(hex!("9326edb21e5541717fde24ec085000b28709847b8aab1ac51f84e94b37ca1b66")),
        H256(hex!("0746846d17469fb2f95ef365efcab9f4e22fa1feb53111c995376be8019981cc")),
        H256(hex!("151e5c8fe2b9d8a606966a79edd2f9e5db47e83947ce368ccba53bf6ba20a40b")),
        H256(hex!("2105650944fcd101621fd5bb3124c9fd191d114b7ad936c1d79d734f9f21392e")),
    ];

    let mut ring: Vec<_> = vec![];
    for key in bandersnatch_public_keys.iter() {
        let item = Public::deserialize_compressed_unchecked(&key[..])
                .unwrap_or_else(|_| Public::from(RingProofParams::padding_point()));
        ring.push(item);
    }

    let prover = Prover::new(ring.clone(), prover_key_index);
    let verifier = Verifier::new(ring);

    let vrf_input_data = b"foo";

    //--- Anonymous VRF

    let aux_data = b"bar";

    // Prover signs some data.
    let ring_signature = measure_time! {
        "ring-vrf-sign",
        prover.ring_vrf_sign(vrf_input_data, aux_data)
    };

    // Verifier checks it without knowing who is the signer.
    let ring_vrf_output_hash = measure_time! {
        "ring-vrf-verify",
        verifier.ring_vrf_verify(vrf_input_data, aux_data, &ring_signature).unwrap()
    };

    //--- Non anonymous VRF

    let other_aux_data = b"hello";

    // Prover signs the same vrf-input data (we want the output to match)
    // But different aux data.
    let ietf_signature = measure_time! {
        "ietf-vrf-sign",
        prover.ietf_vrf_sign(vrf_input_data, other_aux_data)
    };

    // Verifier checks the signature knowing the signer identity.
    let ietf_vrf_output_hash = measure_time! {
        "ietf-vrf-verify",
        verifier.ietf_vrf_verify(vrf_input_data, other_aux_data, &ietf_signature, prover_key_index).unwrap()
    };

    // Must match
    assert_eq!(ring_vrf_output_hash, ietf_vrf_output_hash);

    // We don't need to produce a signature to get the vrf output
    let vrf_output_hash = prover.vrf_output(vrf_input_data);
    assert_eq!(vrf_output_hash, ietf_vrf_output_hash);
}
