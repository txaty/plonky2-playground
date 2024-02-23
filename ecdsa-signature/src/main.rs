use anyhow::Result;
use jemallocator::Jemalloc;
use plonky2_ed25519::gadgets::{eddsa::EDDSATargets, nonnative::CircuitBuilderNonNative};
use plonky2_sha512::circuit::{bits_to_biguint_target, make_circuits};

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// EdDSA Signature Verification
// verify_eddsa_signature(msg, pubKey, signature {R, s})
// - Calculate h = hash(R + pubKey + msg) mod q
// - Calculate P1 = s * G
// - Calculate P2 = R + h * pubKey
// - Return P1 == P2
pub fn make_verify_circuits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg_len: usize,
) -> EDDSATargets {
    let msg_len_in_bits = msg_len * 8;
    let sha512_msg_len = msg_len_in_bits + 512;
    let sha512 = make_circuits(builder, sha512_msg_len as u128);

    let mut msg = Vec::new();
    let mut sig = Vec::new();
    let mut pk = Vec::new();
    for i in 0..msg_len_in_bits {
        msg.push(sha512.message[512 + i]);
    }
    for _ in 0..512 {
        sig.push(builder.add_virtual_bool_target_safe());
    }
    for _ in 0..256 {
        pk.push(builder.add_virtual_bool_target_safe());
    }
    for i in 0..256 {
        builder.connect(sha512.message[i].target, sig[i].target);
    }
    for i in 0..256 {
        builder.connect(sha512.message[256 + i].target, pk[i].target);
    }

    let digest_bits = bits_in_le(sha512.digest.clone());
    let hash = bits_to_biguint_target(builder, digest_bits);
    let h = builder.reduce(&hash);

    let s_bits = bits_in_le(sig[256..512].to_vec());
    let s_biguint = bits_to_biguint_target(builder, s_bits);
    let s = builder.biguint_to_nonnative(&s_biguint);
    let sb = fixed_base_curve_mul_circuit(builder, Ed25519::GENERATOR_AFFINE, &s);

    let pk_bits = bits_in_le(pk.clone());
    let a = builder.point_decompress(&pk_bits);
    let ha = builder.curve_scalar_mul_windowed(&a, &h);

    let r_bits = bits_in_le(sig[..256].to_vec());
    let r = builder.point_decompress(&r_bits);
    let rhs = builder.curve_add(&r, &ha);

    builder.connect_affine_point(&sb, &rhs);

    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();

    let (inner_proof, inner_vd, inner_cd) = inner1;
    let pt = builder.add_virtual_proof_with_pis(inner_cd);
    pw.set_proof_with_pis_target(&pt, inner_proof);

    let inner_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
    };
    pw.set_cap_target(
        &inner_data.constants_sigmas_cap,
        &inner_vd.constants_sigmas_cap,
    );

    builder.verify_proof(pt, &inner_data, inner_cd);
    let data = builder.build::<C>();
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    data.verify(proof.clone())?;
}

fn point_decompress<C: Curve>(&mut self, pv: &Vec<BoolTarget>) -> AffinePointTarget<C> {
    assert_eq!(pv.len(), 256);
    let p = self.add_virtual_affine_point_target();

    self.add_simple_generator(CurvePointDecompressionGenerator::<F, D, C> {
        pv: pv.clone(),
        p: p.clone(),
        _phantom: PhantomData,
    });

    let pv2 = self.point_compress(&p);
    for i in 0..256 {
        self.connect(pv[i].target, pv2[i].target);
    }
    p
}

fn main() {
    println!("Hello, world!");
}
