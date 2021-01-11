#![allow(non_snake_case)]

use schnorrkel::{self, musig, Keypair, Signature};

fn main() {
    let (x1, x2) = (Keypair::generate(), Keypair::generate());

    let ctx = schnorrkel::signing_context(b"this signature does this thing");
    let ctx_msg: &[u8] = "This is a test of the tsunami alert system.".as_bytes();

    // commit
    let mut ms1 = x1.musig(ctx.bytes(ctx_msg));

    //let R1 = ms1.our_commitment();
    //println!("R1({}): {:?}", R1.0.len(), R1);

    let mut ms2 = x2.musig(ctx.bytes(ctx_msg));

    //let R2 = ms2.our_commitment();
    //println!("R2({}): {:?}", R2.0.len(), R2);

    ms1.add_their_commitment(x2.public.clone(), ms2.our_commitment())
        .unwrap();
    ms2.add_their_commitment(x1.public.clone(), ms1.our_commitment())
        .unwrap();

    //println!("X: {:?}",ms1.public_key());
    //println!("X: {:?}",ms2.public_key());

    // reveal
    let mut ms1 = ms1.reveal_stage();
    let mut ms2 = ms2.reveal_stage();

    let R1 = ms1.our_reveal().to_owned();
    let R2 = ms2.our_reveal().to_owned();
    //println!("R1: {:?}",ms1.our_reveal().0);

    ms1.add_their_reveal(x2.public.clone(), ms2.our_reveal().clone())
        .unwrap();
    ms2.add_their_reveal(x1.public.clone(), ms1.our_reveal().clone())
        .unwrap();

    println!("X: {:?}", ms1.public_key());
    println!("X: {:?}", ms2.public_key());

    let transcript = ms1.transcript().clone();

    let mut ms1 = ms1.cosign_stage();
    let mut ms2 = ms2.cosign_stage();

    let co_sig1 = ms1.our_cosignature();
    let co_sig2 = ms2.our_cosignature();

    ms1.add_their_cosignature(x2.public.clone(), ms2.our_cosignature())
        .unwrap();
    ms2.add_their_cosignature(x1.public.clone(), ms1.our_cosignature())
        .unwrap();

    let sig1 = ms1.sign().unwrap();
    let sig2 = ms2.sign().unwrap();
    println!("sig1: {:?}", sig1);
    println!("sig2: {:?}", sig2);

    let mut collector = musig::collect_cosignatures(transcript.clone());

    collector.add(x1.public.clone(), R1, co_sig1).unwrap();
    collector.add(x2.public.clone(), R2, co_sig2).unwrap();

    let sig = collector.signature();
    println!("sig: {:?}", sig);

    let X = ms1.public_key();
    let mut T = vec![transcript.clone()];

    // corrupt the sig
    //let sig = {
    //    let mut s = sig.to_bytes();
    //    s[0] = 0x12;
    //    Signature::from_bytes(&s).unwrap()
    //};

    schnorrkel::verify_batch_deterministic(&mut T, &[sig], &[X], false).unwrap();
    println!("ok");
}
