use schnorrkel::{Keypair, Signature};

fn main() {
    let privkey = Keypair::generate();

    let context = schnorrkel::signing_context(b"this signature does this thing");

    let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();

    let signature: Signature = privkey.sign(context.bytes(message));

    //println!("{:?}",privkey);
    println!("sig: {:?}", signature);

    let pubkey = privkey.public;
    let ok = pubkey.verify(context.bytes(message), &signature).is_ok();
    println!("ok :{}", ok);
}
