use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rsa::{
    pkcs1v15,
    signature::{Keypair, Signer, Verifier},
    RsaPrivateKey
};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

fn rsa_signature_benchmark(c: &mut Criterion) {
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate a key");
    let signing_key = pkcs1v15::SigningKey::<Sha256>::new_unprefixed(private_key);
    let verifying_key = signing_key.verifying_key();
    
    let message = b"Hello, world!";

    let mut hasher = Sha256::new();
    hasher.update(message);
    let hashed_msg = hasher.finalize();

    c.bench_function("RSA Sign", |b| {
        b.iter(|| {
            let signature = signing_key.sign(&hashed_msg);
            black_box(signature);
        });
    });

    c.bench_function("RSA Verify", |b| {
        let signature = signing_key.sign(&hashed_msg);
        b.iter(|| {
            let is_valid = verifying_key.verify(&hashed_msg, &signature).is_ok();
            black_box(is_valid);
        });
    });
}

criterion_group!(benches, rsa_signature_benchmark);
criterion_main!(benches);