use criterion::{black_box, criterion_group, criterion_main, Criterion};
use psionium_ai_threat_detection::detector::ThreatDetector;
use ed25519_dalek::VerifyingKey;

fn bench_detection(c: &mut Criterion) {
    let verifying_key = VerifyingKey::from_bytes(&[0u8; 32]).expect("Invalid verifying key");
    let detector = ThreatDetector::new(verifying_key);
    let features = vec![1.0, 2.0, 1.0];

    c.bench_function("detect", |b| {
        b.iter(|| {
            detector.detect(black_box(&features)).unwrap();
        })
    });
}

criterion_group!(benches, bench_detection);
criterion_main!(benches);