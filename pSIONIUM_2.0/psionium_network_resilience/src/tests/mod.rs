use crate::network::secure_channel::SecureChannel;
use crate::network::anomaly_detector::NetworkAnomalyDetector;
use ed25519_dalek::SigningKey;
use psionium_ai_threat_detection::detector::ThreatDetector;
use rand::RngCore;
use rand::thread_rng;
use tokio::test as tokio_test;

#[tokio_test]
async fn test_secure_channel() {
    let mut rng = thread_rng();
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();

    let mut channel = SecureChannel::new(signing_key, verifying_key, "localhost:8080")
        .await
        .expect("Failed to initialize SecureChannel");
    let data = vec![1, 2, 3, 4];
    channel.send(&data).await.expect("Failed to send");
    let received = channel.receive().await.expect("Failed to receive");
    assert_eq!(data, received);
}

#[tokio_test]
async fn test_anomaly_detector() {
    let mut rng = thread_rng();
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();

    let detector = ThreatDetector::new(verifying_key);
    let anomaly_detector = NetworkAnomalyDetector::new(detector, 10);

    let normal_packet = vec![1.0, 2.0, 3.0];
    let anomaly_packet = vec![100.0, 200.0, 300.0];

    let normal_result = anomaly_detector.analyze_packet(normal_packet, 1234567890)
        .await
        .expect("Failed to analyze normal packet");
    let anomaly_result = anomaly_detector.analyze_packet(anomaly_packet, 1234567891)
        .await
        .expect("Failed to analyze anomaly packet");

    assert_eq!(normal_result, false);
    assert_eq!(anomaly_result, true);
}