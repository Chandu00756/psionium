use crate::ipc::IpcChannel;
use crate::response::ResponseEngine;
use ed25519_dalek::{SigningKey, Signature, Signer, Verifier};
use log::{error, info};
use psionium_ai_threat_detection::detector::ThreatDetector;
use psionium_crypto_engine::crypto::PsioniumCrypto;
use rand::RngCore;
use rand::thread_rng;
use std::sync::Once;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::task;
use tokio::time::{sleep, Duration};
use tokio::test as tokio_test;

static INIT_LOGGER: Once = Once::new();

fn setup_logger() {
    INIT_LOGGER.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .format_timestamp_micros()
            .init();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio_test]
    async fn test_ipc_send_receive() {
        setup_logger();
        info!("Starting test_ipc_send_receive");

        let mut rng = thread_rng();
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let socket_path = "/tmp/psionium_ipc_test1.sock";
        if std::fs::metadata(socket_path).is_ok() {
            std::fs::remove_file(socket_path).expect("Failed to clean up existing socket");
        }
        let listener = UnixListener::bind(socket_path).expect("Failed to bind to socket");
        info!("Listener bound to socket");

        let mut ipc = IpcChannel::new(verifying_key, socket_path).await.expect("Failed to initialize IpcChannel");
        info!("IpcChannel initialized");

        let data = b"Classified Test Message: Operation Enigma";
        let signature = signing_key.sign(data);

        let verifying_key_clone = verifying_key;
        let listener_task = task::spawn(async move {
            info!("Listener task started");
            let (mut stream, _) = listener.accept().await.expect("Failed to accept connection");
            info!("Listener accepted connection");
            let mut buffer = vec![0u8; 1024];
            let n = stream.read(&mut buffer).await.expect("Failed to read from stream");
            buffer.truncate(n);
            info!("Listener read {} bytes", n);

            if buffer.len() < 64 {
                error!("Received data too short for signature: {} bytes", buffer.len());
                return;
            }

            let (received_data, sig_bytes) = buffer.split_at(buffer.len() - 64);
            let signature_bytes: [u8; 64] = sig_bytes.try_into().unwrap();
            let signature = Signature::from_bytes(&signature_bytes);
            if verifying_key_clone.verify(received_data, &signature).is_err() {
                error!("Signature verification failed in listener");
                return;
            }

            stream.write_all(&buffer).await.expect("Failed to write back to stream");
            stream.flush().await.expect("Failed to flush stream");
            info!("Listener wrote response back");
        });

        info!("Sending data via IPC");
        let send_result = ipc.send_response(data, &signature.to_bytes()).await;
        assert!(send_result.is_ok(), "Failed to send data via IPC: {:?}", send_result.err());
        info!("Data sent successfully");

        info!("Receiving response via IPC");
        let received_data = ipc.receive_response().await;
        assert!(received_data.is_ok(), "Failed to receive data via IPC: {:?}", received_data.err());
        let received = received_data.unwrap();
        assert_eq!(received, data, "Received data does not match sent data: {:?} vs {:?}", received, data);
        info!("Response received successfully");

        info!("Government-grade IPC send/receive test passed successfully");

        listener_task.await.expect("Listener task failed");
        if std::fs::metadata(socket_path).is_ok() {
            std::fs::remove_file(socket_path).expect("Failed to remove socket file");
        }
        info!("Test cleanup completed");
    }

    #[tokio_test]
    async fn test_handle_threat_success() {
        setup_logger();
        info!("Starting test_handle_threat_success");

        let mut rng = thread_rng();
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let socket_path = "/tmp/psionium_ipc_test2.sock";
        if std::fs::metadata(socket_path).is_ok() {
            std::fs::remove_file(socket_path).expect("Failed to clean up existing socket");
        }
        let listener = UnixListener::bind(socket_path).expect("Failed to bind to socket");
        info!("Listener bound to socket");

        let verifying_key_clone = verifying_key;
        let listener_task = task::spawn(async move {
            info!("Listener task started");
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    info!("Listener accepted connection");
                    let mut buffer = vec![0u8; 1024];
                    match stream.read(&mut buffer).await {
                        Ok(n) => {
                            buffer.truncate(n);
                            info!("Listener read {} bytes", n);

                            if buffer.len() < 64 {
                                error!("Received data too short for signature: {} bytes", buffer.len());
                                return;
                            }

                            let (received_data, sig_bytes) = buffer.split_at(buffer.len() - 64);
                            let signature_bytes: [u8; 64] = sig_bytes.try_into().unwrap();
                            let signature = Signature::from_bytes(&signature_bytes);
                            if verifying_key_clone.verify(received_data, &signature).is_err() {
                                error!("Signature verification failed in listener");
                                return;
                            }

                            stream.write_all(&buffer).await.expect("Failed to write back to stream");
                            stream.flush().await.expect("Failed to flush stream");
                            info!("Listener wrote response back");
                        }
                        Err(e) => error!("Failed to read from stream: {}", e),
                    }
                }
                Err(e) => error!("Failed to accept connection: {}", e),
            }
        });

        // Wait briefly to ensure listener is bound
        sleep(Duration::from_millis(10)).await;
        info!("Creating ResponseEngine after listener is ready");

        let crypto = PsioniumCrypto::new().expect("Crypto initialization failed");
        let detector = ThreatDetector::new(verifying_key);
        let engine = ResponseEngine::new(crypto, detector, signing_key).await;
        info!("ResponseEngine initialized");

        let threat_data = vec![15.0, 30.0, 7.0];
        info!("Handling threat with data: {:?}", threat_data);
        let result = engine.handle_threat(1234, &threat_data).await;

        assert!(
            result.is_err(),
            "Expected error due to non-existent process, got {:?}",
            result
        );
        if let Err(e) = result {
            assert!(
                e.to_string().contains("Process termination failed"),
                "Unexpected error: {}",
                e
            );
            info!("Threat handling test passed with expected error: {}", e);
        }

        listener_task.abort();
        if std::fs::metadata(socket_path).is_ok() {
            std::fs::remove_file(socket_path).expect("Failed to remove socket file");
        }
        info!("Test cleanup completed");
    }
}