use crate::error::ProtoError;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use crypto_box::aead::OsRng;
use crypto_box::{PublicKey, SecretKey};
use snow::{Builder, TransportState};
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub const MAX_RPC_MESSAGE_BYTES: usize = 1024 * 1024; // 1 MiB hard cap
pub const MAX_WIRE_FRAME_BYTES: usize = 65_535;
const PLAINTEXT_CHUNK_BYTES: usize = 60_000;
const MAX_CHUNKS_PER_MESSAGE: usize = (MAX_RPC_MESSAGE_BYTES / PLAINTEXT_CHUNK_BYTES) + 2;
const MAX_SEALED_PLAINTEXT_BYTES: usize = 64 * 1024;
const MAX_SEALED_B64_CHARS: usize = ((MAX_SEALED_PLAINTEXT_BYTES + 64) * 4 / 3) + 16;
const REKEY_FRAME_INTERVAL: u64 = 1_024;

/// Constant-time 32-byte equality check (no timing side-channel on static pubkey or SHA-256 comparison).
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[derive(Clone)]
pub struct StaticKeypair {
    pub private: Zeroizing<[u8; 32]>,
    pub public: [u8; 32],
}

pub fn derive_noise_keypair_from_private(
    private_bytes: [u8; 32],
) -> Result<StaticKeypair, ProtoError> {
    let sk = SecretKey::from(private_bytes);
    let public = *sk.public_key().as_bytes();
    Ok(StaticKeypair {
        private: Zeroizing::new(private_bytes),
        public,
    })
}

pub fn generate_noise_keypair() -> Result<StaticKeypair, ProtoError> {
    let params = NOISE_PATTERN
        .parse()
        .map_err(|e| ProtoError::Crypto(format!("invalid noise pattern: {e}")))?;
    let kp = Builder::new(params)
        .generate_keypair()
        .map_err(|e| ProtoError::Crypto(format!("noise keygen failed: {e}")))?;
    let priv_arr: [u8; 32] = kp
        .private
        .as_slice()
        .try_into()
        .map_err(|_| ProtoError::Crypto("unexpected noise private key length".into()))?;
    let pub_arr: [u8; 32] = kp
        .public
        .as_slice()
        .try_into()
        .map_err(|_| ProtoError::Crypto("unexpected noise public key length".into()))?;
    Ok(StaticKeypair {
        private: Zeroizing::new(priv_arr),
        public: pub_arr,
    })
}

/// Generates an ephemeral X25519 keypair for libsodium-compatible sealed boxes
/// (used both for Armed Copy Hijack `pk_capture` challenges and test vectors).
pub fn generate_sealed_box_keypair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let sk = SecretKey::generate(&mut OsRng);
    let pk = *sk.public_key().as_bytes();
    (Zeroizing::new(sk.to_bytes()), pk)
}

/// Encrypts `plaintext` into a libsodium-compatible X25519XSalsa20Poly1305 sealed box (base64).
/// Wire-compatible with GitHub Actions `encrypted_value` and enclave `CompleteCapture`.
pub fn seal_base64(recipient_pubkey_b64: &str, plaintext: &[u8]) -> Result<String, ProtoError> {
    if plaintext.is_empty() || plaintext.len() > MAX_SEALED_PLAINTEXT_BYTES {
        return Err(ProtoError::Crypto(
            "plaintext length out of bounds for sealed box".into(),
        ));
    }
    if recipient_pubkey_b64.len() > 64 {
        return Err(ProtoError::Crypto("public key base64 too long".into()));
    }
    let raw_pk = B64
        .decode(recipient_pubkey_b64)
        .map_err(|_| ProtoError::Crypto("invalid base64 public key".into()))?;
    let pk_arr: [u8; 32] = raw_pk
        .as_slice()
        .try_into()
        .map_err(|_| ProtoError::Crypto("public key must be 32 bytes".into()))?;
    let pk = PublicKey::from(pk_arr);
    let ciphertext = pk
        .seal(&mut OsRng, plaintext)
        .map_err(|_| ProtoError::Crypto("sealed box encryption failed".into()))?;
    Ok(B64.encode(ciphertext))
}

/// Decrypts a base64 libsodium sealed box into a `Zeroizing<Vec<u8>>`, enforcing a strict
/// pre-decode byte cap before base64 allocation (closes H1).
pub fn unseal_base64(
    recipient_secret_key: &[u8; 32],
    sealed_b64: &str,
) -> Result<Zeroizing<Vec<u8>>, ProtoError> {
    if sealed_b64.is_empty() || sealed_b64.len() > MAX_SEALED_B64_CHARS {
        return Err(ProtoError::Crypto(
            "sealed ciphertext exceeds maximum allowed length".into(),
        ));
    }
    let ciphertext = B64
        .decode(sealed_b64)
        .map_err(|_| ProtoError::Crypto("invalid base64 sealed ciphertext".into()))?;
    if ciphertext.len() > MAX_SEALED_PLAINTEXT_BYTES + 64 {
        return Err(ProtoError::Crypto(
            "decoded ciphertext exceeds maximum allowed length".into(),
        ));
    }
    let sk = SecretKey::from(*recipient_secret_key);
    let plaintext = sk
        .unseal(&ciphertext)
        .map_err(|_| ProtoError::Crypto("sealed box decryption failed".into()))?;
    Ok(Zeroizing::new(plaintext))
}

pub fn write_raw_frame<W: Write>(stream: &mut W, payload: &[u8]) -> Result<(), ProtoError> {
    if payload.is_empty() || payload.len() > MAX_WIRE_FRAME_BYTES {
        return Err(ProtoError::Transport("invalid wire frame size".into()));
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| ProtoError::Transport("frame length overflow".into()))?;
    stream
        .write_all(&len.to_be_bytes())
        .map_err(|e| ProtoError::Transport(format!("frame header write failed: {e}")))?;
    stream
        .write_all(payload)
        .map_err(|e| ProtoError::Transport(format!("frame body write failed: {e}")))?;
    stream
        .flush()
        .map_err(|e| ProtoError::Transport(format!("stream flush failed: {e}")))?;
    Ok(())
}

pub fn read_raw_frame<R: Read>(stream: &mut R) -> Result<Vec<u8>, ProtoError> {
    let mut hdr = [0u8; 4];
    stream
        .read_exact(&mut hdr)
        .map_err(|e| ProtoError::Transport(format!("frame header read failed: {e}")))?;
    let len = u32::from_be_bytes(hdr) as usize;
    if len == 0 || len > MAX_WIRE_FRAME_BYTES {
        return Err(ProtoError::Transport(
            "wire frame size out of bounds".into(),
        ));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|e| ProtoError::Transport(format!("frame body read failed: {e}")))?;
    Ok(buf)
}

/// Mutually authenticated `Noise_IK` encrypted session over `AF_VSOCK` or host bridge stream.
pub struct NoiseSession {
    transport: TransportState,
    peer_static_pubkey: [u8; 32],
    tx_frames: u64,
    rx_frames: u64,
}

impl NoiseSession {
    pub fn connect_initiator<S: Read + Write>(
        stream: &mut S,
        client_private: &[u8; 32],
        expected_enclave_pubkey: &[u8; 32],
    ) -> Result<Self, ProtoError> {
        let params = NOISE_PATTERN
            .parse()
            .map_err(|e| ProtoError::Crypto(format!("invalid noise pattern: {e}")))?;
        let mut hs = Builder::new(params)
            .local_private_key(client_private)
            .remote_public_key(expected_enclave_pubkey)
            .build_initiator()
            .map_err(|e| ProtoError::Crypto(format!("initiator init failed: {e}")))?;

        let mut buf = vec![0u8; MAX_WIRE_FRAME_BYTES];
        let n1 = hs
            .write_message(&[], &mut buf)
            .map_err(|e| ProtoError::Crypto(format!("handshake msg1 write failed: {e}")))?;
        write_raw_frame(stream, &buf[..n1])?;

        let msg2 = read_raw_frame(stream)?;
        hs.read_message(&msg2, &mut buf).map_err(|_| {
            ProtoError::Unauthorized("enclave Noise_IK responder authentication failed".into())
        })?;

        let transport = hs
            .into_transport_mode()
            .map_err(|e| ProtoError::Crypto(format!("transport transition failed: {e}")))?;
        Ok(Self {
            transport,
            peer_static_pubkey: *expected_enclave_pubkey,
            tx_frames: 0,
            rx_frames: 0,
        })
    }

    pub fn accept_responder<S: Read + Write>(
        stream: &mut S,
        enclave_private: &[u8; 32],
        authorized_client_pubkey: &[u8; 32],
    ) -> Result<Self, ProtoError> {
        let params = NOISE_PATTERN
            .parse()
            .map_err(|e| ProtoError::Crypto(format!("invalid noise pattern: {e}")))?;
        let mut hs = Builder::new(params)
            .local_private_key(enclave_private)
            .build_responder()
            .map_err(|e| ProtoError::Crypto(format!("responder init failed: {e}")))?;

        let mut buf = vec![0u8; MAX_WIRE_FRAME_BYTES];
        let msg1 = read_raw_frame(stream)?;
        hs.read_message(&msg1, &mut buf).map_err(|_| {
            ProtoError::Unauthorized("Noise_IK initiator handshake decryption failed".into())
        })?;

        let Some(remote_static) = hs.get_remote_static() else {
            return Err(ProtoError::Unauthorized(
                "missing initiator static key".into(),
            ));
        };
        let remote_arr: [u8; 32] = remote_static
            .try_into()
            .map_err(|_| ProtoError::Unauthorized("invalid initiator key length".into()))?;
        if !constant_time_eq_32(&remote_arr, authorized_client_pubkey) {
            return Err(ProtoError::Unauthorized(
                "client static public key is not authorized for this enclave".into(),
            ));
        }

        let n2 = hs
            .write_message(&[], &mut buf)
            .map_err(|e| ProtoError::Crypto(format!("handshake msg2 write failed: {e}")))?;
        write_raw_frame(stream, &buf[..n2])?;

        let transport = hs
            .into_transport_mode()
            .map_err(|e| ProtoError::Crypto(format!("transport transition failed: {e}")))?;
        Ok(Self {
            transport,
            peer_static_pubkey: remote_arr,
            tx_frames: 0,
            rx_frames: 0,
        })
    }

    pub fn peer_static_pubkey(&self) -> &[u8; 32] {
        &self.peer_static_pubkey
    }

    fn step_tx_rekey(&mut self) {
        self.tx_frames = self.tx_frames.saturating_add(1);
        if self.tx_frames.is_multiple_of(REKEY_FRAME_INTERVAL) {
            self.transport.rekey_outgoing();
        }
    }

    fn step_rx_rekey(&mut self) {
        self.rx_frames = self.rx_frames.saturating_add(1);
        if self.rx_frames.is_multiple_of(REKEY_FRAME_INTERVAL) {
            self.transport.rekey_incoming();
        }
    }

    pub fn send_message<W: Write>(
        &mut self,
        stream: &mut W,
        plaintext: &[u8],
    ) -> Result<(), ProtoError> {
        if plaintext.len() > MAX_RPC_MESSAGE_BYTES {
            return Err(ProtoError::Transport(
                "RPC message exceeds 1 MiB cap".into(),
            ));
        }
        let mut wire_buf = vec![0u8; MAX_WIRE_FRAME_BYTES];
        let mut chunk_plain = Zeroizing::new(Vec::with_capacity(PLAINTEXT_CHUNK_BYTES + 1));

        if plaintext.is_empty() {
            chunk_plain.push(0x00);
            let n = self
                .transport
                .write_message(&chunk_plain, &mut wire_buf)
                .map_err(|e| ProtoError::Crypto(format!("noise encrypt failed: {e}")))?;
            self.step_tx_rekey();
            return write_raw_frame(stream, &wire_buf[..n]);
        }

        let chunks: Vec<&[u8]> = plaintext.chunks(PLAINTEXT_CHUNK_BYTES).collect();
        for (idx, part) in chunks.iter().enumerate() {
            chunk_plain.clear();
            let more = u8::from(idx + 1 < chunks.len());
            chunk_plain.push(more);
            chunk_plain.extend_from_slice(part);
            let n = self
                .transport
                .write_message(&chunk_plain, &mut wire_buf)
                .map_err(|e| ProtoError::Crypto(format!("noise encrypt failed: {e}")))?;
            self.step_tx_rekey();
            write_raw_frame(stream, &wire_buf[..n])?;
        }
        Ok(())
    }

    pub fn recv_message<R: Read>(
        &mut self,
        stream: &mut R,
    ) -> Result<Zeroizing<Vec<u8>>, ProtoError> {
        let mut assembled = Zeroizing::new(Vec::new());
        let mut dec_buf = Zeroizing::new(vec![0u8; MAX_WIRE_FRAME_BYTES]);
        let mut chunk_count = 0usize;

        loop {
            chunk_count += 1;
            if chunk_count > MAX_CHUNKS_PER_MESSAGE {
                return Err(ProtoError::Transport(
                    "noise message exceeded maximum chunk count".into(),
                ));
            }
            let ct = read_raw_frame(stream)?;
            let n = self
                .transport
                .read_message(&ct, &mut dec_buf)
                .map_err(|_| ProtoError::Crypto("noise frame authentication failed".into()))?;
            self.step_rx_rekey();
            if n == 0 {
                return Err(ProtoError::Transport("empty noise chunk".into()));
            }
            let more = dec_buf[0];
            let payload = &dec_buf[1..n];
            if more == 0x01 && payload.is_empty() {
                return Err(ProtoError::Transport(
                    "empty continuation noise chunk rejected".into(),
                ));
            }
            if assembled.len().saturating_add(payload.len()) > MAX_RPC_MESSAGE_BYTES {
                return Err(ProtoError::Transport(
                    "assembled RPC message exceeds 1 MiB cap".into(),
                ));
            }
            assembled.extend_from_slice(payload);
            match more {
                0x00 => return Ok(assembled),
                0x01 => continue,
                _ => {
                    return Err(ProtoError::Transport(
                        "invalid chunk continuation flag".into(),
                    ));
                }
            }
        }
    }
}
