/*
frame 组成:
  1 byte  header = 5bit message_type | 3bit flags
            flags bit0-1 = 压缩算法 (0=无, 1=gzip, 2=deflate)
            flags bit2   = ChaCha20-Poly1305 加密 (CHACHA20POLY1305)
  8 bytes tx_id (big-endian u64)
  2 bytes 数据包长度 (big-endian u16，指向后续 payload)
  payload:
    若未加密: 压缩后的数据（或原始数据）
    若加密:  12-byte nonce || AEAD ciphertext||tag
  处理顺序: 写 = 先压缩再加密；读 = 先解密再解压。
  每个包最多一个压缩算法 + 一个加密算法，二者可同时存在。
*/

use std::io::{self, Read, Write};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use flate2::Compression;
use flate2::read::{DeflateDecoder, GzDecoder};
use flate2::write::{DeflateEncoder, GzEncoder};
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// ChaCha20-Poly1305 加密用的全局 key。
/// 若未 `set_encrypt_key`（或设为 `None`）却使用加密，会 panic。
pub static ENCRYPT_KEY_CHACHA20POLY1305: once_cell::sync::OnceCell<Option<[u8; KEY_LEN]>> =
    once_cell::sync::OnceCell::new();

/// 配置全局加密 key，进程内只应调用一次。
pub fn set_encrypt_key(key: Option<[u8; KEY_LEN]>) {
    ENCRYPT_KEY_CHACHA20POLY1305
        .set(key)
        .expect("ENCRYPT_KEY_CHACHA20POLY1305 already configured");
}

fn require_encrypt_key() -> &'static [u8; KEY_LEN] {
    ENCRYPT_KEY_CHACHA20POLY1305
        .get()
        .expect("ENCRYPT_KEY_CHACHA20POLY1305 not configured; call set_encrypt_key first")
        .as_ref()
        .expect("ENCRYPT_KEY_CHACHA20POLY1305 is None; cannot use CHACHA20POLY1305 encryption")
}

/// 未压缩
pub const COMPRESS_NONE: u8 = 0x00;
/// gzip 压缩算法
pub const COMPRESS_GZIP: u8 = 0x01;
/// deflate 压缩算法
pub const COMPRESS_DEFLATE: u8 = 0x02;
/// ChaCha20-Poly1305 加密；可与压缩 flags OR 组合
pub const CHACHA20POLY1305: u8 = 0x04;

const MESSAGE_TYPE_BITS: u8 = 5;
const MESSAGE_TYPE_MASK: u8 = (1 << MESSAGE_TYPE_BITS) - 1; // 0x1F
const FLAGS_MASK: u8 = 0x07;
const COMPRESS_MASK: u8 = 0x03;

/// 解析后的一帧（`data` 为解密+解压后的业务内容）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub message_type: u8,
    pub compress_id: u8,
    pub encrypted: bool,
    pub tx_id: u64,
    pub data: Vec<u8>,
}

fn pack_header_byte(message_type: u8, flags: u8) -> io::Result<u8> {
    if message_type > MESSAGE_TYPE_MASK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("message_type must fit in {MESSAGE_TYPE_BITS} bits, got {message_type}"),
        ));
    }
    if flags & !FLAGS_MASK != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("flags must fit in 3 bits, got {flags:#x}"),
        ));
    }
    let compress_id = flags & COMPRESS_MASK;
    if !matches!(
        compress_id,
        COMPRESS_NONE | COMPRESS_GZIP | COMPRESS_DEFLATE
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported compress_id: {compress_id}"),
        ));
    }
    Ok((message_type << 3) | flags)
}

fn compress_payload(compress_id: u8, data: &[u8]) -> io::Result<Vec<u8>> {
    match compress_id {
        COMPRESS_NONE => Ok(data.to_vec()),
        COMPRESS_GZIP => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data)?;
            encoder.finish()
        }
        COMPRESS_DEFLATE => {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data)?;
            encoder.finish()
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported compress_id: {other}"),
        )),
    }
}

fn decompress_payload(compress_id: u8, data: &[u8]) -> io::Result<Vec<u8>> {
    match compress_id {
        COMPRESS_NONE => Ok(data.to_vec()),
        COMPRESS_GZIP => {
            let mut decoder = GzDecoder::new(data);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)?;
            Ok(out)
        }
        COMPRESS_DEFLATE => {
            let mut decoder = DeflateDecoder::new(data);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)?;
            Ok(out)
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported compress_id: {other}"),
        )),
    }
}

fn aead_aad(header: u8, tx_id: u64) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[0] = header;
    aad[1..9].copy_from_slice(&tx_id.to_be_bytes());
    aad
}

fn encrypt_payload(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "chacha20poly1305 encrypt failed"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_payload(key: &[u8; KEY_LEN], aad: &[u8], payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() < NONCE_LEN + TAG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "encrypted payload too short",
        ));
    }
    let (nonce_bytes, ciphertext) = payload.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "chacha20poly1305 decrypt failed",
            )
        })
}

/// 写入一帧。`flags` = 压缩 id，可与 `CHACHA20POLY1305` OR。
/// 若设置了加密位，使用全局 `ENCRYPT_KEY_CHACHA20POLY1305`（未配置则 panic）。
pub async fn write_frame<T: AsyncWrite + Unpin + Send>(
    w: &mut T,
    message_type: u8,
    tx_id: u64,
    data: &[u8],
    flags: u8,
) -> io::Result<()> {
    let header = pack_header_byte(message_type, flags)?;
    let compress_id = flags & COMPRESS_MASK;
    let encrypted = flags & CHACHA20POLY1305 != 0;

    let mut payload = compress_payload(compress_id, data)?;
    if encrypted {
        let key = require_encrypt_key();
        let aad = aead_aad(header, tx_id);
        payload = encrypt_payload(key, &aad, &payload)?;
    }

    if payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload length exceeds u16::MAX",
        ));
    }

    let mut buf = Vec::with_capacity(1 + 8 + 2 + payload.len());
    buf.push(header);
    buf.extend_from_slice(&tx_id.to_be_bytes());
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(&payload);

    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// 明文、无压缩写入
pub async fn write_frame_plain<T: AsyncWrite + Unpin + Send>(
    w: &mut T,
    message_type: u8,
    tx_id: u64,
    data: &[u8],
) -> io::Result<()> {
    write_frame(w, message_type, tx_id, data, COMPRESS_NONE).await
}

/// 读取并解析一帧；自动解密/解压到 `Frame::data`。
/// 若帧带加密位，使用全局 `ENCRYPT_KEY_CHACHA20POLY1305`（未配置则 panic）。
pub async fn read_frame<T: AsyncRead + Unpin + Send>(r: &mut T) -> io::Result<Frame> {
    let mut header_buf = [0u8; 1];
    r.read_exact(&mut header_buf).await?;
    let header = header_buf[0];
    let message_type = header >> 3;
    let flags = header & FLAGS_MASK;
    let compress_id = flags & COMPRESS_MASK;
    let encrypted = flags & CHACHA20POLY1305 != 0;

    let mut tx_bytes = [0u8; 8];
    r.read_exact(&mut tx_bytes).await?;
    let tx_id = u64::from_be_bytes(tx_bytes);

    let mut len_bytes = [0u8; 2];
    r.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;

    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload).await?;
    }

    if encrypted {
        let key = require_encrypt_key();
        let aad = aead_aad(header, tx_id);
        payload = decrypt_payload(key, &aad, &payload)?;
    }

    let data = decompress_payload(compress_id, &payload)?;
    Ok(Frame {
        message_type,
        compress_id,
        encrypted,
        tx_id,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    fn ensure_test_key() {
        let _ = ENCRYPT_KEY_CHACHA20POLY1305.set(Some([0x42; KEY_LEN]));
    }

    async fn roundtrip(message_type: u8, tx_id: u64, data: &[u8], flags: u8) {
        if flags & CHACHA20POLY1305 != 0 {
            ensure_test_key();
        }
        let (mut client, mut server): (DuplexStream, DuplexStream) = tokio::io::duplex(64 * 1024);
        write_frame(&mut client, message_type, tx_id, data, flags)
            .await
            .unwrap();
        let frame = read_frame(&mut server).await.unwrap();
        assert_eq!(frame.message_type, message_type);
        assert_eq!(frame.compress_id, flags & COMPRESS_MASK);
        assert_eq!(frame.encrypted, flags & CHACHA20POLY1305 != 0);
        assert_eq!(frame.tx_id, tx_id);
        assert_eq!(frame.data, data);
    }

    #[tokio::test]
    async fn plain_roundtrip() {
        roundtrip(0x15, 0x1122334455667788, b"hello frame", COMPRESS_NONE).await;
    }

    #[tokio::test]
    async fn gzip_roundtrip() {
        roundtrip(1, 42, b"compress me please!!!!", COMPRESS_GZIP).await;
    }

    #[tokio::test]
    async fn deflate_roundtrip() {
        roundtrip(31, u64::MAX, &[0u8; 256], COMPRESS_DEFLATE).await;
    }

    #[tokio::test]
    async fn encrypt_only_roundtrip() {
        roundtrip(3, 99, b"secret payload", CHACHA20POLY1305).await;
    }

    #[tokio::test]
    async fn gzip_and_encrypt_roundtrip() {
        roundtrip(
            7,
            12345,
            b"compress then encrypt !!!!!!!!!!!!!!!!",
            COMPRESS_GZIP | CHACHA20POLY1305,
        )
        .await;
    }

    #[tokio::test]
    async fn deflate_and_encrypt_roundtrip() {
        roundtrip(0, 1, &[1u8; 128], COMPRESS_DEFLATE | CHACHA20POLY1305).await;
    }

    #[tokio::test]
    async fn empty_payload() {
        roundtrip(0, 0, b"", COMPRESS_NONE).await;
    }

    #[tokio::test]
    async fn empty_encrypted_payload() {
        roundtrip(0, 0, b"", CHACHA20POLY1305).await;
    }

    #[tokio::test]
    async fn rejects_oversized_message_type() {
        let (mut client, _server) = tokio::io::duplex(1024);
        let err = write_frame(&mut client, 32, 0, b"x", COMPRESS_NONE)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn rejects_tampered_ciphertext() {
        ensure_test_key();
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        write_frame(&mut client, 1, 7, b"secret", CHACHA20POLY1305)
            .await
            .unwrap();
        drop(client);

        let mut raw = Vec::new();
        server.read_to_end(&mut raw).await.unwrap();
        // header(1) + tx_id(8) + len(2) + nonce(12) + ciphertext...
        let payload_start = 1 + 8 + 2 + NONCE_LEN;
        assert!(raw.len() > payload_start);
        raw[payload_start] ^= 0xff;

        let err = read_frame(&mut raw.as_slice()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
