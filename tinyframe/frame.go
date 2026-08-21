// Package tinyframe 实现与 Rust proto4::tiny_frame 对等的帧编解码。
//
// frame 组成:
//
//	1 byte  header = 5bit message_type | 3bit flags
//	          flags bit0-1 = 压缩算法 (0=无, 1=gzip, 2=deflate)
//	          flags bit2   = ChaCha20-Poly1305 加密 (CHACHA20POLY1305)
//	8 bytes tx_id (big-endian u64)
//	2 bytes 数据包长度 (big-endian u16，指向后续 payload)
//	payload:
//	  若未加密: 压缩后的数据（或原始数据）
//	  若加密:  12-byte nonce || AEAD ciphertext||tag
//	处理顺序: 写 = 先压缩再加密；读 = 先解密再解压。
//	每个包最多一个压缩算法 + 一个加密算法，二者可同时存在。
package tinyframe

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeyLen   = 32
	NonceLen = 12
	tagLen   = 16

	CompressNone    byte = 0x00
	CompressGzip    byte = 0x01
	CompressDeflate byte = 0x02
	// ChaCha20Poly1305 可与压缩 flags OR 组合。
	ChaCha20Poly1305 byte = 0x04

	messageTypeBits = 5
	messageTypeMask = (1 << messageTypeBits) - 1 // 0x1F
	flagsMask       = 0x07
	compressMask    = 0x03
)

// Frame 为解密+解压后的一帧业务数据。
type Frame struct {
	MessageType byte
	CompressID  byte
	Encrypted   bool
	TxID        uint64
	Data        []byte
}

var (
	encryptKeyMu  sync.Mutex
	encryptKey    *[KeyLen]byte
	encryptKeySet bool
)

// SetEncryptKey 配置全局 ChaCha20-Poly1305 key。
// 重复调用会覆盖先前的 key。
func SetEncryptKey(key *[KeyLen]byte) {
	encryptKeyMu.Lock()
	defer encryptKeyMu.Unlock()
	encryptKey = key
	encryptKeySet = true
}

// ResetEncryptKey 清除已配置的全局 key，仅供测试使用。
func ResetEncryptKey() {
	encryptKeyMu.Lock()
	defer encryptKeyMu.Unlock()
	encryptKey = nil
	encryptKeySet = false
}

func requireEncryptKey() *[KeyLen]byte {
	encryptKeyMu.Lock()
	defer encryptKeyMu.Unlock()
	if !encryptKeySet {
		panic("ENCRYPT_KEY_CHACHA20POLY1305 not configured; call SetEncryptKey first")
	}
	if encryptKey == nil {
		panic("ENCRYPT_KEY_CHACHA20POLY1305 is nil; cannot use ChaCha20Poly1305 encryption")
	}
	return encryptKey
}

func packHeaderByte(messageType, flags byte) (byte, error) {
	if messageType > messageTypeMask {
		return 0, fmt.Errorf("message_type must fit in %d bits, got %d", messageTypeBits, messageType)
	}
	if flags&^flagsMask != 0 {
		return 0, fmt.Errorf("flags must fit in 3 bits, got %#x", flags)
	}
	compressID := flags & compressMask
	switch compressID {
	case CompressNone, CompressGzip, CompressDeflate:
	default:
		return 0, fmt.Errorf("unsupported compress_id: %d", compressID)
	}
	return (messageType << 3) | flags, nil
}

func compressPayload(compressID byte, data []byte) ([]byte, error) {
	switch compressID {
	case CompressNone:
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	case CompressGzip:
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(data); err != nil {
			_ = w.Close()
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case CompressDeflate:
		var buf bytes.Buffer
		w, err := flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(data); err != nil {
			_ = w.Close()
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported compress_id: %d", compressID)
	}
}

func decompressPayload(compressID byte, data []byte) ([]byte, error) {
	switch compressID {
	case CompressNone:
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	case CompressGzip:
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	case CompressDeflate:
		r := flate.NewReader(bytes.NewReader(data))
		defer r.Close()
		return io.ReadAll(r)
	default:
		return nil, fmt.Errorf("unsupported compress_id: %d", compressID)
	}
}

func aeadAAD(header byte, txID uint64) []byte {
	aad := make([]byte, 9)
	aad[0] = header
	binary.BigEndian.PutUint64(aad[1:], txID)
	return aad
}

func encryptPayload(key *[KeyLen]byte, aad, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, NonceLen+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func decryptPayload(key *[KeyLen]byte, aad, payload []byte) ([]byte, error) {
	if len(payload) < NonceLen+tagLen {
		return nil, errors.New("encrypted payload too short")
	}
	nonce := payload[:NonceLen]
	ciphertext := payload[NonceLen:]
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("chacha20poly1305 decrypt failed")
	}
	return plain, nil
}

// WriteFrame 写入一帧。flags = 压缩 id，可与 ChaCha20Poly1305 OR。
// 若设置了加密位，使用全局 key（未配置则 panic）。
func WriteFrame(w io.Writer, messageType byte, txID uint64, data []byte, flags byte) error {
	var key *[KeyLen]byte
	if flags&ChaCha20Poly1305 != 0 {
		key = requireEncryptKey()
	}
	return WriteFrameWithKey(w, messageType, txID, data, flags, key)
}

// WriteFrameWithKey 与 WriteFrame 相同，但加密时使用显式 key（供 SDK 使用，避免全局状态）。
func WriteFrameWithKey(w io.Writer, messageType byte, txID uint64, data []byte, flags byte, key *[KeyLen]byte) error {
	header, err := packHeaderByte(messageType, flags)
	if err != nil {
		return err
	}
	compressID := flags & compressMask
	encrypted := flags&ChaCha20Poly1305 != 0

	payload, err := compressPayload(compressID, data)
	if err != nil {
		return err
	}
	if encrypted {
		if key == nil {
			return errors.New("encryption requires a 32-byte key")
		}
		aad := aeadAAD(header, txID)
		payload, err = encryptPayload(key, aad, payload)
		if err != nil {
			return err
		}
	}
	if len(payload) > 0xffff {
		return errors.New("payload length exceeds uint16 max")
	}

	buf := make([]byte, 0, 1+8+2+len(payload))
	buf = append(buf, header)
	var txBuf [8]byte
	binary.BigEndian.PutUint64(txBuf[:], txID)
	buf = append(buf, txBuf[:]...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, payload...)

	if _, err := w.Write(buf); err != nil {
		return err
	}
	if f, ok := w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

// WriteFramePlain 明文、无压缩写入。
func WriteFramePlain(w io.Writer, messageType byte, txID uint64, data []byte) error {
	return WriteFrame(w, messageType, txID, data, CompressNone)
}

// ReadFrame 读取并解析一帧；自动解密/解压到 Frame.Data。
// 若帧带加密位，使用全局 key（未配置则 panic）。
func ReadFrame(r io.Reader) (*Frame, error) {
	return readFrame(r, nil, true)
}

// ReadFrameWithKey 与 ReadFrame 相同，但解密时使用显式 key。
func ReadFrameWithKey(r io.Reader, key *[KeyLen]byte) (*Frame, error) {
	return readFrame(r, key, false)
}

func readFrame(r io.Reader, key *[KeyLen]byte, useGlobal bool) (*Frame, error) {
	var headerBuf [1]byte
	if _, err := io.ReadFull(r, headerBuf[:]); err != nil {
		return nil, err
	}
	header := headerBuf[0]
	messageType := header >> 3
	flags := header & flagsMask
	compressID := flags & compressMask
	encrypted := flags&ChaCha20Poly1305 != 0

	var txBuf [8]byte
	if _, err := io.ReadFull(r, txBuf[:]); err != nil {
		return nil, err
	}
	txID := binary.BigEndian.Uint64(txBuf[:])

	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))

	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}

	var err error
	if encrypted {
		k := key
		if useGlobal {
			k = requireEncryptKey()
		}
		if k == nil {
			return nil, errors.New("encrypted frame requires a 32-byte key")
		}
		aad := aeadAAD(header, txID)
		payload, err = decryptPayload(k, aad, payload)
		if err != nil {
			return nil, err
		}
	}

	data, err := decompressPayload(compressID, payload)
	if err != nil {
		return nil, err
	}
	return &Frame{
		MessageType: messageType,
		CompressID:  compressID,
		Encrypted:   encrypted,
		TxID:        txID,
		Data:        data,
	}, nil
}
