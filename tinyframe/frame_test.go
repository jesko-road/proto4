package tinyframe

import (
	"bytes"
	"io"
	"testing"
)

func ensureTestKey(t *testing.T) {
	t.Helper()
	encryptKeyMu.Lock()
	defer encryptKeyMu.Unlock()
	if encryptKeySet {
		return
	}
	var key [KeyLen]byte
	for i := range key {
		key[i] = 0x42
	}
	encryptKey = &key
	encryptKeySet = true
}

func roundtrip(t *testing.T, messageType byte, txID uint64, data []byte, flags byte) {
	t.Helper()
	if flags&ChaCha20Poly1305 != 0 {
		ensureTestKey(t)
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, messageType, txID, data, flags); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	frame, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if frame.MessageType != messageType {
		t.Fatalf("MessageType: got %d want %d", frame.MessageType, messageType)
	}
	if frame.CompressID != flags&compressMask {
		t.Fatalf("CompressID: got %d want %d", frame.CompressID, flags&compressMask)
	}
	if frame.Encrypted != (flags&ChaCha20Poly1305 != 0) {
		t.Fatalf("Encrypted: got %v", frame.Encrypted)
	}
	if frame.TxID != txID {
		t.Fatalf("TxID: got %d want %d", frame.TxID, txID)
	}
	if !bytes.Equal(frame.Data, data) {
		t.Fatalf("Data: got %q want %q", frame.Data, data)
	}
}

func TestPlainRoundtrip(t *testing.T) {
	roundtrip(t, 0x15, 0x1122334455667788, []byte("hello frame"), CompressNone)
}

func TestGzipRoundtrip(t *testing.T) {
	roundtrip(t, 1, 42, []byte("compress me please!!!!"), CompressGzip)
}

func TestDeflateRoundtrip(t *testing.T) {
	data := make([]byte, 256)
	roundtrip(t, 31, ^uint64(0), data, CompressDeflate)
}

func TestEncryptOnlyRoundtrip(t *testing.T) {
	roundtrip(t, 3, 99, []byte("secret payload"), ChaCha20Poly1305)
}

func TestGzipAndEncryptRoundtrip(t *testing.T) {
	roundtrip(t, 7, 12345, []byte("compress then encrypt !!!!!!!!!!!!!!!!"), CompressGzip|ChaCha20Poly1305)
}

func TestDeflateAndEncryptRoundtrip(t *testing.T) {
	data := bytes.Repeat([]byte{1}, 128)
	roundtrip(t, 0, 1, data, CompressDeflate|ChaCha20Poly1305)
}

func TestEmptyPayload(t *testing.T) {
	roundtrip(t, 0, 0, nil, CompressNone)
}

func TestEmptyEncryptedPayload(t *testing.T) {
	roundtrip(t, 0, 0, nil, ChaCha20Poly1305)
}

func TestRejectsOversizedMessageType(t *testing.T) {
	var buf bytes.Buffer
	err := WriteFrame(&buf, 32, 0, []byte("x"), CompressNone)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRejectsTamperedCiphertext(t *testing.T) {
	ensureTestKey(t)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, 1, 7, []byte("secret"), ChaCha20Poly1305); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	raw := buf.Bytes()
	payloadStart := 1 + 8 + 2 + NonceLen
	if len(raw) <= payloadStart {
		t.Fatalf("frame too short: %d", len(raw))
	}
	raw[payloadStart] ^= 0xff
	_, err := ReadFrame(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected decrypt error")
	}
}

func TestWriteFramePlain(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFramePlain(&buf, 2, 9, []byte("plain")); err != nil {
		t.Fatal(err)
	}
	frame, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Encrypted || frame.CompressID != CompressNone {
		t.Fatalf("unexpected flags: %+v", frame)
	}
	if !bytes.Equal(frame.Data, []byte("plain")) {
		t.Fatalf("data: %q", frame.Data)
	}
}

func TestReadTruncated(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader([]byte{0x00}))
	if err == nil {
		t.Fatal("expected EOF")
	}
	if err != io.ErrUnexpectedEOF && err != io.EOF {
		// ReadFull returns UnexpectedEOF for short reads
		if err != io.ErrUnexpectedEOF {
			t.Logf("got err: %v", err)
		}
	}
}
