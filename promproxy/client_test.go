package promproxy

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/jesko-road/proto4/tinyframe"
)

func testKey() [tinyframe.KeyLen]byte {
	var key [tinyframe.KeyLen]byte
	for i := range key {
		key[i] = 0x42
	}
	return key
}

func TestParseSecretKeyHex(t *testing.T) {
	hexKey := "071c9849f90b8caf7b9083bd53817e56d7274dc35796c4206b7fc97caec44dea"
	key, err := ParseSecretKeyHex(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("len=%d", len(key))
	}
}

func TestPrepareRemoteWriteBody(t *testing.T) {
	out := PrepareRemoteWriteBody([]byte("fake-write-request-protobuf"))
	if len(out) == 0 {
		t.Fatal("empty snappy output")
	}
}

func TestRemoteWriteRoundtrip(t *testing.T) {
	key := testKey()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer conn.Close()

		req, err := tinyframe.ReadFrameWithKey(conn, &key)
		if err != nil {
			t.Errorf("read: %v", err)
			return
		}
		if req.MessageType != MsgRemoteWrite {
			t.Errorf("message_type: got %d want %d", req.MessageType, MsgRemoteWrite)
		}
		if string(req.Data) != "snappy-body" {
			t.Errorf("body: %q", req.Data)
		}
		ack, _ := json.Marshal(RemoteWriteAck{Status: 204})
		if err := tinyframe.WriteFrameWithKey(conn, MsgRemoteWriteAck, req.TxID, ack, tinyframe.ChaCha20Poly1305, &key); err != nil {
			t.Errorf("write ack: %v", err)
		}
	}()

	client, err := New(Config{Addr: ln.Addr().String(), SecretKey: key})
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.RemoteWrite(context.Background(), []byte("snappy-body"))
	if err != nil {
		t.Fatal(err)
	}
	if status != 204 {
		t.Fatalf("status: got %d want 204", status)
	}
	<-done
}

func TestRemoteWriteProtobuf(t *testing.T) {
	key := testKey()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := tinyframe.ReadFrameWithKey(conn, &key)
		if err != nil {
			return
		}
		ack, _ := json.Marshal(RemoteWriteAck{Status: 204})
		_ = tinyframe.WriteFrameWithKey(conn, MsgRemoteWriteAck, req.TxID, ack, tinyframe.ChaCha20Poly1305, &key)
	}()

	client, err := New(Config{Addr: ln.Addr().String(), SecretKey: key})
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.RemoteWriteProtobuf(context.Background(), []byte("protobuf-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if status != 204 {
		t.Fatalf("status=%d", status)
	}
}

func TestRemoteWriteError(t *testing.T) {
	key := testKey()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := tinyframe.ReadFrameWithKey(conn, &key)
		if err != nil {
			return
		}
		eb, _ := json.Marshal(ErrorBody{Message: "upstream HTTP 400: bad"})
		_ = tinyframe.WriteFrameWithKey(conn, MsgError, req.TxID, eb, tinyframe.ChaCha20Poly1305, &key)
	}()

	client, err := New(Config{Addr: ln.Addr().String(), SecretKey: key, DialTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RemoteWrite(context.Background(), []byte("x"))
	if err == nil || err.Error() != "promproxy: upstream HTTP 400: bad" {
		t.Fatalf("expected protocol error, got %v", err)
	}
}

func TestNewRequiresAddr(t *testing.T) {
	_, err := New(Config{SecretKey: testKey()})
	if err == nil {
		t.Fatal("expected error")
	}
}
