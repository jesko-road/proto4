package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/jesko-road/proto4/tinyframe"
)

func TestParseTCPURL(t *testing.T) {
	host, path, err := parseTCPURL("tcp://127.0.0.1:8080/api/v1/message1")
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1:8080" || path != "/api/v1/message1" {
		t.Fatalf("got %q %q", host, path)
	}
}

func TestLoadManifest(t *testing.T) {
	path := writeTempManifest(t, `{
  "api": {
    "secretkey": "071c9849f90b8caf7b9083bd53817e56d7274dc35796c4206b7fc97caec44dea",
    "compress_method": "gzip",
    "interfaces": [{"message_type": 1, "path": "/x", "compressed": true}]
  }
}`)
	m, err := loadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	iface, err := m.findRoute("/x")
	if err != nil {
		t.Fatal(err)
	}
	if iface.MessageType != 1 || !iface.Compressed {
		t.Fatalf("unexpected iface: %+v", iface)
	}
}

func TestCompressedRequiresCompressMethod(t *testing.T) {
	m := &manifest{
		API: apiConfig{
			SecretKey:      strings.Repeat("ab", 32),
			CompressMethod: "",
			Interfaces:     []apiRoute{{MessageType: 1, Path: "/x", Compressed: true}},
		},
	}
	iface := &m.API.Interfaces[0]
	err := iface.validateResponseCompression(m.API.CompressMethod, tinyframe.CompressGzip)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDoGetIntegration(t *testing.T) {
	m := testManifest()
	key, err := m.parseSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	addr := startTestServer(t, func(conn net.Conn) {
		tinyframe.SetEncryptKey(key)
		req, err := tinyframe.ReadFrame(conn)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		if req.MessageType != 1 {
			t.Errorf("message_type: got %d want 1", req.MessageType)
		}
		if !req.Encrypted {
			t.Errorf("request not encrypted")
		}
		flags := tinyframe.ChaCha20Poly1305 | tinyframe.CompressGzip
		if err := tinyframe.WriteFrame(conn, 1, req.TxID, []byte("hello from server"), flags); err != nil {
			t.Errorf("write response: %v", err)
		}
	})

	var out bytes.Buffer
	err = doGet("tcp://"+addr+"/api/v1/message1", m, &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "hello from server" {
		t.Fatalf("output: %q", out.String())
	}
}

func TestDoGetPlainResponse(t *testing.T) {
	m := testManifest()
	key, err := m.parseSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	addr := startTestServer(t, func(conn net.Conn) {
		tinyframe.SetEncryptKey(key)
		req, err := tinyframe.ReadFrame(conn)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		if req.MessageType != 2 {
			t.Errorf("message_type: got %d want 2", req.MessageType)
		}
		if err := tinyframe.WriteFrame(conn, 2, req.TxID, []byte("plain"), tinyframe.ChaCha20Poly1305); err != nil {
			t.Errorf("write response: %v", err)
		}
	})

	var out bytes.Buffer
	err = doGet("tcp://"+addr+"/api/v1/message2", m, &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "plain" {
		t.Fatalf("output: %q", out.String())
	}
}

func TestDoGetUnknownPath(t *testing.T) {
	m := testManifest()
	err := doGet("tcp://127.0.0.1:1/nope", m, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error, got %v", err)
	}
}

func testManifest() *manifest {
	return &manifest{
		API: apiConfig{
			SecretKey:      "071c9849f90b8caf7b9083bd53817e56d7274dc35796c4206b7fc97caec44dea",
			CompressMethod: "gzip",
			Interfaces: []apiRoute{
				{MessageType: 1, Path: "/api/v1/message1", Compressed: true},
				{MessageType: 2, Path: "/api/v1/message2", Compressed: false},
				{MessageType: 10, Path: "/api/v1/write", Compressed: false},
			},
		},
	}
}

func startTestServer(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		handler(conn)
	}()
	return ln.Addr().String()
}

func writeTempManifest(t *testing.T, body string) string {
	t.Helper()
	f, err := os.CreateTemp("", "tframe-manifest-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(body); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	return f.Name()
}
