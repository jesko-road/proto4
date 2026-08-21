package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jesko-road/proto4/tinyframe"
)

func parseTCPURL(raw string) (hostPort, path string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "tcp" {
		return "", "", fmt.Errorf("unsupported scheme %q, expected tcp", u.Scheme)
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("missing host in url")
	}
	path = u.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return u.Host, path, nil
}

func randomTxID() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return uint64(time.Now().UnixNano()), nil
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

func doGet(rawURL string, m *manifest, out io.Writer) error {
	hostPort, path, err := parseTCPURL(rawURL)
	if err != nil {
		return err
	}

	iface, err := m.findRoute(path)
	if err != nil {
		return err
	}
	if iface.MessageType < 0 || iface.MessageType > 31 {
		return fmt.Errorf("message_type %d out of range (0-31)", iface.MessageType)
	}

	key, err := m.parseSecretKey()
	if err != nil {
		return err
	}
	tinyframe.SetEncryptKey(key)

	compressFlag, err := m.compressMethodFlag()
	if err != nil {
		return err
	}
	if iface.Compressed && compressFlag == tinyframe.CompressNone {
		return fmt.Errorf("interface %q has compressed=true but api.compress_method is not set", iface.Path)
	}

	conn, err := net.DialTimeout("tcp", hostPort, 30*time.Second)
	if err != nil {
		return fmt.Errorf("connect %s: %w", hostPort, err)
	}
	defer conn.Close()

	txID, err := randomTxID()
	if err != nil {
		return err
	}

	if err := tinyframe.WriteFrame(conn, byte(iface.MessageType), txID, nil, tinyframe.ChaCha20Poly1305); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	frame, err := tinyframe.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if err := iface.validateResponseCompression(m.API.CompressMethod, frame.CompressID); err != nil {
		return err
	}

	if len(frame.Data) > 0 {
		if _, err := out.Write(frame.Data); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
	return nil
}

func doGetStdout(rawURL string, m *manifest) error {
	return doGet(rawURL, m, os.Stdout)
}
