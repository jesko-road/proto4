package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jesko-road/proto4/tinyframe"
)

type manifest struct {
	API apiConfig `json:"api"`
}

type apiConfig struct {
	SecretKey      string     `json:"secretkey"`
	CompressMethod string     `json:"compress_method"`
	Interfaces     []apiRoute `json:"interfaces"`
}

type apiRoute struct {
	MessageType int    `json:"message_type"`
	Path        string `json:"path"`
	Compressed  bool   `json:"compressed"`
}

func defaultManifestPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "tframe.json"), nil
}

func loadManifest(path string) (*manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest %q: %w", path, err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if m.API.SecretKey == "" {
		return nil, fmt.Errorf("manifest api.secretkey is required")
	}
	return &m, nil
}

func (m *manifest) parseSecretKey() (*[tinyframe.KeyLen]byte, error) {
	hexKey := strings.TrimSpace(m.API.SecretKey)
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid secretkey hex: %w", err)
	}
	if len(raw) != tinyframe.KeyLen {
		return nil, fmt.Errorf("secretkey must be %d bytes (%d hex chars), got %d bytes", tinyframe.KeyLen, tinyframe.KeyLen*2, len(raw))
	}
	var key [tinyframe.KeyLen]byte
	copy(key[:], raw)
	return &key, nil
}

func (m *manifest) compressMethodFlag() (byte, error) {
	switch strings.ToLower(strings.TrimSpace(m.API.CompressMethod)) {
	case "", "none":
		return tinyframe.CompressNone, nil
	case "gzip":
		return tinyframe.CompressGzip, nil
	case "deflate":
		return tinyframe.CompressDeflate, nil
	default:
		return 0, fmt.Errorf("unsupported compress_method %q", m.API.CompressMethod)
	}
}

func (m *manifest) findRoute(path string) (*apiRoute, error) {
	for i := range m.API.Interfaces {
		iface := &m.API.Interfaces[i]
		if iface.Path == path {
			return iface, nil
		}
	}
	return nil, fmt.Errorf("path %q not found in manifest interfaces", path)
}

func (route *apiRoute) validateResponseCompression(compressMethod string, compressFlag byte) error {
	if !route.Compressed {
		return nil
	}
	method := strings.ToLower(strings.TrimSpace(compressMethod))
	if method == "" || method == "none" {
		return fmt.Errorf("interface %q has compressed=true but api.compress_method is not set", route.Path)
	}
	if compressFlag == tinyframe.CompressNone {
		return fmt.Errorf("interface %q expects compressed response but frame is not compressed", route.Path)
	}
	return nil
}
