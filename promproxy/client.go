// Package promproxy 是可供其它 Go 项目引用的 Prometheus remote_write 客户端 SDK。
//
//	client, _ := promproxy.New(promproxy.Config{Addr: "127.0.0.1:9100", SecretKey: key})
//	status, err := client.RemoteWriteGather(ctx, registry)
package promproxy

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang/snappy"
	"github.com/jesko-road/proto4/tinyframe"
)

const (
	// MsgRemoteWrite 客户端 → 代理：snappy 压缩的 protobuf WriteRequest。
	MsgRemoteWrite byte = 10
	// MsgRemoteWriteAck 代理 → 客户端：转发成功。
	MsgRemoteWriteAck byte = 11
	// MsgError 代理 → 客户端：错误。
	MsgError byte = 12

	defaultDialTimeout = 30 * time.Second
)

// RemoteWriteAck 代理成功响应。
type RemoteWriteAck struct {
	Status uint16 `json:"status"`
}

// ErrorBody 代理错误响应。
type ErrorBody struct {
	Message string `json:"message"`
}

// Config SDK 客户端配置。
type Config struct {
	// Addr 代理地址，host:port，例如 "127.0.0.1:9100"。
	Addr string
	// SecretKey 与代理 / manifest.api.secretkey 相同的 32 字节密钥。
	SecretKey [tinyframe.KeyLen]byte
	// MessageType 默认 MsgRemoteWrite(10)；需与代理 / manifest 一致。
	MessageType byte
	// DialTimeout 默认 30s。
	DialTimeout time.Duration
}

// Client 可被其它项目长期持有的 remote_write SDK 客户端。
// 线程安全。
type Client struct {
	addr        string
	key         [tinyframe.KeyLen]byte
	messageType byte
	dialTimeout time.Duration
	nextTx      atomic.Uint64
}

// ParseSecretKeyHex 解析 64 字符 hex（manifest secretkey）为 32 字节密钥。
func ParseSecretKeyHex(hexKey string) ([tinyframe.KeyLen]byte, error) {
	var out [tinyframe.KeyLen]byte
	raw, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return out, fmt.Errorf("invalid secretkey hex: %w", err)
	}
	if len(raw) != tinyframe.KeyLen {
		return out, fmt.Errorf("secretkey must be %d bytes (%d hex chars), got %d",
			tinyframe.KeyLen, tinyframe.KeyLen*2, len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// PrepareRemoteWriteBody 将未压缩的 protobuf WriteRequest 做 Snappy block 压缩。
func PrepareRemoteWriteBody(protobufWriteRequest []byte) []byte {
	return snappy.Encode(nil, protobufWriteRequest)
}

// New 创建 SDK 客户端。Addr 与 SecretKey 必填。
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.Addr) == "" {
		return nil, errors.New("promproxy: Addr is required")
	}
	msgType := cfg.MessageType
	if msgType == 0 {
		msgType = MsgRemoteWrite
	}
	if msgType > 31 {
		return nil, fmt.Errorf("promproxy: MessageType %d out of range (0-31)", msgType)
	}
	timeout := cfg.DialTimeout
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}
	c := &Client{
		addr:        cfg.Addr,
		key:         cfg.SecretKey,
		messageType: msgType,
		dialTimeout: timeout,
	}
	c.nextTx.Store(1)
	return c, nil
}

func (c *Client) nextTxID() uint64 {
	for {
		id := c.nextTx.Load()
		next := id + 1
		if next == 0 {
			next = 1
		}
		if c.nextTx.CompareAndSwap(id, next) {
			return id
		}
	}
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: c.dialTimeout}
	return d.DialContext(ctx, "tcp", c.addr)
}

// RemoteWrite 发送已 snappy 压缩的 remote_write HTTP body，返回上游 HTTP status。
func (c *Client) RemoteWrite(ctx context.Context, body []byte) (uint16, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return 0, fmt.Errorf("promproxy: connect %s: %w", c.addr, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	txID := c.nextTxID()
	key := c.key
	if err := tinyframe.WriteFrameWithKey(
		conn, c.messageType, txID, body, tinyframe.ChaCha20Poly1305, &key,
	); err != nil {
		return 0, fmt.Errorf("promproxy: write request: %w", err)
	}

	frame, err := tinyframe.ReadFrameWithKey(conn, &key)
	if err != nil {
		return 0, fmt.Errorf("promproxy: read response: %w", err)
	}

	switch frame.MessageType {
	case MsgRemoteWriteAck:
		var ack RemoteWriteAck
		if err := json.Unmarshal(frame.Data, &ack); err != nil {
			return 0, fmt.Errorf("promproxy: decode ack: %w", err)
		}
		return ack.Status, nil
	case MsgError:
		var eb ErrorBody
		if err := json.Unmarshal(frame.Data, &eb); err != nil {
			return 0, fmt.Errorf("promproxy: decode error: %w", err)
		}
		return 0, fmt.Errorf("promproxy: %s", eb.Message)
	default:
		return 0, fmt.Errorf("promproxy: unexpected message_type %d", frame.MessageType)
	}
}

// RemoteWriteProtobuf 接受未压缩的 protobuf WriteRequest，内部做 snappy 后发送。
func (c *Client) RemoteWriteProtobuf(ctx context.Context, protobufWriteRequest []byte) (uint16, error) {
	return c.RemoteWrite(ctx, PrepareRemoteWriteBody(protobufWriteRequest))
}
