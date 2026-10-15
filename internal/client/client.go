// Package client 是 fw CLI 使用的 API 客户端：优先走 Unix 域套接字（免令牌），
// 不可用时回退到本机 HTTP。
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"fwdd/internal/config"
)

// Client 是与 fwdd 通信的薄客户端。
type Client struct {
	hc      *http.Client
	base    string
	stream  string
	token   string
	viaUnix bool
}

// New 依据配置构造客户端。
func New(cfg config.Config) *Client {
	c := &Client{token: cfg.Token}

	// Unix 套接字优先。
	if cfg.Socket != "" {
		if _, err := os.Stat(cfg.Socket); err == nil {
			sock := cfg.Socket
			c.hc = &http.Client{
				Timeout: 60 * time.Second,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						var d net.Dialer
						return d.DialContext(ctx, "unix", sock)
					},
				},
			}
			c.base = "http://unix/api/v1"
			c.viaUnix = true
			return c
		}
	}

	addr := cfg.Listen
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	c.hc = &http.Client{Timeout: 60 * time.Second}
	c.base = strings.TrimRight(addr, "/") + "/api/v1"
	return c
}

// Via 返回连接方式描述。
func (c *Client) Via() string {
	if c.viaUnix {
		return "unix socket"
	}
	return c.base
}

// Get / Post / Put / Delete 是便捷封装。

func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) Post(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

func (c *Client) Put(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPut, path, body, out)
}

func (c *Client) Delete(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodDelete, path, nil, out)
}

// GetText 返回纯文本响应（用于 /ruleset）。
func (c *Client) GetText(ctx context.Context, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(path), nil)
	if err != nil {
		return "", err
	}
	c.auth(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("无法连接 fwdd（%s）: %w。请确认服务已启动", c.Via(), err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return string(body), nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.auth(req)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("无法连接 fwdd（%s）: %w。请确认服务已启动", c.Via(), err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return errorFromBody(resp.StatusCode, data)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("解析响应失败: %w (%s)", err, truncate(string(data), 200))
	}
	return nil
}

func (c *Client) url(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return c.base + path
}

func (c *Client) auth(req *http.Request) {
	if c.token != "" && !c.viaUnix {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

// errorFromBody 尽量从 JSON 错误体中还原可读信息。
func errorFromBody(code int, data []byte) error {
	var payload struct {
		Error    string `json:"error"`
		Problems []struct {
			Where   string `json:"where"`
			Message string `json:"message"`
		} `json:"problems"`
	}
	if err := json.Unmarshal(data, &payload); err == nil {
		if len(payload.Problems) > 0 {
			var b strings.Builder
			b.WriteString("策略校验失败:")
			for _, p := range payload.Problems {
				fmt.Fprintf(&b, "\n  - %s: %s", p.Where, p.Message)
			}
			return fmt.Errorf("%s", b.String())
		}
		if payload.Error != "" {
			return fmt.Errorf("%s", payload.Error)
		}
	}
	return fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(data)), 300))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Query 构造带查询参数的路径。
func Query(path string, kv map[string]string) string {
	if len(kv) == 0 {
		return path
	}
	q := url.Values{}
	for k, v := range kv {
		q.Set(k, v)
	}
	return path + "?" + q.Encode()
}
