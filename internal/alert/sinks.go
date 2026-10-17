package alert

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"os/exec"
	"strings"
	"time"
)

// ---- Webhook ----

// WebhookFormat 决定 payload 的形状。国内常用的几种机器人各有各的格式，
// 一份 Webhook 实现加格式适配就能全覆盖，不必为每家写一个通道。
type WebhookFormat string

const (
	// FormatGeneric 直接发事件本身的结构化 JSON，适合自建告警系统。
	FormatGeneric WebhookFormat = "generic"
	// FormatWecom 企业微信群机器人。
	FormatWecom WebhookFormat = "wecom"
	// FormatDingtalk 钉钉群机器人。
	FormatDingtalk WebhookFormat = "dingtalk"
	// FormatFeishu 飞书群机器人。
	FormatFeishu WebhookFormat = "feishu"
	// FormatTelegram Telegram Bot API。
	FormatTelegram WebhookFormat = "telegram"
)

// WebhookOptions 配置一个 Webhook 通道。
type WebhookOptions struct {
	URL    string        `json:"url"`
	Format WebhookFormat `json:"format"`
	// ChatID 仅 Telegram 需要。
	ChatID string `json:"chat_id,omitempty"`
	// Token 会作为 Authorization: Bearer 头发送（自建系统的鉴权用）。
	Token   string        `json:"token,omitempty"`
	Timeout time.Duration `json:"timeout,omitempty"`
}

type webhookNotifier struct {
	o  WebhookOptions
	hc *http.Client
}

// NewWebhook 创建 Webhook 通道。
func NewWebhook(o WebhookOptions) (Notifier, error) {
	if o.URL == "" {
		return nil, fmt.Errorf("webhook 缺少 url")
	}
	switch o.Format {
	case "":
		o.Format = FormatGeneric
	case FormatGeneric, FormatWecom, FormatDingtalk, FormatFeishu, FormatTelegram:
	default:
		return nil, fmt.Errorf("未知的 webhook 格式 %q", o.Format)
	}
	if o.Format == FormatTelegram && o.ChatID == "" {
		return nil, fmt.Errorf("telegram 格式需要 chat_id")
	}
	if o.Timeout <= 0 {
		o.Timeout = 8 * time.Second
	}
	return &webhookNotifier{o: o, hc: &http.Client{Timeout: o.Timeout}}, nil
}

func (w *webhookNotifier) Name() string {
	return "webhook(" + string(w.o.Format) + ")"
}

func (w *webhookNotifier) Notify(ctx context.Context, ev Event) error {
	body, err := w.payload(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.o.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.o.Token != "" {
		req.Header.Set("Authorization", "Bearer "+w.o.Token)
	}

	resp, err := w.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 读懂响应体的一部分：机器人接口出错时是 200 + 错误码，
	// 只看状态码会把"没发出去"当成成功。
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(data), 200))
	}
	if code := robotErrorCode(data); code != "" {
		return fmt.Errorf("机器人接口返回错误: %s", code)
	}
	return nil
}

// robotErrorCode 从各家的响应体里提取错误信息。
//
// 企业微信/钉钉/飞书都是 HTTP 200 + 业务错误码，不解析就会把失败当成功。
func robotErrorCode(body []byte) string {
	if len(bytes.TrimSpace(body)) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	for _, k := range []string{"errcode", "code", "StatusCode"} {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch n := v.(type) {
		case float64:
			if n != 0 {
				return fmt.Sprintf("%s=%v msg=%v", k, n, m["errmsg"])
			}
		case string:
			if n != "" && n != "0" && n != "success" {
				return fmt.Sprintf("%s=%s", k, n)
			}
		}
	}
	// Telegram 用 ok:false
	if ok, exists := m["ok"].(bool); exists && !ok {
		return fmt.Sprintf("%v", m["description"])
	}
	return ""
}

func (w *webhookNotifier) payload(ev Event) ([]byte, error) {
	// 各家机器人都只接受纯文本，所以把事件渲染成一段人读的文字。
	text := "🛡 fwdd 告警\n" + ev.String()

	switch w.o.Format {
	case FormatGeneric:
		return json.Marshal(ev)
	case FormatWecom, FormatDingtalk:
		// 企业微信与钉钉的文本消息格式相同
		return json.Marshal(map[string]any{
			"msgtype": "text",
			"text":    map[string]string{"content": text},
		})
	case FormatFeishu:
		return json.Marshal(map[string]any{
			"msg_type": "text",
			"content":  map[string]string{"text": text},
		})
	case FormatTelegram:
		return json.Marshal(map[string]any{
			"chat_id": w.o.ChatID,
			"text":    text,
		})
	}
	return nil, fmt.Errorf("未处理的格式 %q", w.o.Format)
}

// ---- 邮件 ----

// SMTPOptions 配置邮件通道。
type SMTPOptions struct {
	// Addr 是 host:port，如 smtp.example.com:587。
	Addr     string   `json:"addr"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	// ImplicitTLS 为 true 时用隐式 TLS（通常 465 端口，连上就是 TLS）；
	// 为 false 时用 STARTTLS（通常 587 端口）。
	ImplicitTLS bool          `json:"implicit_tls,omitempty"`
	Timeout     time.Duration `json:"timeout,omitempty"`
}

type smtpNotifier struct{ o SMTPOptions }

// NewSMTP 创建邮件通道。
func NewSMTP(o SMTPOptions) (Notifier, error) {
	if o.Addr == "" || o.From == "" || len(o.To) == 0 {
		return nil, fmt.Errorf("smtp 需要 addr、from 与至少一个 to")
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	return &smtpNotifier{o: o}, nil
}

func (s *smtpNotifier) Name() string { return "smtp" }

func (s *smtpNotifier) Notify(ctx context.Context, ev Event) error {
	msg := s.buildMessage(ev)

	// net/smtp 的 SendMail 会按需 STARTTLS，但不支持隐式 TLS，
	// 465 端口必须自己先建 TLS 连接。
	if s.o.ImplicitTLS {
		return s.sendImplicitTLS(ctx, msg)
	}

	var auth smtp.Auth
	if s.o.Username != "" {
		host, _, _ := strings.Cut(s.o.Addr, ":")
		auth = smtp.PlainAuth("", s.o.Username, s.o.Password, host)
	}
	if err := smtp.SendMail(s.o.Addr, auth, s.o.From, s.o.To, msg); err != nil {
		return fmt.Errorf("发送邮件失败: %w", err)
	}
	return nil
}

func (s *smtpNotifier) sendImplicitTLS(ctx context.Context, msg []byte) error {
	host, _, _ := strings.Cut(s.o.Addr, ":")
	conn, err := tls.Dial("tcp", s.o.Addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err != nil {
		return fmt.Errorf("建立 TLS 连接失败: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if s.o.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.o.Username, s.o.Password, host)); err != nil {
			return fmt.Errorf("SMTP 认证失败: %w", err)
		}
	}
	if err := c.Mail(s.o.From); err != nil {
		return err
	}
	for _, to := range s.o.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(msg); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (s *smtpNotifier) buildMessage(ev Event) []byte {
	subject := fmt.Sprintf("[fwdd/%s] %s", ev.Severity, ev.Title)
	if ev.IP != "" {
		subject += " " + ev.IP
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", s.o.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(s.o.To, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(ev.String())
	b.WriteString("\r\n")
	return []byte(b.String())
}

// ---- 本地命令 ----

// CommandOptions 配置命令通道。
//
// 用途是"我已有的告警系统"接不上 webhook 时，用本地脚本兜底。
// 事件内容通过**环境变量**传给命令，不走命令行参数 —— 因为事件里的
// IP、备注都可能来自外部输入，拼进命令行就是注入。
type CommandOptions struct {
	// Command 是要执行的程序路径。
	Command string `json:"command"`
	// Args 是附加参数（固定值，不含事件内容）。
	Args    []string      `json:"args,omitempty"`
	Timeout time.Duration `json:"timeout,omitempty"`
}

type commandNotifier struct{ o CommandOptions }

// NewCommand 创建命令通道。
func NewCommand(o CommandOptions) (Notifier, error) {
	if o.Command == "" {
		return nil, fmt.Errorf("command 通道缺少 command")
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	return &commandNotifier{o: o}, nil
}

func (c *commandNotifier) Name() string { return "command" }

func (c *commandNotifier) Notify(ctx context.Context, ev Event) error {
	ctx, cancel := context.WithTimeout(ctx, c.o.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.o.Command, c.o.Args...)
	// 事件内容只走环境变量与 stdin，不拼进命令行。
	cmd.Env = append(cmd.Environ(),
		"FWDD_SEVERITY="+string(ev.Severity),
		"FWDD_KIND="+ev.Kind,
		"FWDD_IP="+ev.IP,
		"FWDD_TITLE="+ev.Title,
		"FWDD_DETAIL="+ev.Detail,
		"FWDD_TIME="+ev.At.Format(time.RFC3339),
	)
	body, _ := json.Marshal(ev)
	cmd.Stdin = bytes.NewReader(body)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("执行 %s 失败: %w (%s)", c.o.Command, err, truncate(string(out), 200))
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
