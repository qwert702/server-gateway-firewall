// Package nftables 是 Backend 的 nftables 实现。
//
// 实现方式：把 ir.Snapshot 渲染为 nft 规则集文本，再通过管道交给 `nft -f -`。
//
// 为什么走 nft 命令行而不是 netlink 库：
//   - `nft -f -` 会把整个文件作为**单个 netlink 事务**下发，天然满足"要么全生效、
//     要么内核不变"的原子性要求；
//   - dry-run 输出的文本就是实际下发的文本，所见即所得，不存在"渲染器与库不一致"；
//   - 不引入对 nftables 库 API 版本变化的耦合。
//
// Backend 接口与具体实现解耦，若日后需要结构化访问，可另加一个基于
// github.com/google/nftables 的实现，二者可互换。
package nftables

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"fwdd/internal/backend"
	"fwdd/internal/ir"
)

// Backend 实现 backend.Backend。
type Backend struct {
	mu sync.Mutex

	bin       string
	family    string
	tableName string
	runner    Runner
}

// Runner 抽象命令执行，便于测试时注入伪造的 nft。
type Runner interface {
	Run(ctx context.Context, stdin string, args ...string) (stdout string, stderr string, err error)
}

// ExecRunner 用 os/exec 执行真实命令。
type ExecRunner struct{ Bin string }

// Run 实现 Runner。
func (r ExecRunner) Run(ctx context.Context, stdin string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, r.Bin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return out.String(), errb.String(), err
}

// Option 配置后端。
type Option func(*Backend)

// WithBinary 指定 nft 可执行文件路径。
func WithBinary(path string) Option { return func(b *Backend) { b.bin = path } }

// WithTable 指定表名与地址族。
func WithTable(family, name string) Option {
	return func(b *Backend) {
		if family != "" {
			b.family = family
		}
		if name != "" {
			b.tableName = name
		}
	}
}

// WithRunner 注入自定义 Runner（测试用）。
func WithRunner(r Runner) Option { return func(b *Backend) { b.runner = r } }

// New 创建 nftables 后端。未显式指定时使用 PATH 中的 nft。
func New(opts ...Option) *Backend {
	b := &Backend{
		bin:       "nft",
		family:    "inet",
		tableName: "fw",
	}
	for _, o := range opts {
		o(b)
	}
	if b.runner == nil {
		b.runner = ExecRunner{Bin: b.bin}
	}
	return b
}

// Name 实现 backend.Backend。
func (b *Backend) Name() string { return "nftables" }

// Available 报告 nft 是否可用（含版本探测）。
func (b *Backend) Available(ctx context.Context) (string, error) {
	out, errText, err := b.runner.Run(ctx, "", "--version")
	if err != nil {
		msg := strings.TrimSpace(errText)
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("无法执行 %s: %s", b.bin, msg)
	}
	return strings.TrimSpace(out), nil
}

// Render 实现 backend.Backend：只渲染不下发。
func (b *Backend) Render(ctx context.Context, s *ir.Snapshot) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s == nil {
		return "", errors.New("nftables: 快照为空")
	}
	return b.header() + s.Render(), nil
}

// Apply 实现 backend.Backend：在单个 nft 事务中整表重建。
//
// 事务内容：
//
//	table inet fw { }      # 不存在则创建（幂等，不影响既有内容）
//	delete table inet fw   # 清空旧规则
//	table inet fw { ... }  # 写入新规则
//
// 三步同属一次 nft -f 调用，因此内核看到的要么是旧规则、要么是新规则。
func (b *Backend) Apply(ctx context.Context, s *ir.Snapshot) error {
	if s == nil {
		return errors.New("nftables: 快照为空")
	}
	if err := b.checkTable(s); err != nil {
		return err
	}

	var buf strings.Builder
	buf.WriteString(b.header())
	fmt.Fprintf(&buf, "table %s %s { }\n", b.family, b.tableName)
	fmt.Fprintf(&buf, "delete table %s %s\n", b.family, b.tableName)
	buf.WriteString(s.Render())

	return b.exec(ctx, buf.String(), "应用规则集")
}

// Reset 实现 backend.Backend：删除整张表，内核回到默认放行状态。
func (b *Backend) Reset(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, errText, err := b.runner.Run(ctx,
		b.header()+fmt.Sprintf("delete table %s %s\n", b.family, b.tableName),
		"-f", "-")
	if err != nil && !isNotFound(errText) {
		return fmt.Errorf("重置规则集失败: %s", firstNonEmpty(errText, err.Error()))
	}
	return nil
}

// State 实现 backend.Backend：读取内核中的实际规则集。
func (b *Backend) State(ctx context.Context) (*backend.RuntimeState, error) {
	st := &backend.RuntimeState{Backend: "nftables", Table: b.tableName}

	raw, errText, err := b.runner.Run(ctx, "", "-j", "list", "table", b.family, b.tableName)
	if err != nil {
		if isNotFound(errText) {
			st.Note = fmt.Sprintf("表 %s %s 尚不存在（未下发过规则）", b.family, b.tableName)
			return st, nil
		}
		// 退回纯文本模式，至少能展示与对账。
		text, errText2, err2 := b.runner.Run(ctx, "", "list", "table", b.family, b.tableName)
		if err2 != nil {
			return nil, fmt.Errorf("读取规则集失败: %s", firstNonEmpty(errText2, errText, err2.Error()))
		}
		st.Text = text
		st.Hash = hashOf(text)
		st.Note = "JSON 输出不可用，已降级为文本模式"
		return st, nil
	}

	text, _, _ := b.runner.Run(ctx, "", "list", "table", b.family, b.tableName)
	st.Text = text
	st.Hash = hashOf(text)

	if err := parseJSONState(raw, st); err != nil {
		st.Note = fmt.Sprintf("解析 nft JSON 失败，已降级为文本模式: %v", err)
	}
	return st, nil
}

// SetAdd 实现 backend.Backend：向集合注入元素（用于封禁）。
func (b *Backend) SetAdd(ctx context.Context, set string, elems ...ir.Element) error {
	if len(elems) == 0 {
		return nil
	}
	fam, ok := b.setFamily(set)
	if !ok {
		return fmt.Errorf("nftables: 集合 %q 不存在或类型未知", set)
	}
	var parts []string
	for _, e := range elems {
		item := e.Key
		if e.Timeout > 0 {
			item += " timeout " + formatDuration(e.Timeout)
		}
		if e.Comment != "" {
			item += ` comment "` + strings.ReplaceAll(e.Comment, `"`, `\"`) + `"`
		}
		parts = append(parts, item)
	}
	text := fmt.Sprintf("add element %s %s %s { %s }\n",
		fam, b.tableName, set, strings.Join(parts, ", "))
	return b.exec(ctx, b.header()+text, "添加集合元素")
}

// SetDel 实现 backend.Backend：从集合移除元素（用于解封）。
func (b *Backend) SetDel(ctx context.Context, set string, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	fam, ok := b.setFamily(set)
	if !ok {
		return fmt.Errorf("nftables: 集合 %q 不存在或类型未知", set)
	}
	var quoted []string
	quoted = append(quoted, keys...)
	text := fmt.Sprintf("delete element %s %s %s { %s }\n",
		fam, b.tableName, set, strings.Join(quoted, ", "))
	// 删除不存在的元素会报错，按需忽略。
	if err := b.exec(ctx, b.header()+text, "删除集合元素"); err != nil && !isNotFound(err.Error()) {
		return err
	}
	return nil
}

// SetList 实现 backend.Backend：列出集合当前元素，附带剩余超时。
func (b *Backend) SetList(ctx context.Context, set string) ([]ir.Element, error) {
	fam, ok := b.setFamily(set)
	if !ok {
		return nil, fmt.Errorf("nftables: 集合 %q 不存在或类型未知", set)
	}
	raw, errText, err := b.runner.Run(ctx, "", "-j", "list", "set", fam, b.tableName, set)
	if err != nil {
		return nil, fmt.Errorf("读取集合 %s 失败: %s", set, firstNonEmpty(errText, err.Error()))
	}
	return parseJSONSetElements(raw)
}

// Close 实现 backend.Backend。
func (b *Backend) Close() error { return nil }

// ---- 内部 ----

func (b *Backend) header() string {
	return fmt.Sprintf("# 由 fwdd 生成，请勿手工编辑\n# 生成时间: %s\n",
		time.Now().Format(time.RFC3339))
}

func (b *Backend) checkTable(s *ir.Snapshot) error {
	if len(s.Tables) != 1 {
		return fmt.Errorf("nftables: 只支持单一表，收到 %d 张", len(s.Tables))
	}
	t := s.Tables[0]
	if string(t.Family) != b.family || t.Name != b.tableName {
		return fmt.Errorf("nftables: 快照表为 %s %s，与后端配置 %s %s 不一致",
			t.Family, t.Name, b.family, b.tableName)
	}
	return nil
}

func (b *Backend) exec(ctx context.Context, text, what string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, errText, err := b.runner.Run(ctx, text, "-f", "-")
	if err != nil {
		return fmt.Errorf("%s 失败: %s", what, firstNonEmpty(errText, err.Error()))
	}
	return nil
}

// setFamily 依据集合名后缀推断地址族（banned4/geoip_us4 等）。
func (b *Backend) setFamily(name string) (string, bool) {
	switch {
	case strings.HasSuffix(name, "4"):
		return "ip", true
	case strings.HasSuffix(name, "6"):
		return "ip6", true
	default:
		return "", false
	}
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func isNotFound(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "no such") || strings.Contains(s, "not found") ||
		strings.Contains(s, "does not exist")
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	if d%time.Second == 0 {
		return fmt.Sprintf("%ds", d/time.Second)
	}
	return fmt.Sprintf("%dms", d/time.Millisecond)
}

// ---- nft -j JSON 解析 ----

type nftJSON struct {
	Nftables []map[string]json.RawMessage `json:"nftables"`
}

type nftTable struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

type nftChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Prio   int    `json:"prio"`
	Policy string `json:"policy"`
}

type nftSet struct {
	Family string   `json:"family"`
	Table  string   `json:"table"`
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Flags  []string `json:"flags"`
}

type nftRule struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Chain  string            `json:"chain"`
	Handle int               `json:"handle"`
	Expr   []json.RawMessage `json:"expr"`
}

type nftElement struct {
	Family string           `json:"family"`
	Table  string           `json:"table"`
	Name   string           `json:"name"`
	Elem   []map[string]any `json:"elem"`
}

func parseJSONState(raw string, st *backend.RuntimeState) error {
	var doc nftJSON
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return err
	}
	ruleCount := map[string]int{}
	chains := map[string]*backend.ChainInfo{}
	sets := map[string]*backend.SetInfo{}

	for _, item := range doc.Nftables {
		for kind, body := range item {
			switch kind {
			case "chain":
				var c nftChain
				if err := json.Unmarshal(body, &c); err != nil {
					continue
				}
				chains[c.Name] = &backend.ChainInfo{
					Name: c.Name, Type: c.Type, Hook: c.Hook,
					Priority: fmt.Sprintf("%d", c.Prio), Policy: c.Policy,
				}
			case "rule":
				var r nftRule
				if err := json.Unmarshal(body, &r); err != nil {
					continue
				}
				ruleCount[r.Chain]++
			case "set":
				var s nftSet
				if err := json.Unmarshal(body, &s); err != nil {
					continue
				}
				sets[s.Name] = &backend.SetInfo{Name: s.Name, KeyType: s.Type, Flags: s.Flags}
			case "element":
				var e nftElement
				if err := json.Unmarshal(body, &e); err != nil {
					continue
				}
				if s := sets[e.Name]; s != nil {
					s.Elements += len(e.Elem)
				}
			}
		}
	}
	for name, c := range chains {
		c.Rules = ruleCount[name]
		st.Chains = append(st.Chains, *c)
	}
	sortChains(st.Chains)
	for _, s := range sets {
		st.Sets = append(st.Sets, *s)
	}
	sortSets(st.Sets)
	return nil
}

func parseJSONSetElements(raw string) ([]ir.Element, error) {
	var doc nftJSON
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, err
	}
	var out []ir.Element
	for _, item := range doc.Nftables {
		body, ok := item["element"]
		if !ok {
			continue
		}
		var e nftElement
		if err := json.Unmarshal(body, &e); err != nil {
			continue
		}
		for _, el := range e.Elem {
			key, _ := el["val"].(string)
			if key == "" {
				continue
			}
			el2 := ir.Element{Key: key}
			if ttl, ok := el["expires"].(float64); ok && ttl > 0 {
				el2.Timeout = time.Duration(ttl) * time.Second
			}
			if c, ok := el["comment"].(string); ok {
				el2.Comment = c
			}
			out = append(out, el2)
		}
	}
	return out, nil
}

func sortChains(cs []backend.ChainInfo) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].Name < cs[j].Name })
}

func sortSets(ss []backend.SetInfo) {
	sort.Slice(ss, func(i, j int) bool { return ss[i].Name < ss[j].Name })
}
