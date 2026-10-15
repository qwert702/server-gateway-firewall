// Package backend 定义防火墙后端抽象。
//
// 主实现为 nftables（见 internal/backend/nftables），另提供 mock 用于单元测试
// 与无内核环境（如开发机）下的演示。所有后端都只接收 ir.Snapshot，
// 因此编译逻辑与具体实现完全解耦。
package backend

import (
	"context"
	"errors"

	"fwdd/internal/ir"
)

// ErrNotSupported 表示后端不支持某个操作。
var ErrNotSupported = errors.New("backend: 该操作不被当前后端支持")

// Backend 是防火墙实现的最小契约。
type Backend interface {
	// Name 返回后端名称，如 "nftables"。
	Name() string

	// Apply 原子替换规则集：要么全部生效，要么内核保持不变。
	Apply(ctx context.Context, s *ir.Snapshot) error

	// Reset 移除本后端管理的一切过滤状态，回到"没有任何规则"的状态。
	//
	// 用于 commit-confirm 回滚时**尚无历史版本**的场景：此时正确的"撤销"是
	// 撤掉整张表（内核回到默认放行），而不是下发一份空策略——空策略会编译成
	// default drop 的链，等于把机器彻底锁死。
	Reset(ctx context.Context) error

	// Render 只渲染不下发，返回将写入内核的规则集文本（dry-run）。
	Render(ctx context.Context, s *ir.Snapshot) (string, error)

	// State 读取当前运行状态，用于展示与对账。
	State(ctx context.Context) (*RuntimeState, error)

	// SetAdd 向命名集合添加元素（封禁注入）。
	SetAdd(ctx context.Context, set string, elems ...ir.Element) error
	// SetDel 从命名集合移除元素（解封）。
	SetDel(ctx context.Context, set string, keys ...string) error
	// SetList 列出命名集合当前元素。
	SetList(ctx context.Context, set string) ([]ir.Element, error)

	// Close 释放资源。
	Close() error
}

// ChainInfo 是运行态中一条链的摘要。
type ChainInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`
	Hook     string `json:"hook,omitempty"`
	Priority string `json:"priority,omitempty"`
	Policy   string `json:"policy,omitempty"`
	Rules    int    `json:"rules"`
}

// SetInfo 是运行态中一个集合的摘要。
type SetInfo struct {
	Name     string   `json:"name"`
	KeyType  string   `json:"type,omitempty"`
	Flags    []string `json:"flags,omitempty"`
	Elements int      `json:"elements"`
}

// RuntimeState 是后端当前已生效的规则集快照。
type RuntimeState struct {
	Backend string      `json:"backend"`
	Table   string      `json:"table,omitempty"`
	Chains  []ChainInfo `json:"chains,omitempty"`
	Sets    []SetInfo   `json:"sets,omitempty"`
	// Text 是原始规则集文本（nft 的 `list table` 输出）。
	Text string `json:"text,omitempty"`
	// Hash 是 Text 的内容哈希，用于快速判断是否发生漂移。
	Hash string `json:"hash,omitempty"`
	// Note 记录读取过程中的降级说明（如工具缺失）。
	Note string `json:"note,omitempty"`
}
