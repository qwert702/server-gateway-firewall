package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"fwdd/internal/backend"
	"fwdd/internal/ir"
	"fwdd/internal/model"
)

// kernelStyleBackend 模拟真实内核的行为：State() 返回的规则集文本是
// 内核重新排版过的规范形式，与 fwdd 生成的文本**逐字节不同**。
//
// mock 后端返回的 Hash 恰好等于 Render() 的结果，所以本地测试结构上
// 发现不了"拿内核文本哈希与生成文本哈希比较"这个错误 —— 它只在真机上
// 表现为 InSync 恒为 false。
type kernelStyleBackend struct {
	applied *ir.Snapshot
	text    string
}

func (b *kernelStyleBackend) Name() string { return "kernel-style" }

func (b *kernelStyleBackend) Apply(ctx context.Context, s *ir.Snapshot) error {
	b.applied = s
	b.text = s.Render()
	return nil
}

func (b *kernelStyleBackend) Render(ctx context.Context, s *ir.Snapshot) (string, error) {
	return s.Render(), nil
}

func (b *kernelStyleBackend) Reset(ctx context.Context) error {
	b.applied, b.text = nil, ""
	return nil
}

func (b *kernelStyleBackend) State(ctx context.Context) (*backend.RuntimeState, error) {
	// 内核读回来的文本与生成时不同：加上缩进、重新排序、附带计数器等。
	reformatted := "# 这是内核重新排版后的样子\n" + b.text + "\n# 附带各种运行时元数据\n"
	sum := sha256.Sum256([]byte(reformatted))
	return &backend.RuntimeState{
		Backend: "kernel-style",
		Text:    reformatted,
		Hash:    hex.EncodeToString(sum[:8]),
	}, nil
}

func (b *kernelStyleBackend) SetAdd(context.Context, string, ...ir.Element) error { return nil }
func (b *kernelStyleBackend) SetDel(context.Context, string, ...string) error     { return nil }
func (b *kernelStyleBackend) SetList(context.Context, string) ([]ir.Element, error) {
	return nil, nil
}
func (b *kernelStyleBackend) Close() error { return nil }

// 下发之后必须报告"已同步"。
//
// 之前的实现里，Status 拿内核读回来的文本哈希与生成文本哈希比较，
// 两者排版不同必然不等，InSync 恒为 false —— 表现为界面永远挂着
// "未同步"告警、每次 apply 都报"有变化"。
func TestInSyncTrueAfterApplyWithRealisticBackend(t *testing.T) {
	be := &kernelStyleBackend{}
	e := New(testConfig(), be, quietLogger())

	p := basePolicy()
	if err := e.SetPolicy(p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), ApplyOptions{}); err != nil {
		t.Fatal(err)
	}

	st := e.Status(context.Background())
	if !st.InSync {
		t.Errorf("刚下发完应报告已同步。期望 %s / 已下发 %s\n"+
			"（若二者相等却仍报未同步，就是拿内核文本哈希去比了）",
			st.DesiredHash, st.AppliedHash)
	}
	if st.DesiredHash != st.AppliedHash {
		t.Fatalf("两个哈希应相等: %s vs %s", st.DesiredHash, st.AppliedHash)
	}
	if st.Runtime == nil || st.Runtime.Hash == "" {
		t.Fatal("运行态信息不应为空（界面要展示内核里的链与集合）")
	}
}

// 改了期望状态但没下发时，必须报告未同步。
func TestInSyncFalseAfterPolicyChange(t *testing.T) {
	be := &kernelStyleBackend{}
	e := New(testConfig(), be, quietLogger())
	ctx := context.Background()

	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if !e.Status(ctx).InSync {
		t.Fatal("下发后应同步")
	}

	if err := e.Update(func(p *model.Policy) error {
		p.Rules = append(p.Rules, model.Rule{ID: "extra", SrcZone: "wan", DstZone: "lan", Action: model.ActionDrop})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if e.Status(ctx).InSync {
		t.Error("改了期望状态但未下发，不应报告已同步")
	}
}

// 哈希必须稳定：同一份期望状态反复取状态，哈希不能变。
func TestDesiredHashStableAcrossStatusCalls(t *testing.T) {
	be := &kernelStyleBackend{}
	e := New(testConfig(), be, quietLogger())
	ctx := context.Background()
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}

	first := e.Status(ctx).DesiredHash
	time.Sleep(1100 * time.Millisecond) // 跨过一秒，时间戳类非确定性会暴露
	second := e.Status(ctx).DesiredHash
	if first != second {
		t.Errorf("期望状态哈希随时间变化: %s -> %s", first, second)
	}
	if !e.Status(ctx).InSync {
		t.Error("哈希稳定却报告未同步")
	}
}
