package nftables

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"fwdd/internal/backend"
	"fwdd/internal/compiler"
	"fwdd/internal/ir"
	"fwdd/internal/model"
)

// fakeRunner 记录收到的 nft 事务，并可注入错误。
type fakeRunner struct {
	calls   []call
	respond func(args []string) (string, string, error)
}

type call struct {
	stdin string
	args  []string
}

func (f *fakeRunner) Run(_ context.Context, stdin string, args ...string) (string, string, error) {
	f.calls = append(f.calls, call{stdin: stdin, args: args})
	if f.respond != nil {
		return f.respond(args)
	}
	return "", "", nil
}

func (f *fakeRunner) last() call { return f.calls[len(f.calls)-1] }

func testSnapshot(t *testing.T) *ir.Snapshot {
	t.Helper()
	p := &model.Policy{
		Zones: []model.Zone{{Name: "lan", Interfaces: []string{"eth1"}}, {Name: "wan", Interfaces: []string{"eth0"}}},
		Rules: []model.Rule{{
			ID: "web", SrcZone: "lan", DstZone: "wan", Proto: model.ProtoTCP,
			DstPort: []string{"443"}, State: []string{"new"}, Action: model.ActionAccept,
		}},
		Default: model.DefaultPolicy{Forward: model.ActionDrop},
	}
	res, err := compiler.Compile(p, compiler.Options{TableName: "fw", Counters: true})
	if err != nil {
		t.Fatal(err)
	}
	return res.Snapshot
}

func TestApplyUsesSingleAtomicTransaction(t *testing.T) {
	fr := &fakeRunner{}
	b := New(WithRunner(fr))

	if err := b.Apply(context.Background(), testSnapshot(t)); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	if len(fr.calls) != 1 {
		t.Fatalf("Apply 应只调用一次 nft，实际 %d 次", len(fr.calls))
	}

	c := fr.last()
	if got := strings.Join(c.args, " "); got != "-f -" {
		t.Errorf("nft 参数 = %q, 期望 \"-f -\"", got)
	}

	// 事务必须依次包含：建表占位 → 删表 → 新表
	order := []string{"table inet fw { }", "delete table inet fw", "table inet fw {"}
	pos := 0
	for _, want := range order {
		i := strings.Index(c.stdin[pos:], want)
		if i < 0 {
			t.Fatalf("事务中缺少 %q（顺序应为 %v）\n%s", want, order, c.stdin)
		}
		pos += i + len(want)
	}
	if !strings.Contains(c.stdin, "policy drop") {
		t.Errorf("未包含默认策略:\n%s", c.stdin)
	}
}

func TestApplyPropagatesNftError(t *testing.T) {
	fr := &fakeRunner{respond: func([]string) (string, string, error) {
		return "", "Error: syntax error, unexpected newline", errors.New("exit status 1")
	}}
	b := New(WithRunner(fr))

	err := b.Apply(context.Background(), testSnapshot(t))
	if err == nil {
		t.Fatal("nft 报错时 Apply 必须失败")
	}
	if !strings.Contains(err.Error(), "syntax error") {
		t.Errorf("错误应包含 nft 的 stderr，实际: %v", err)
	}
}

func TestApplyRejectsMismatchedTable(t *testing.T) {
	b := New(WithRunner(&fakeRunner{}), WithTable("inet", "firewall"))
	err := b.Apply(context.Background(), testSnapshot(t)) // 快照表名为 fw
	if err == nil {
		t.Fatal("表名不匹配应被拒绝")
	}
}

func TestRenderIsDryRun(t *testing.T) {
	fr := &fakeRunner{}
	b := New(WithRunner(fr))

	out, err := b.Render(context.Background(), testSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 0 {
		t.Errorf("Render 不得调用 nft，实际调用 %d 次", len(fr.calls))
	}
	if !strings.Contains(out, "table inet fw {") || !strings.Contains(out, `tcp dport 443`) {
		t.Errorf("渲染内容不完整:\n%s", out)
	}
}

func TestSetAddRendersTimeout(t *testing.T) {
	fr := &fakeRunner{}
	b := New(WithRunner(fr))

	err := b.SetAdd(context.Background(), "banned4",
		ir.Element{Key: "203.0.113.9", Timeout: 2 * time.Hour, Comment: "ssh 爆破"},
		ir.Element{Key: "203.0.113.10"},
	)
	if err != nil {
		t.Fatal(err)
	}
	got := fr.last().stdin
	want := `add element inet fw banned4 { 203.0.113.9 timeout 2h comment "ssh 爆破", 203.0.113.10 }`
	if !strings.Contains(got, want) {
		t.Errorf("集合注入渲染错误\n got: %s\nwant: %s", strings.TrimSpace(got), want)
	}
}

func TestSetDelToleratesMissingElement(t *testing.T) {
	fr := &fakeRunner{respond: func([]string) (string, string, error) {
		return "", "Error: Could not process rule: No such file or directory", errors.New("exit status 1")
	}}
	b := New(WithRunner(fr))

	if err := b.SetDel(context.Background(), "banned4", "203.0.113.9"); err != nil {
		t.Errorf("删除不存在的元素应被忽略，实际报错: %v", err)
	}
}

func TestStateParsesJSON(t *testing.T) {
	const sample = `{"nftables":[
		{"metainfo":{"version":"1.0.9"}},
		{"table":{"family":"inet","name":"fw","handle":1}},
		{"chain":{"family":"inet","table":"fw","name":"forward","handle":1,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
		{"rule":{"family":"inet","table":"fw","chain":"forward","handle":5,"expr":[]}},
		{"rule":{"family":"inet","table":"fw","chain":"forward","handle":6,"expr":[]}},
		{"set":{"family":"inet","table":"fw","name":"banned4","type":"ipv4_addr","flags":["timeout"]}},
		{"element":{"family":"inet","table":"fw","name":"banned4","elem":[{"val":"203.0.113.9","expires":3599}]}}
	]}`
	fr := &fakeRunner{respond: func(args []string) (string, string, error) {
		if args[0] == "-j" {
			return sample, "", nil
		}
		return "table inet fw {\n}\n", "", nil
	}}
	b := New(WithRunner(fr))

	st, err := b.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Chains) != 1 || st.Chains[0].Name != "forward" || st.Chains[0].Rules != 2 {
		t.Errorf("链解析错误: %+v", st.Chains)
	}
	if st.Chains[0].Policy != "drop" {
		t.Errorf("链策略解析错误: %+v", st.Chains[0])
	}
	if len(st.Sets) != 1 || st.Sets[0].Name != "banned4" || st.Sets[0].Elements != 1 {
		t.Errorf("集合解析错误: %+v", st.Sets)
	}
}

func TestStateHandlesMissingTable(t *testing.T) {
	fr := &fakeRunner{respond: func([]string) (string, string, error) {
		return "", "Error: No such file or directory", errors.New("exit status 1")
	}}
	b := New(WithRunner(fr))

	st, err := b.State(context.Background())
	if err != nil {
		t.Fatalf("表不存在不应报错: %v", err)
	}
	if st.Note == "" {
		t.Error("表不存在时应给出说明")
	}
}

var _ backend.Backend = (*Backend)(nil)

// 集合属于**表**，不属于地址族。
//
// 曾经按集合名后缀推断族（banned4 → ip），在 inet 表上生成的
// `add element ip fw banned4 {...}` 会被 nft 拒绝：
//
//	No such file or directory; did you mean table 'fw' in family inet?
//
// 结果是封禁在真机上完全不生效 —— 而且是静默的，日志里只有一行 nft 报错。
// 这个 bug 只在真机 netns 测试里暴露过：mock 后端不校验族，
// 伪造 runner 也只比对命令文本。
func TestSetOperationsUseTableFamily(t *testing.T) {
	cases := []struct {
		family string
		want   string
	}{
		{"inet", "inet fw banned4"}, // 最常用：inet 表同时覆盖 v4/v6
		{"ip", "ip fw banned4"},     // 纯 v4 表
		{"ip6", "ip6 fw banned4"},   // 纯 v6 表
	}
	for _, c := range cases {
		fr := &fakeRunner{}
		b := New(WithRunner(fr), WithTable(c.family, "fw"))

		if err := b.SetAdd(context.Background(), "banned4", ir.Element{Key: "203.0.113.9"}); err != nil {
			t.Fatalf("%s: SetAdd 失败: %v", c.family, err)
		}
		got := fr.last().stdin
		if !strings.Contains(got, "add element "+c.want) {
			t.Errorf("SetAdd 应使用表族 %s，实际:\n%s", c.family, got)
		}

		if err := b.SetDel(context.Background(), "banned4", "203.0.113.9"); err != nil {
			t.Fatalf("%s: SetDel 失败: %v", c.family, err)
		}
		if got := fr.last().stdin; !strings.Contains(got, "delete element "+c.want) {
			t.Errorf("SetDel 应使用表族 %s，实际:\n%s", c.family, got)
		}
	}
}

// Render 必须对同一份快照给出逐字节相同的结果。
//
// 这是同类错误的第二次出现（第一次是封禁元素把剩余时长编译进快照）：
// 只要产物里有随时间变化的东西，对账哈希就会永远对不上，
// 表现为 fw status 永远"未同步"、每次 apply 都报"有变化"。
// 前一次是 header 里带了 time.Now()。
func TestRenderIsDeterministicOverTime(t *testing.T) {
	b := New(WithRunner(&fakeRunner{}))
	snap := testSnapshot(t)
	ctx := context.Background()

	first, err := b.Render(ctx, snap)
	if err != nil {
		t.Fatal(err)
	}
	// 跨过一秒再渲染一次 —— 时间戳类的非确定性会在这里暴露
	time.Sleep(1100 * time.Millisecond)
	second, err := b.Render(ctx, snap)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("同一快照两次渲染结果不同 —— 产物里混入了随时间变化的内容:\n--- 第一次 ---\n%s\n--- 第二次 ---\n%s",
			first, second)
	}
}
