package ban

import (
	"context"
	"strings"
	"testing"
	"time"
)

// fakeClock 让滑动窗口与递进惩罚可以被确定性地测试。
type fakeClock struct{ t time.Time }

func newClock() *fakeClock                   { return &fakeClock{t: time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)} }
func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func newEngine(t *testing.T, clk *fakeClock, mutate func(*Settings)) *Engine {
	t.Helper()
	cfg := DefaultSettings()
	cfg.Enabled = true
	cfg.Window = time.Minute
	cfg.Threshold = 5
	cfg.BaseTTL = time.Minute
	cfg.Multiplier = 2
	cfg.MaxTTL = time.Hour
	cfg.StrikeResetAfter = time.Hour
	if mutate != nil {
		mutate(&cfg)
	}
	e, err := New(cfg, WithClock(clk.Now))
	if err != nil {
		t.Fatalf("创建引擎失败: %v", err)
	}
	return e
}

func TestBelowThresholdDoesNotBan(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, nil)

	for i := 0; i < 4; i++ {
		d := e.Observe(Event{IP: "203.0.113.9", Source: "ssh"})
		if d.Action != ActionIgnore {
			t.Fatalf("第 %d 次事件不应封禁: %+v", i+1, d)
		}
		if d.EventCount != i+1 {
			t.Errorf("事件计数应为 %d，实际 %d", i+1, d.EventCount)
		}
	}
}

func TestReachingThresholdBans(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, nil)

	var last Decision
	for i := 0; i < 5; i++ {
		last = e.Observe(Event{IP: "203.0.113.9", Source: "ssh"})
	}
	if last.Action != ActionBan {
		t.Fatalf("达到阈值应封禁: %+v", last)
	}
	if last.TTL != time.Minute {
		t.Errorf("首次封禁时长应为 base_ttl=1m，实际 %s", last.TTL)
	}
	if last.Strikes != 1 {
		t.Errorf("应为第 1 次违规，实际 %d", last.Strikes)
	}
	if !strings.Contains(last.Reason, "ssh") {
		t.Errorf("原因应注明来源: %q", last.Reason)
	}
}

func TestWeightsAreRespected(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, nil)

	// 单条权重 5 的事件即可触发（阈值 5）
	d := e.Observe(Event{IP: "203.0.113.9", Source: "nft", Weight: 5})
	if d.Action != ActionBan {
		t.Fatalf("高权重事件应直接触发封禁: %+v", d)
	}
}

func TestWindowSlidesOut(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, nil)

	for i := 0; i < 4; i++ {
		e.Observe(Event{IP: "203.0.113.9", Source: "ssh"})
	}
	// 滑过窗口后，旧事件应失效
	clk.Advance(2 * time.Minute)
	d := e.Observe(Event{IP: "203.0.113.9", Source: "ssh"})
	if d.Action != ActionIgnore {
		t.Fatalf("窗口外的旧事件不应计入: %+v", d)
	}
	if d.EventCount != 1 {
		t.Errorf("窗口内应只剩 1 条事件，实际 %d", d.EventCount)
	}
}

func TestEscalatingPenalty(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, nil)

	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute}
	for i, wantTTL := range want {
		// 每个封禁周期结束后再来一轮
		if i > 0 {
			clk.Advance(want[i-1] + time.Second)
		}
		var d Decision
		for j := 0; j < 5; j++ {
			d = e.Observe(Event{IP: "203.0.113.9", Source: "ssh"})
		}
		if d.Action != ActionBan {
			t.Fatalf("第 %d 轮应封禁: %+v", i+1, d)
		}
		if d.TTL != wantTTL {
			t.Errorf("第 %d 次违规时长应为 %s，实际 %s（递进惩罚未生效）", i+1, wantTTL, d.TTL)
		}
	}
}

func TestPenaltyIsCappedByMaxTTL(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, func(s *Settings) {
		s.BaseTTL = 10 * time.Minute
		s.MaxTTL = 15 * time.Minute
		s.Multiplier = 4
	})

	var d Decision
	for j := 0; j < 5; j++ {
		d = e.Observe(Event{IP: "203.0.113.9"})
	}
	if d.Action != ActionBan {
		t.Fatal("应封禁")
	}
	if d.TTL > 15*time.Minute {
		t.Errorf("封禁时长不得超过 max_ttl，实际 %s", d.TTL)
	}
}

func TestStrikesResetAfterQuietPeriod(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, func(s *Settings) { s.StrikeResetAfter = time.Hour })

	// 第一次违规
	var d Decision
	for j := 0; j < 5; j++ {
		d = e.Observe(Event{IP: "203.0.113.9"})
	}
	if d.Strikes != 1 {
		t.Fatalf("应为第 1 次，实际 %d", d.Strikes)
	}

	// 安静很久之后再次违规：惩罚应清零重来，而不是直接翻倍
	clk.Advance(25 * time.Hour)
	d = e.Observe(Event{IP: "203.0.113.9"})
	if d.Action != ActionIgnore && d.Action != ActionObserve {
		t.Fatalf("长期安静后单次事件不应立刻封禁: %+v", d)
	}
	for j := 0; j < 4; j++ {
		d = e.Observe(Event{IP: "203.0.113.9"})
	}
	if d.Action != ActionBan {
		t.Fatalf("应再次封禁: %+v", d)
	}
	if d.Strikes != 1 {
		t.Errorf("违规次数应已重置为 1，实际 %d", d.Strikes)
	}
	if d.TTL != time.Minute {
		t.Errorf("时长应回到 base_ttl，实际 %s", d.TTL)
	}
}

// 已在封禁期内收到新事件不应重复下发封禁（避免封禁风暴与审计刷屏）。
func TestNoBanStormWhileBanned(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, nil)
	banCount := 0
	e.onDecision = func(d Decision) {
		if d.Action == ActionBan {
			banCount++
		}
	}

	for j := 0; j < 5; j++ {
		e.Observe(Event{IP: "203.0.113.9"})
	}
	if banCount != 1 {
		t.Fatalf("应封禁 1 次，实际 %d", banCount)
	}
	for j := 0; j < 20; j++ {
		d := e.Observe(Event{IP: "203.0.113.9"})
		if d.Action == ActionBan {
			t.Fatalf("封禁期内不应重复封禁: %+v", d)
		}
	}
	if banCount != 1 {
		t.Errorf("封禁次数不应增加，实际 %d", banCount)
	}
}

// 封禁后窗口必须清空，否则解封瞬间会因残留计数立刻再次触发。
func TestWindowClearedAfterBan(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, nil)

	for j := 0; j < 5; j++ {
		e.Observe(Event{IP: "203.0.113.9"})
	}
	// 恰好解封
	clk.Advance(time.Minute + time.Second)
	d := e.Observe(Event{IP: "203.0.113.9"})
	if d.Action != ActionIgnore {
		t.Fatalf("解封后单条事件不应立刻再次封禁: %+v", d)
	}
	if d.EventCount != 1 {
		t.Errorf("封禁后窗口应清空，实际计数 %d", d.EventCount)
	}
}

func TestWhitelistNeverBans(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, func(s *Settings) {
		s.Whitelist = []string{"10.0.0.0/8", "192.168.1.1"}
	})

	for j := 0; j < 50; j++ {
		d := e.Observe(Event{IP: "10.1.2.3"})
		if d.Action == ActionBan {
			t.Fatalf("白名单网段内的地址不应被封禁: %+v", d)
		}
	}
	for j := 0; j < 50; j++ {
		d := e.Observe(Event{IP: "192.168.1.1"})
		if d.Action == ActionBan {
			t.Fatalf("白名单单 IP 不应被封禁: %+v", d)
		}
	}
	if s := e.Stats(); s.Observed != 0 {
		t.Errorf("白名单地址不应计入观察统计，实际 %d", s.Observed)
	}
}

// 未开启封禁时只观察并给出提示，便于先跑一段时间评估误报率。
func TestDisabledEngineOnlyObserves(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, func(s *Settings) { s.Enabled = false })

	var d Decision
	for j := 0; j < 5; j++ {
		d = e.Observe(Event{IP: "203.0.113.9"})
	}
	if d.Action != ActionObserve {
		t.Fatalf("未开启时应给出 observe: %+v", d)
	}
	if d.TTL != 0 {
		t.Errorf("未开启时不应给出封禁时长: %s", d.TTL)
	}
	if !strings.Contains(d.Reason, "未开启") {
		t.Errorf("原因应说明未开启自动封禁: %q", d.Reason)
	}
	if s := e.Stats(); s.Banned != 0 {
		t.Errorf("未开启时不应有封禁: %+v", s)
	}
}

func TestRuntimeToggle(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, func(s *Settings) { s.Enabled = false })

	for j := 0; j < 5; j++ {
		e.Observe(Event{IP: "203.0.113.9"})
	}
	e.SetEnabled(true)
	d := e.Observe(Event{IP: "203.0.113.9"})
	if d.Action != ActionBan {
		t.Fatalf("打开开关后应开始封禁: %+v", d)
	}
}

func TestInvalidIPIgnored(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, nil)
	d := e.Observe(Event{IP: "not-an-ip"})
	if d.Action != ActionIgnore || !strings.Contains(d.Reason, "非法") {
		t.Errorf("非法地址应被忽略并说明原因: %+v", d)
	}
}

func TestMaxTrackedBoundsMemory(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, func(s *Settings) { s.MaxTracked = 10 })

	// 模拟海量随机源地址的扫描
	for i := 0; i < 100; i++ {
		e.Observe(Event{IP: "203.0.113." + itoa(i)})
	}
	if s := e.Stats(); s.Tracked > 10 {
		t.Errorf("跟踪表超过上限: %d", s.Tracked)
	}
	if s := e.Stats(); s.Dropped == 0 {
		t.Error("被丢弃的来源应有计数，便于发现攻击规模")
	}
}

func TestIPv6Handled(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, func(s *Settings) { s.Whitelist = []string{"2001:db8::/32"} })

	d := e.Observe(Event{IP: "2001:db8::dead"})
	if d.Action != ActionIgnore || !strings.Contains(d.Reason, "白名单") {
		t.Errorf("IPv6 白名单应生效: %+v", d)
	}
	for j := 0; j < 5; j++ {
		d = e.Observe(Event{IP: "2001:dead::1"})
	}
	if d.Action != ActionBan {
		t.Errorf("IPv6 地址应能正常封禁: %+v", d)
	}
}

func TestForgetClearsState(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, nil)
	for j := 0; j < 4; j++ {
		e.Observe(Event{IP: "203.0.113.9"})
	}
	e.Forget("203.0.113.9")
	d := e.Observe(Event{IP: "203.0.113.9"})
	if d.EventCount != 1 {
		t.Errorf("Forget 后应重新计数，实际 %d", d.EventCount)
	}
}

func TestOffendersSortedByScore(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, nil)
	for j := 0; j < 3; j++ {
		e.Observe(Event{IP: "203.0.113.1"})
	}
	for j := 0; j < 2; j++ {
		e.Observe(Event{IP: "203.0.113.2"})
	}
	off := e.Offenders()
	if len(off) != 2 {
		t.Fatalf("应跟踪 2 个地址，实际 %d", len(off))
	}
	if off[0].IP != "203.0.113.1" || off[0].Score != 3 {
		t.Errorf("应按可疑度倒序: %+v", off)
	}
}

func TestStatsReflectsBans(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, nil)
	for j := 0; j < 5; j++ {
		e.Observe(Event{IP: "203.0.113.9"})
	}
	s := e.Stats()
	if !s.Enabled || s.Banned != 1 || s.Threshold != 5 || s.Window != time.Minute {
		t.Errorf("统计不正确: %+v", s)
	}
}

func TestDecisionsNewestFirst(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, nil)
	e.Observe(Event{IP: "203.0.113.1"})
	clk.Advance(time.Second)
	e.Observe(Event{IP: "203.0.113.2"})

	ds := e.Decisions()
	if len(ds) != 2 {
		t.Fatalf("应有 2 条决策，实际 %d", len(ds))
	}
	if ds[0].IP != "203.0.113.2" {
		t.Errorf("决策应最新在前: %+v", ds)
	}
}

func TestDecisionsAreBounded(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, nil)
	for i := 0; i < 800; i++ {
		e.Observe(Event{IP: "203.0.113." + itoa(i%250)})
	}
	if n := len(e.Decisions()); n > 600 {
		t.Errorf("决策记录应有上限，实际 %d 条", n)
	}
}

func TestSettingsValidation(t *testing.T) {
	bad := []Settings{
		{BaseTTL: time.Hour, MaxTTL: time.Minute}, // max < base
		{Whitelist: []string{"不是地址"}},             // 白名单非法
	}
	for _, s := range bad {
		if err := s.Normalize(); err == nil {
			t.Errorf("应拒绝非法配置: %+v", s)
		}
	}
	// 零值应被补齐为默认值
	var s Settings
	if err := s.Normalize(); err != nil {
		t.Fatal(err)
	}
	if s.Window == 0 || s.Threshold == 0 || s.BaseTTL == 0 {
		t.Errorf("零值应补齐默认值: %+v", s)
	}
}

func TestAttachSinkReceivesBan(t *testing.T) {
	clk := newClock()
	e := newEngine(t, clk, nil)

	got := make(chan Decision, 1)
	e.AttachSink(sinkFunc(func(ctx context.Context, ip, reason string, ttl time.Duration) error {
		got <- Decision{IP: ip, TTL: ttl, Reason: reason}
		return nil
	}))

	for j := 0; j < 5; j++ {
		e.Observe(Event{IP: "203.0.113.9", Reason: "爆破"})
	}
	select {
	case d := <-got:
		if d.IP != "203.0.113.9" || d.TTL != time.Minute {
			t.Errorf("Sink 收到的封禁不正确: %+v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Sink 未收到封禁")
	}
}

type sinkFunc func(context.Context, string, string, time.Duration) error

func (f sinkFunc) BanIP(ctx context.Context, ip, reason string, ttl time.Duration) error {
	return f(ctx, ip, reason, ttl)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
