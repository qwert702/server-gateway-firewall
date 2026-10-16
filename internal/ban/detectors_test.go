package ban

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 真实的 /proc/net/nf_conntrack 样本。注意 UDP/ICMP 行**没有**状态字段，
// 如果按固定下标取状态就会解析错位 —— 这是最容易踩的坑。
const conntrackSample = `ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=10.0.0.1 sport=51234 dport=22 packets=10 bytes=800 src=10.0.0.1 dst=10.0.0.5 sport=22 dport=51234 packets=8 bytes=600 [ASSURED] mark=0 use=1
ipv4     2 udp      17 28 src=10.0.0.6 dst=8.8.8.8 sport=40000 dport=53 packets=2 bytes=140 src=8.8.8.8 dst=10.0.0.6 sport=53 dport=40000 packets=1 bytes=91 mark=0 use=1
ipv4     2 icmp     1 29 src=10.0.0.7 dst=10.0.0.1 type=8 code=0 id=1234 packets=1 bytes=84 src=10.0.0.1 dst=10.0.0.7 type=0 code=0 id=1234 packets=1 bytes=84 mark=0 use=1
ipv6    10 tcp      6 431999 ESTABLISHED src=2001:db8::1 dst=2001:db8::2 sport=1234 dport=443 packets=5 bytes=400 src=2001:db8::2 dst=2001:db8::1 sport=443 dport=1234 packets=4 bytes=300 mark=0 use=1
ipv4     2 tcp      6 117 SYN_SENT src=203.0.113.9 dst=10.0.0.1 sport=40001 dport=22 packets=1 bytes=60 src=10.0.0.1 dst=203.0.113.9 sport=22 dport=40001 packets=0 bytes=0 mark=0 use=1
`

func TestParseConntrackTCPWithState(t *testing.T) {
	conns, err := ParseConntrack(strings.NewReader(conntrackSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 5 {
		t.Fatalf("应解析出 5 条连接，实际 %d", len(conns))
	}
	c := conns[0]
	if c.Proto != "tcp" || c.Src != "10.0.0.5" || c.Dst != "10.0.0.1" ||
		c.SrcPort != 51234 || c.DstPort != 22 || c.State != "ESTABLISHED" {
		t.Errorf("TCP 连接解析错误: %+v", c)
	}
	if c.Timeout != 431999*time.Second {
		t.Errorf("超时解析错误: %s", c.Timeout)
	}
}

// 没有状态字段时必须靠"下一个 token 是否含 ="来判断，不能按固定下标取。
func TestParseConntrackWithoutState(t *testing.T) {
	conns, _ := ParseConntrack(strings.NewReader(conntrackSample))

	udp := conns[1]
	if udp.Proto != "udp" {
		t.Fatalf("第 2 条应为 udp: %+v", udp)
	}
	if udp.State != "" {
		t.Errorf("UDP 无状态字段，不应解析出状态: %q", udp.State)
	}
	if udp.Src != "10.0.0.6" || udp.SrcPort != 40000 || udp.DstPort != 53 {
		t.Errorf("UDP 地址/端口解析错误（很可能错位到了状态字段）: %+v", udp)
	}

	icmp := conns[2]
	if icmp.Proto != "icmp" || icmp.Src != "10.0.0.7" {
		t.Errorf("ICMP 解析错误: %+v", icmp)
	}
}

func TestParseConntrackIPv6(t *testing.T) {
	conns, _ := ParseConntrack(strings.NewReader(conntrackSample))
	v6 := conns[3]
	if v6.Src != "2001:db8::1" || v6.DstPort != 443 {
		t.Errorf("IPv6 解析错误: %+v", v6)
	}
}

func TestParseConntrackSkipsGarbage(t *testing.T) {
	in := "这不是一条连接记录\n\n" +
		"ipv4 2 tcp 6 100 ESTABLISHED src=not-an-ip dst=10.0.0.1 sport=1 dport=2\n" +
		"ipv4 2 tcp 6 117 SYN_SENT src=203.0.113.9 dst=10.0.0.1 sport=40001 dport=22\n"
	conns, err := ParseConntrack(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 1 {
		t.Fatalf("只应解析出 1 条合法连接，实际 %d: %+v", len(conns), conns)
	}
	if conns[0].State != "SYN_SENT" {
		t.Errorf("SYN_SENT 状态解析错误: %+v", conns[0])
	}
}

func TestConnKeyDistinguishesTuples(t *testing.T) {
	a := Conn{Proto: "tcp", Src: "10.0.0.1", SrcPort: 1000, Dst: "10.0.0.2", DstPort: 80}
	b := Conn{Proto: "tcp", Src: "10.0.0.1", SrcPort: 1001, Dst: "10.0.0.2", DstPort: 80}
	c := Conn{Proto: "udp", Src: "10.0.0.1", SrcPort: 1000, Dst: "10.0.0.2", DstPort: 80}
	if a.Key() == b.Key() {
		t.Error("源端口不同的连接不应视为同一条")
	}
	if a.Key() == c.Key() {
		t.Error("协议不同的连接不应视为同一条")
	}
}

// ---- 采样与检测 ----

type fakeConntrack struct {
	content string
	opens   int
}

func (f *fakeConntrack) open(string) (io.ReadCloser, error) {
	f.opens++
	return io.NopCloser(strings.NewReader(f.content)), nil
}

func TestConntrackDetectorCountsOnlyNewConnections(t *testing.T) {
	f := &fakeConntrack{content: conntrackSample}
	d := &ConntrackDetector{open: f.open}

	// 第一次采样只建立基线，不报新增
	s1, err := d.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if len(s1.NewByIP) != 0 {
		t.Errorf("首次采样不应报告新增连接: %+v", s1.NewByIP)
	}
	if s1.Total != 5 {
		t.Errorf("总数应为 5，实际 %d", s1.Total)
	}

	// 追加一条新连接后，只有它的源地址应被计为新增
	f.content += "ipv4     2 tcp      6 117 SYN_SENT src=198.51.100.7 dst=10.0.0.1 sport=40002 dport=22 packets=1 bytes=60 src=10.0.0.1 dst=198.51.100.7 sport=22 dport=40002 packets=0 bytes=0 mark=0 use=1\n"
	s2, err := d.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.NewByIP) != 1 || s2.NewByIP["198.51.100.7"] != 1 {
		t.Errorf("应只报告那一条新连接: %+v", s2.NewByIP)
	}
}

func TestConntrackDetectorEmitsOnRateExceeded(t *testing.T) {
	f := &fakeConntrack{content: conntrackSample}
	d := &ConntrackDetector{open: f.open, MaxNewPerInterval: 2}
	if _, err := d.Sample(); err != nil { // 基线
		t.Fatal(err)
	}

	// 一个源地址突然建立 3 条新连接（阈值 2）
	for i := 0; i < 3; i++ {
		f.content += "ipv4     2 tcp      6 117 SYN_SENT src=203.0.113.50 dst=10.0.0.1 sport=4010" + itoa(i) + " dport=22 packets=1 bytes=60 src=10.0.0.1 dst=203.0.113.50 sport=22 dport=4010" + itoa(i) + " packets=0 bytes=0 mark=0 use=1\n"
	}
	s, err := d.Sample()
	if err != nil {
		t.Fatal(err)
	}

	out := make(chan Event, 16)
	d.emit(s, out, context.Background())
	close(out)

	var got []Event
	for ev := range out {
		got = append(got, ev)
	}
	if len(got) != 1 {
		t.Fatalf("应产生 1 条事件，实际 %d: %+v", len(got), got)
	}
	if got[0].IP != "203.0.113.50" || got[0].Source != "conntrack" {
		t.Errorf("事件内容不正确: %+v", got[0])
	}
	if got[0].Weight != 3 {
		t.Errorf("权重应为新增连接数 3，实际 %d", got[0].Weight)
	}
}

func TestConntrackDetectorEmitsOnConcurrency(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 30; i++ {
		b.WriteString("ipv4     2 tcp      6 117 SYN_SENT src=203.0.113.60 dst=10.0.0.1 sport=41" + itoa(100+i) + " dport=22 packets=1 bytes=60 src=10.0.0.1 dst=203.0.113.60 sport=22 dport=41" + itoa(100+i) + " packets=0 bytes=0 mark=0 use=1\n")
	}
	f := &fakeConntrack{content: b.String()}
	d := &ConntrackDetector{open: f.open, MaxConcurrent: 20}

	s, err := d.Sample()
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan Event, 16)
	d.emit(s, out, context.Background())
	close(out)

	found := false
	for ev := range out {
		if ev.IP == "203.0.113.60" && strings.Contains(ev.Reason, "并发") {
			found = true
		}
	}
	if !found {
		t.Error("并发连接超限应产生事件")
	}
}

func TestConntrackDetectorSurfacesReadErrors(t *testing.T) {
	d := &ConntrackDetector{open: func(string) (io.ReadCloser, error) {
		return nil, os.ErrNotExist
	}}
	if _, err := d.Sample(); err == nil {
		t.Fatal("文件不存在时应返回错误，好让 Run 跳过本轮而不是崩溃")
	}
}

func TestTopByConcurrent(t *testing.T) {
	s := &Sample{
		ConcByIP: map[string]int{"10.0.0.1": 3, "10.0.0.2": 9, "10.0.0.3": 5},
		NewByIP:  map[string]int{"10.0.0.2": 4},
	}
	top := s.TopByConcurrent(2)
	if len(top) != 2 {
		t.Fatalf("应返回 2 项，实际 %d", len(top))
	}
	if top[0].IP != "10.0.0.2" || top[0].Count != 9 || top[0].New != 4 {
		t.Errorf("排序或内容错误: %+v", top)
	}
}

// ---- 日志检测 ----

func TestMatchLineDefaultPatterns(t *testing.T) {
	ps, err := CompilePatterns(DefaultLogPatterns())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		line string
		want string
	}{
		{`Oct 16 10:00:00 host sshd[123]: Failed password for root from 203.0.113.9 port 51234 ssh2`, "203.0.113.9"},
		{`Oct 16 10:00:00 host sshd[123]: Failed publickey for admin from 198.51.100.7 port 1 ssh2`, "198.51.100.7"},
		{`Oct 16 10:00:00 host sshd[123]: Invalid user oracle from 192.0.2.5`, "192.0.2.5"},
		{`Oct 16 10:00:00 host sshd[123]: error: maximum authentication attempts exceeded for root from 203.0.113.10 port 1 ssh2`, "203.0.113.10"},
		{`kernel: fw: IN=eth0 SRC=203.0.113.11 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=22`, "203.0.113.11"},
	}
	for _, c := range cases {
		evs := MatchLine(ps, c.line)
		if len(evs) == 0 {
			t.Errorf("未命中: %s", c.line)
			continue
		}
		found := false
		for _, ev := range evs {
			if ev.IP == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("提取到 %v，期望 %s（行: %s）", evs, c.want, c.line)
		}
	}
}

func TestMatchLineIgnoresBenignLines(t *testing.T) {
	ps, _ := CompilePatterns(DefaultLogPatterns())
	benign := []string{
		`Oct 16 10:00:00 host sshd[1]: Accepted password for root from 10.0.0.5 port 22 ssh2`,
		`Oct 16 10:00:00 host systemd[1]: Started Session 3 of user root.`,
		``,
	}
	for _, line := range benign {
		if evs := MatchLine(ps, line); len(evs) != 0 {
			t.Errorf("正常日志不应命中: %q -> %+v", line, evs)
		}
	}
}

// 特征必须恰好一个捕获组，否则提取到的地址是错的。
func TestCompilePatternsRejectsBadRegex(t *testing.T) {
	bad := [][]LogPattern{
		{{Name: "no-group", Regex: `failed from \S+`}},
		{{Name: "two-groups", Regex: `from (\S+) port (\d+)`}},
		{{Name: "broken", Regex: `(`}},
		{{Name: "", Regex: `(\S+)`}},
	}
	for _, in := range bad {
		if _, err := CompilePatterns(in); err == nil {
			t.Errorf("应拒绝: %+v", in)
		}
	}
}

func TestLogWatcherReadsOnlyNewContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte("history line with Failed password for root from 1.1.1.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ps, _ := CompilePatterns(DefaultLogPatterns())
	w := &LogWatcher{Path: path, Patterns: ps, FromEnd: true}

	out := make(chan Event, 16)
	// 第一次轮询只establish基线，不应产出历史事件
	if err := w.PollOnce(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-out:
		t.Fatalf("首次轮询不应产出历史日志事件: %+v", ev)
	default:
	}

	// 追加新内容
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("Oct 16 10:00:00 host sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2\n")
	f.Close()

	if err := w.PollOnce(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-out:
		if ev.IP != "203.0.113.9" {
			t.Errorf("提取地址错误: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("新增日志应产出事件")
	}

	// 没有新内容时不应重复产出
	if err := w.PollOnce(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-out:
		t.Fatalf("无新内容时不应重复产出: %+v", ev)
	default:
	}
}

// 日志轮转（文件被截断）后必须从头读，否则会永远卡在旧偏移上。
func TestLogWatcherHandlesTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	long := strings.Repeat("padding line\n", 50)
	if err := os.WriteFile(path, []byte(long), 0o600); err != nil {
		t.Fatal(err)
	}

	ps, _ := CompilePatterns(DefaultLogPatterns())
	w := &LogWatcher{Path: path, Patterns: ps, FromEnd: true}
	out := make(chan Event, 16)
	if err := w.PollOnce(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	// 轮转：文件变成很短的新文件
	if err := os.WriteFile(path, []byte("Oct 16 10:00:00 host sshd[1]: Failed password for root from 198.51.100.9 port 1 ssh2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.PollOnce(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-out:
		if ev.IP != "198.51.100.9" {
			t.Errorf("轮转后提取地址错误: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("轮转后应能读到新文件内容")
	}
}

func TestLogWatcherMissingFileIsNotFatal(t *testing.T) {
	ps, _ := CompilePatterns(DefaultLogPatterns())
	w := &LogWatcher{Path: filepath.Join(t.TempDir(), "nope.log"), Patterns: ps}
	if err := w.PollOnce(context.Background(), make(chan Event, 1)); err == nil {
		t.Error("文件不存在时应返回错误，由调用方跳过本轮")
	}
}

func TestDetectorsReportNames(t *testing.T) {
	if (&ConntrackDetector{}).Name() != "conntrack" {
		t.Error("conntrack 检测器名称错误")
	}
	if got := (&LogWatcher{Path: "/var/log/auth.log"}).Name(); !strings.HasPrefix(got, "log:") {
		t.Errorf("日志检测器名称错误: %q", got)
	}
}
