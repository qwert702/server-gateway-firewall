package ban

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Conn 是一条 conntrack 连接记录。
type Conn struct {
	Proto   string `json:"proto"`
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	SrcPort int    `json:"src_port,omitempty"`
	DstPort int    `json:"dst_port,omitempty"`
	State   string `json:"state,omitempty"`
	// Timeout 是内核给这条连接的剩余生存时间。
	Timeout time.Duration `json:"timeout,omitempty"`
}

// Key 返回连接的唯一标识（五元组），用于比较两次采样之间的新增连接。
func (c Conn) Key() string {
	return fmt.Sprintf("%s|%s|%d|%s|%d", c.Proto, c.Src, c.SrcPort, c.Dst, c.DstPort)
}

// ParseConntrack 解析 /proc/net/nf_conntrack 的内容。
//
// 行格式（内核 4.x/5.x/6.x）：
//
//	ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.5 dst=10.0.0.1 sport=51234 dport=22 \
//	     packets=10 bytes=800 src=... dst=... sport=22 dport=51234 [ASSURED] mark=0 use=1
//
// 非 TCP 协议（udp/icmp）没有状态字段，因此状态是可选的 —— 不能写死字段位置。
func ParseConntrack(r io.Reader) ([]Conn, error) {
	var out []Conn
	sc := bufio.NewScanner(r)
	// conntrack 表可能很大，单行也可能很长，放宽缓冲区。
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if c, ok := parseConntrackLine(line); ok {
			out = append(out, c)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("读取 conntrack 失败: %w", err)
	}
	return out, nil
}

func parseConntrackLine(line string) (Conn, bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return Conn{}, false
	}
	// 头部：family l3num proto l4num timeout [state]
	c := Conn{Proto: fields[2]}
	idx := 4
	if len(fields) > idx {
		if n, err := strconv.Atoi(fields[idx]); err == nil {
			c.Timeout = time.Duration(n) * time.Second
			idx++
		}
	}
	if idx < len(fields) && !strings.Contains(fields[idx], "=") {
		c.State = fields[idx]
		idx++
	}
	// TCP 的复合状态形如 SYN_SENT（单个 token），无需额外处理。
	// 后面是两组 (src,dst,sport,dport)，只取第一组。
	for _, f := range fields[idx:] {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "src":
			if c.Src == "" {
				c.Src = v
			}
		case "dst":
			if c.Dst == "" {
				c.Dst = v
			}
		case "sport":
			if c.SrcPort == 0 {
				c.SrcPort = atoiSafe(v)
			}
		case "dport":
			if c.DstPort == 0 {
				c.DstPort = atoiSafe(v)
			}
		case "timeout":
			if c.Timeout == 0 {
				if n, err := strconv.Atoi(v); err == nil {
					c.Timeout = time.Duration(n) * time.Second
				}
			}
		}
		if c.Src != "" && c.Dst != "" && c.SrcPort != 0 && c.DstPort != 0 {
			break
		}
	}
	if c.Src == "" || net.ParseIP(c.Src) == nil {
		return Conn{}, false
	}
	return c, true
}

func atoiSafe(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// ConntrackDetector 通过轮询 conntrack 表发现异常：单个源地址的连接速率
// 或并发连接数超限。
//
// 用"两次采样之差"来判断新增连接，而不是读内核计数器 —— 后者需要额外的
// nf_conntrack_acct 配置，前者在任何内核上都能用。
type ConntrackDetector struct {
	// Path 通常是 /proc/net/nf_conntrack（部分系统为 /proc/net/ip_conntrack）。
	Path string
	// Interval 是采样周期。
	Interval time.Duration
	// MaxNewPerInterval：单个源地址在一个采样周期内新增连接数超过该值即告警。
	MaxNewPerInterval int
	// MaxConcurrent：单个源地址并发连接数超过该值即告警。
	MaxConcurrent int
	// MinIntervalForRate 用作速率下限的保护：采样间隔过短时计数噪声大。
	// IgnoreWhitelist 为 true 时不产出白名单地址的事件（由判罚引擎再兜一次）。
	IgnoreWhitelist []string

	// open 允许测试注入文件读取。
	open func(string) (io.ReadCloser, error)

	prev map[string]struct{}
}

// Name 实现 Detector。
func (d *ConntrackDetector) Name() string { return "conntrack" }

// Detector 是事件来源。
type Detector interface {
	Name() string
	Run(ctx context.Context, out chan<- Event) error
}

// Sample 读一次 conntrack 表并计算本周期内的新增与并发统计。
//
// 抽成公开方法是为了能脱离定时循环单独测试。
type Sample struct {
	Total    int            `json:"total"`
	NewByIP  map[string]int `json:"new_by_ip"`
	ConcByIP map[string]int `json:"concurrent_by_ip"`
	At       time.Time      `json:"at"`
}

// Sample 执行一次采样。第一次调用时"新增"为空（没有可比对的基线）。
func (d *ConntrackDetector) Sample() (*Sample, error) {
	open := d.open
	if open == nil {
		open = func(p string) (io.ReadCloser, error) { return os.Open(p) }
	}
	path := d.Path
	if path == "" {
		path = "/proc/net/nf_conntrack"
	}
	f, err := open(path)
	if err != nil {
		return nil, fmt.Errorf("打开 %s 失败: %w", path, err)
	}
	defer f.Close()

	conns, err := ParseConntrack(f)
	if err != nil {
		return nil, err
	}

	cur := make(map[string]struct{}, len(conns))
	newByIP := map[string]int{}
	concByIP := map[string]int{}
	for _, c := range conns {
		k := c.Key()
		cur[k] = struct{}{}
		concByIP[c.Src]++
		if d.prev != nil {
			if _, seen := d.prev[k]; !seen {
				newByIP[c.Src]++
			}
		}
	}
	d.prev = cur

	return &Sample{Total: len(conns), NewByIP: newByIP, ConcByIP: concByIP, At: time.Now()}, nil
}

// Run 实现 Detector：周期性采样并把超限的源地址转成事件。
func (d *ConntrackDetector) Run(ctx context.Context, out chan<- Event) error {
	interval := d.Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		s, err := d.Sample()
		if err != nil {
			// 读不到 conntrack（模块未加载、无权限）不应中断整个守护进程。
			continue
		}
		d.emit(s, out, ctx)
	}
}

func (d *ConntrackDetector) emit(s *Sample, out chan<- Event, ctx context.Context) {
	send := func(ev Event) bool {
		select {
		case out <- ev:
			return true
		case <-ctx.Done():
			return false
		}
	}

	for ip, n := range s.NewByIP {
		if d.MaxNewPerInterval > 0 && n > d.MaxNewPerInterval {
			if !send(Event{IP: ip, Source: "conntrack", Weight: n,
				Reason: fmt.Sprintf("采样周期内新建 %d 个连接（阈值 %d）", n, d.MaxNewPerInterval)}) {
				return
			}
		}
	}
	for ip, n := range s.ConcByIP {
		if d.MaxConcurrent > 0 && n > d.MaxConcurrent {
			if !send(Event{IP: ip, Source: "conntrack", Weight: 1,
				Reason: fmt.Sprintf("并发连接 %d 个（阈值 %d）", n, d.MaxConcurrent)}) {
				return
			}
		}
	}
}

// TopByConcurrent 返回并发连接数最高的若干源地址，供展示与调参。
func (s *Sample) TopByConcurrent(n int) []IPCount {
	out := make([]IPCount, 0, len(s.ConcByIP))
	for ip, c := range s.ConcByIP {
		out = append(out, IPCount{IP: ip, Count: c, New: s.NewByIP[ip]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].IP < out[j].IP
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// IPCount 是地址到计数的映射项。
type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
	New   int    `json:"new,omitempty"`
}
