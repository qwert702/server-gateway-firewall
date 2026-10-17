package ban

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

// LogPattern 是一条日志特征。
//
// 约定：正则有且只有一个捕获组，捕获的是**违规来源地址**。
// 这样匹配逻辑不需要知道各种日志格式的差异。
type LogPattern struct {
	// Name 用于展示与审计，如 "ssh-auth-fail"。
	Name string `json:"name"`
	// Regex 源串（正则），必须含一个捕获 IP 的组。
	Regex string `json:"regex"`
	// Weight 是该特征的可疑权重，用于区分"一次探测"和"持续爆破"。
	Weight int `json:"weight,omitempty"`

	re *regexp.Regexp
}

// Compile 编译所有特征。
func CompilePatterns(in []LogPattern) ([]LogPattern, error) {
	out := make([]LogPattern, 0, len(in))
	for _, p := range in {
		if p.Name == "" {
			return nil, fmt.Errorf("日志特征缺少 name")
		}
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("日志特征 %s 的正则非法: %w", p.Name, err)
		}
		if re.NumSubexp() != 1 {
			return nil, fmt.Errorf("日志特征 %s 必须恰好含 1 个捕获组（用于提取来源地址），实际 %d 个",
				p.Name, re.NumSubexp())
		}
		if p.Weight <= 0 {
			p.Weight = 1
		}
		p.re = re
		out = append(out, p)
	}
	return out, nil
}

// DefaultLogPatterns 返回开箱可用的特征集。
//
// 只收录"命中即明确可疑"的模式，宁缺毋滥 —— 自动封禁的误报代价很高。
func DefaultLogPatterns() []LogPattern {
	return []LogPattern{
		{Name: "ssh-auth-fail", Weight: 2,
			Regex: `Failed (?:password|publickey) for .*? from (\S+)`},
		{Name: "ssh-invalid-user", Weight: 2,
			Regex: `Invalid user \S+ from (\S+)`},
		{Name: "ssh-max-attempts", Weight: 3,
			Regex: `error: maximum authentication attempts exceeded for \S+ from (\S+)`},
		// 本工具自己生成的限速/记录日志。
		//
		// **必须带 "fw: " 前缀**。早先的写法只匹配 `SRC=(...)`，那会命中任何
		// nft/ufw 的日志行 —— 装了 ufw 的机器上，每个被拦下的扫描包都会被算成
		// 一次攻击事件，把"ufw 拦了一个包"和"这个 IP 在攻击"混为一谈。
		{Name: "fw-rate-limit", Weight: 3,
			Regex: `fw: .*SRC=(\d{1,3}(?:\.\d{1,3}){3})`},
		// 如果确实希望"被 ufw 拦下的扫描包也计入攻击事件"，取消下面一行的注释。
		// 注意它会把正常的误连（比如连错端口）也算进去。
		// {Name: "ufw-block", Weight: 1, Regex: `\[UFW BLOCK\].*SRC=(\d{1,3}(?:\.\d{1,3}){3})`},
	}
}

// MatchLine 检查一行日志是否命中任一特征。
//
// 纯函数：不碰文件系统，便于用固定日志样本做回归测试。
func MatchLine(patterns []LogPattern, line string) []Event {
	var out []Event
	for _, p := range patterns {
		if p.re == nil {
			continue
		}
		m := p.re.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		ip := strings.TrimSpace(m[1])
		// sshd 有时把地址写成 "1.2.3.4 port 5678"，取第一段。
		if i := strings.IndexByte(ip, ' '); i > 0 {
			ip = ip[:i]
		}
		if ip == "" {
			continue
		}
		out = append(out, Event{
			IP:     ip,
			Source: "log:" + p.Name,
			Weight: p.Weight,
			Reason: fmt.Sprintf("日志命中 %s", p.Name),
		})
	}
	return out
}

// LogWatcher 跟踪一个日志文件并产出事件。
//
// 只做增量读：记录读取偏移，轮转（文件被截断或替换）时自动从头开始。
// 依赖外部轮转工具（logrotate）而不是自己管理文件生命周期。
type LogWatcher struct {
	// Path 是日志文件路径；Linux 上也可以指向 journald 导出的文件。
	Path string
	// Patterns 由 CompilePatterns 产出。
	Patterns []LogPattern
	// PollInterval 是检查新内容的周期。
	PollInterval time.Duration
	// FromEnd 为 true 时从文件末尾开始（默认），避免启动瞬间把历史日志
	// 当成新事件而把整个日志里的人全封了。
	FromEnd bool

	offset int64
	primed bool
}

// Name 实现 Detector。
func (w *LogWatcher) Name() string { return "log:" + w.Path }

// Run 实现 Detector。
func (w *LogWatcher) Run(ctx context.Context, out chan<- Event) error {
	if w.Path == "" {
		return fmt.Errorf("日志检测器未指定文件路径")
	}
	interval := w.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if err := w.pollOnce(ctx, out); err != nil {
			// 文件暂时不在（轮转间隙）属正常，继续等待。
			_ = err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// PollOnce 读一次新增内容并产出事件。公开以便测试驱动。
func (w *LogWatcher) PollOnce(ctx context.Context, out chan<- Event) error {
	return w.pollOnce(ctx, out)
}

func (w *LogWatcher) pollOnce(ctx context.Context, out chan<- Event) error {
	f, err := os.Open(w.Path)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	if !w.primed {
		w.primed = true
		if w.FromEnd {
			// 跳到末尾：只看启动之后新写入的内容。
			w.offset = fi.Size()
		} else {
			w.offset = 0
		}
		return nil
	}

	// 文件被截断或轮转（新文件比记录的偏移还小）→ 从头读。
	if fi.Size() < w.offset {
		w.offset = 0
	}
	if fi.Size() == w.offset {
		return nil
	}
	if _, err := f.Seek(w.offset, io.SeekStart); err != nil {
		return err
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		w.offset += int64(len(sc.Bytes())) + 1 // +1 为换行符
		if ctx.Err() != nil {
			return ctx.Err()
		}
		for _, ev := range MatchLine(w.Patterns, sc.Text()) {
			select {
			case out <- ev:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return sc.Err()
}
