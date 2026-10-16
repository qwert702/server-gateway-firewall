package engine

import (
	"fmt"
	"sort"
	"strings"

	"fwdd/internal/model"
)

// 本文件提供策略对象的增删改查。所有写操作都走 Update，
// 因此天然满足：先校验、再落库，校验不过则内存与磁盘都不动。

// ---- 域 ----

// AddZone 新增一个安全域。
func (e *Engine) AddZone(z model.Zone) error {
	if z.Name == "" {
		return fmt.Errorf("域名不能为空")
	}
	if z.Name == model.ZoneAny || z.Name == model.ZoneLocal {
		return fmt.Errorf("域名 %q 是保留字", z.Name)
	}
	return e.Update(func(p *model.Policy) error {
		if p.ZoneByName(z.Name) != nil {
			return fmt.Errorf("域 %q 已存在", z.Name)
		}
		p.Zones = append(p.Zones, z)
		return nil
	})
}

// UpdateZone 覆盖一个已存在的域。改名前会同步更新所有引用。
func (e *Engine) UpdateZone(oldName string, z model.Zone) error {
	return e.Update(func(p *model.Policy) error {
		idx := -1
		for i := range p.Zones {
			if p.Zones[i].Name == oldName {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("域 %q 不存在", oldName)
		}
		if z.Name != oldName {
			if z.Name == "" {
				return fmt.Errorf("域名不能为空")
			}
			if p.ZoneByName(z.Name) != nil {
				return fmt.Errorf("域 %q 已存在", z.Name)
			}
			// 改名同时更新引用，否则会留下一堆悬空引用让校验失败。
			renameRefs(p, oldName, z.Name)
		}
		p.Zones[idx] = z
		return nil
	})
}

// DeleteZone 删除一个域；仍被规则引用时拒绝删除。
func (e *Engine) DeleteZone(name string) error {
	return e.Update(func(p *model.Policy) error {
		var users []string
		for _, r := range p.Rules {
			if r.SrcZone == name || r.DstZone == name {
				users = append(users, r.ID)
			}
		}
		for _, n := range p.NATRules {
			if n.SrcZone == name || n.OutZone == name {
				users = append(users, "nat/"+n.ID)
			}
		}
		if len(users) > 0 {
			return fmt.Errorf("域 %q 仍被 %d 处引用（%s），请先解除引用",
				name, len(users), strings.Join(limit(users, 5), ", "))
		}
		for i := range p.Zones {
			if p.Zones[i].Name == name {
				p.Zones = append(p.Zones[:i], p.Zones[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("域 %q 不存在", name)
	})
}

func renameRefs(p *model.Policy, from, to string) {
	swap := func(s string) string {
		if s == from {
			return to
		}
		return s
	}
	for i := range p.Rules {
		p.Rules[i].SrcZone = swap(p.Rules[i].SrcZone)
		p.Rules[i].DstZone = swap(p.Rules[i].DstZone)
	}
	for i := range p.NATRules {
		p.NATRules[i].SrcZone = swap(p.NATRules[i].SrcZone)
		p.NATRules[i].OutZone = swap(p.NATRules[i].OutZone)
	}
}

// ---- 规则 ----

// AddRule 追加一条规则；ID 为空时自动生成，Priority 为 0 时排到末尾。
func (e *Engine) AddRule(r model.Rule) (string, error) {
	var id string
	err := e.Update(func(p *model.Policy) error {
		if r.ID == "" {
			r.ID = nextRuleID(p)
		} else if p.RuleByID(r.ID) != nil {
			return fmt.Errorf("规则 id %q 已存在", r.ID)
		}
		if r.Priority == 0 {
			r.Priority = nextPriority(p.Rules)
		}
		p.Rules = append(p.Rules, r)
		id = r.ID
		return nil
	})
	if err != nil {
		return "", err
	}
	e.audit("rule.add", id, r.Comment)
	return id, nil
}

// UpdateRule 覆盖一条已存在的规则。
func (e *Engine) UpdateRule(id string, r model.Rule) error {
	if err := e.Update(func(p *model.Policy) error {
		idx := ruleIndex(p, id)
		if idx < 0 {
			return fmt.Errorf("规则 %q 不存在", id)
		}
		if r.ID == "" {
			r.ID = id
		}
		if r.ID != id && p.RuleByID(r.ID) != nil {
			return fmt.Errorf("规则 id %q 已存在", r.ID)
		}
		// 未显式给出优先级时保留原值，避免"改个备注就把规则挪了位置"。
		if r.Priority == 0 {
			r.Priority = p.Rules[idx].Priority
		}
		// Enabled 为 nil 时保持原启用状态。
		if r.Enabled == nil {
			r.Enabled = p.Rules[idx].Enabled
		}
		p.Rules[idx] = r
		return nil
	}); err != nil {
		return err
	}
	e.audit("rule.update", id, r.Comment)
	return nil
}

// DeleteRule 删除一条规则。
func (e *Engine) DeleteRule(id string) error {
	if err := e.Update(func(p *model.Policy) error {
		idx := ruleIndex(p, id)
		if idx < 0 {
			return fmt.Errorf("规则 %q 不存在", id)
		}
		p.Rules = append(p.Rules[:idx], p.Rules[idx+1:]...)
		return nil
	}); err != nil {
		return err
	}
	e.audit("rule.delete", id, "")
	return nil
}

// SetRuleEnabled 启用或停用一条规则。
func (e *Engine) SetRuleEnabled(id string, enabled bool) error {
	if err := e.Update(func(p *model.Policy) error {
		idx := ruleIndex(p, id)
		if idx < 0 {
			return fmt.Errorf("规则 %q 不存在", id)
		}
		p.Rules[idx].Enabled = &enabled
		return nil
	}); err != nil {
		return err
	}
	e.audit("rule.enable", id, fmt.Sprintf("enabled=%v", enabled))
	return nil
}

// MoveRule 把规则插到目标规则之前；before 为空表示移到末尾。
func (e *Engine) MoveRule(id, before string) error {
	if err := e.Update(func(p *model.Policy) error {
		idx := ruleIndex(p, id)
		if idx < 0 {
			return fmt.Errorf("规则 %q 不存在", id)
		}
		r := p.Rules[idx]
		rest := append(append([]model.Rule{}, p.Rules[:idx]...), p.Rules[idx+1:]...)

		at := len(rest)
		if before != "" {
			at = -1
			for i := range rest {
				if rest[i].ID == before {
					at = i
					break
				}
			}
			if at < 0 {
				return fmt.Errorf("目标规则 %q 不存在", before)
			}
		}
		rest = append(rest[:at], append([]model.Rule{r}, rest[at:]...)...)
		p.Rules = rest
		renumber(p.Rules)
		return nil
	}); err != nil {
		return err
	}
	e.audit("rule.move", id, "before="+before)
	return nil
}

// ReorderRules 按给定 id 顺序重排，未列出的规则保持相对顺序追加在后。
func (e *Engine) ReorderRules(ids []string) error {
	if err := e.Update(func(p *model.Policy) error {
		pos := make(map[string]int, len(ids))
		for i, id := range ids {
			if ruleIndex(p, id) < 0 {
				return fmt.Errorf("规则 %q 不存在", id)
			}
			pos[id] = i
		}
		sort.SliceStable(p.Rules, func(i, j int) bool {
			pi, oki := pos[p.Rules[i].ID]
			pj, okj := pos[p.Rules[j].ID]
			switch {
			case oki && okj:
				return pi < pj
			case oki:
				return true
			case okj:
				return false
			default:
				return false
			}
		})
		renumber(p.Rules)
		return nil
	}); err != nil {
		return err
	}
	e.audit("rule.reorder", "", fmt.Sprintf("count=%d", len(ids)))
	return nil
}

// ListRules 返回按优先级排序的规则副本。
func (e *Engine) ListRules() []model.Rule {
	p := e.Policy()
	out := append([]model.Rule(nil), p.Rules...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

// ---- NAT ----

// AddNATRule 追加一条 NAT 规则。
func (e *Engine) AddNATRule(n model.NATRule) (string, error) {
	var id string
	err := e.Update(func(p *model.Policy) error {
		if n.ID == "" {
			n.ID = nextNATID(p)
		} else if natIndex(p, n.ID) >= 0 {
			return fmt.Errorf("NAT 规则 id %q 已存在", n.ID)
		}
		if n.Priority == 0 {
			n.Priority = nextPriorityNAT(p.NATRules)
		}
		p.NATRules = append(p.NATRules, n)
		id = n.ID
		return nil
	})
	if err != nil {
		return "", err
	}
	e.audit("nat.add", id, string(n.Kind))
	return id, nil
}

// UpdateNATRule 覆盖一条 NAT 规则。
func (e *Engine) UpdateNATRule(id string, n model.NATRule) error {
	if err := e.Update(func(p *model.Policy) error {
		idx := natIndex(p, id)
		if idx < 0 {
			return fmt.Errorf("NAT 规则 %q 不存在", id)
		}
		if n.ID == "" {
			n.ID = id
		}
		if n.ID != id && natIndex(p, n.ID) >= 0 {
			return fmt.Errorf("NAT 规则 id %q 已存在", n.ID)
		}
		if n.Priority == 0 {
			n.Priority = p.NATRules[idx].Priority
		}
		if n.Enabled == nil {
			n.Enabled = p.NATRules[idx].Enabled
		}
		p.NATRules[idx] = n
		return nil
	}); err != nil {
		return err
	}
	e.audit("nat.update", id, string(n.Kind))
	return nil
}

// DeleteNATRule 删除一条 NAT 规则。
func (e *Engine) DeleteNATRule(id string) error {
	if err := e.Update(func(p *model.Policy) error {
		idx := natIndex(p, id)
		if idx < 0 {
			return fmt.Errorf("NAT 规则 %q 不存在", id)
		}
		p.NATRules = append(p.NATRules[:idx], p.NATRules[idx+1:]...)
		return nil
	}); err != nil {
		return err
	}
	e.audit("nat.delete", id, "")
	return nil
}

// ListNATRules 返回按优先级排序的 NAT 规则副本。
func (e *Engine) ListNATRules() []model.NATRule {
	p := e.Policy()
	out := append([]model.NATRule(nil), p.NATRules...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

// ---- 内部工具 ----

func ruleIndex(p *model.Policy, id string) int {
	for i := range p.Rules {
		if p.Rules[i].ID == id {
			return i
		}
	}
	return -1
}

func natIndex(p *model.Policy, id string) int {
	for i := range p.NATRules {
		if p.NATRules[i].ID == id {
			return i
		}
	}
	return -1
}

// nextRuleID 生成一个未被占用的规则 id。
func nextRuleID(p *model.Policy) string {
	for n := 1; ; n++ {
		id := fmt.Sprintf("rule-%d", n)
		if p.RuleByID(id) == nil {
			return id
		}
	}
}

func nextNATID(p *model.Policy) string {
	for n := 1; ; n++ {
		id := fmt.Sprintf("nat-%d", n)
		if natIndex(p, id) < 0 {
			return id
		}
	}
}

// nextPriority 返回比现有最大值更大的优先级，让新规则默认排到末尾。
func nextPriority(rs []model.Rule) int {
	max := 0
	for _, r := range rs {
		if r.Priority > max {
			max = r.Priority
		}
	}
	return max + 10
}

func nextPriorityNAT(ns []model.NATRule) int {
	max := 0
	for _, n := range ns {
		if n.Priority > max {
			max = n.Priority
		}
	}
	return max + 10
}

// renumber 把规则优先级重排为 10, 20, 30……保留原有顺序。
func renumber(rs []model.Rule) {
	for i := range rs {
		rs[i].Priority = (i + 1) * 10
	}
}

func limit(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string{}, s[:n]...), fmt.Sprintf("…等 %d 处", len(s)))
}
