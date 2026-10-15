package nftables

import (
	"testing"
	"time"

	"fwdd/internal/compiler"
	"fwdd/internal/ir"
	"fwdd/internal/model"
)

// 这些快照同时覆盖编译器最易出错的语法面：集合、NAT、限速、IPv6、log、reject。

func build(t *testing.T, p *model.Policy, opts compiler.Options) *ir.Snapshot {
	t.Helper()
	if opts.TableName == "" {
		opts.TableName = "fw"
	}
	if opts.Family == "" {
		opts.Family = ir.FamilyINet
	}
	res, err := compiler.Compile(p, opts)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	return res.Snapshot
}

// goldenSnapshot 是一个典型三接口网关策略。
func goldenSnapshot(t *testing.T) *ir.Snapshot {
	t.Helper()
	p := &model.Policy{
		Zones: []model.Zone{
			{Name: "wan", Interfaces: []string{"eth0"}, Trust: model.TrustUntrusted},
			{Name: "lan", Interfaces: []string{"eth1"}, Trust: model.TrustLAN},
			{Name: "dmz", Interfaces: []string{"eth2"}, Trust: model.TrustDMZ},
		},
		Rules: []model.Rule{
			{ID: "lan-wan", Priority: 100, SrcZone: "lan", DstZone: "wan", Action: model.ActionAccept},
			{ID: "lan-dmz-web", Priority: 110, SrcZone: "lan", DstZone: "dmz",
				Proto: model.ProtoTCP, DstPort: []string{"80", "443"}, State: []string{"new"}, Action: model.ActionAccept},
			{ID: "ssh", Priority: 300, SrcZone: "lan", DstZone: model.ZoneLocal,
				Proto: model.ProtoTCP, DstPort: []string{"22"}, Action: model.ActionAccept,
				Limit: &model.RateLimit{Rate: 10, Per: "minute", Burst: 20}},
			{ID: "rej", Priority: 400, SrcZone: "wan", DstZone: "lan",
				Proto: model.ProtoTCP, DstPort: []string{"445"}, Action: model.ActionReject, Reject: model.RejectTCPReset},
			{ID: "log-deny", Priority: 500, SrcZone: "wan", DstZone: "dmz", Action: model.ActionLog,
				LogPrefix: "fw-deny: "},
			{ID: "icmp", Priority: 600, SrcZone: "lan", DstZone: model.ZoneLocal, Proto: model.ProtoICMP,
				Action: model.ActionAccept, Limit: &model.RateLimit{Rate: 10, Per: "second", Burst: 20}},
		},
		NATRules: []model.NATRule{
			{ID: "web", Kind: model.NATDNAT, Proto: model.ProtoTCP, SrcZone: "wan",
				MatchPort: "8080", ToAddr: "192.168.20.10", ToPort: "80"},
			{ID: "masq", Kind: model.NATMasquerade, OutZone: "wan"},
		},
		Default: model.DefaultPolicy{Input: model.ActionDrop, Forward: model.ActionDrop, Output: model.ActionAccept},
		BanSet:  model.BanSettings{Timeout: 24 * time.Hour},
		Bans:    []model.BanEntry{{IP: "203.0.113.9", Reason: "ssh 爆破", ExpiresAt: time.Now().Add(time.Hour)}},
	}
	return build(t, p, compiler.Options{
		BanSet4: "banned4", BanSet6: "banned6", BanTimeout: 24 * time.Hour,
		ConntrackFastPath: true, Counters: true,
	})
}

// banAndLimitSnapshot 覆盖按源地址限速（动态集合 + meter 语义）。
func banAndLimitSnapshot(t *testing.T) *ir.Snapshot {
	t.Helper()
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}, {Name: "lan", Interfaces: []string{"eth1"}}},
		Rules: []model.Rule{
			{ID: "perip", Priority: 100, SrcZone: "wan", DstZone: "lan",
				Proto: model.ProtoTCP, DstPort: []string{"443"}, State: []string{"new"},
				Action: model.ActionDrop, Limit: &model.RateLimit{Rate: 20, Per: "second", PerIP: true}},
			{ID: "global", Priority: 110, SrcZone: "wan", DstZone: "lan",
				Proto: model.ProtoUDP, DstPort: []string{"53"}, Action: model.ActionAccept,
				Limit: &model.RateLimit{Rate: 100, Per: "second", Burst: 200}},
			{ID: "portrange", Priority: 120, SrcZone: "lan", DstZone: "wan",
				Proto: model.ProtoTCP, DstPort: []string{"32768-60999"}, Action: model.ActionAccept},
		},
		Default: model.DefaultPolicy{Forward: model.ActionDrop},
	}
	return build(t, p, compiler.Options{BanSet4: "banned4", BanSet6: "banned6", Counters: true})
}

// v6Snapshot 覆盖 IPv6 拆分、IPv6 集合与 IPv6 DNAT 的方括号语法。
func v6Snapshot(t *testing.T) *ir.Snapshot {
	t.Helper()
	p := &model.Policy{
		Zones: []model.Zone{
			{Name: "wan", Interfaces: []string{"eth0"}},
			{Name: "lan6", Networks: []string{"2001:db8:1::/64"}},
		},
		Rules: []model.Rule{
			{ID: "mixed", Priority: 100, SrcZone: "wan", DstZone: "lan6",
				SrcAddr: []string{"10.0.0.0/8", "2001:db8:dead::/48"},
				Proto:   model.ProtoTCP, DstPort: []string{"22"}, Action: model.ActionAccept},
			{ID: "v6only", Priority: 110, SrcZone: "wan", DstZone: "lan6",
				SrcAddr: []string{"2001:db8:bad::/48"}, Action: model.ActionDrop},
		},
		NATRules: []model.NATRule{
			{ID: "v6dnat", Kind: model.NATDNAT, Proto: model.ProtoTCP, SrcZone: "wan",
				MatchPort: "8443", ToAddr: "2001:db8:20::10", ToPort: "443"},
		},
		Default: model.DefaultPolicy{Forward: model.ActionDrop},
		Bans:    []model.BanEntry{{IP: "2001:db8::dead", ExpiresAt: time.Now().Add(time.Hour)}},
	}
	return build(t, p, compiler.Options{BanSet4: "banned4", BanSet6: "banned6", Counters: true})
}
