package obs

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"fwdd/internal/backend/mock"
	"fwdd/internal/config"
	"fwdd/internal/engine"
	"fwdd/internal/model"
)

func newTestEngine(t *testing.T) *engine.Engine {
	t.Helper()
	cfg := config.Default()
	cfg.Backend = "mock"
	cfg.Table = "fw"
	cfg.Family = "inet"
	cfg.Listen = ""
	cfg.Socket = ""

	be := mock.New(mock.WithTableName("fw"))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := engine.New(cfg, be, logger)

	// 给一份最小策略并下发，这样运行态里才有链与集合可供指标采集。
	p := &model.Policy{
		Zones:   []model.Zone{{Name: "lan", Interfaces: []string{"eth1"}}},
		Rules:   []model.Rule{{ID: "r1", SrcZone: "lan", DstZone: model.ZoneAny, Action: model.ActionAccept}},
		Default: model.DefaultPolicy{Forward: model.ActionDrop},
	}
	if err := e.SetPolicy(p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), engine.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	return e
}
