//go:build !linux

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sort"
)

// ErrUnsupported 表示当前平台不支持系统网络配置。
var ErrUnsupported = errors.New("netcfg: 当前平台不支持系统网络配置（仅 Linux）")

type otherProvider struct{}

// New 返回当前平台的实现。
func New() Provider { return otherProvider{} }

func (otherProvider) Platform() string { return runtime.GOOS }
func (otherProvider) Supported() bool  { return false }

// Read 在非 Linux 上只能拿到标准库能提供的接口信息，
// 用于让开发机上的 `fw status` 不至于一片空白。
func (otherProvider) Read(ctx context.Context) (*State, error) {
	st := &State{
		Platform: runtime.GOOS,
		Sysctls:  map[string]string{},
		Note:     "非 Linux 平台：只能读取基本接口信息，无法读取转发开关、路由与策略路由",
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return st, nil
	}
	for _, i := range ifaces {
		flags := []string{}
		if i.Flags&net.FlagUp != 0 {
			flags = append(flags, "up")
		}
		if i.Flags&net.FlagLoopback != 0 {
			flags = append(flags, "loopback")
		}
		st.Links = append(st.Links, LinkState{Name: i.Name, Index: i.Index, MTU: i.MTU, Up: i.Flags&net.FlagUp != 0, Flags: flags})
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				family := "inet"
				if ipnet.IP.To4() == nil {
					family = "inet6"
				}
				st.Addresses = append(st.Addresses, Address{Interface: i.Name, CIDR: ipnet.String(), Family: family})
			}
		}
	}
	sort.Slice(st.Links, func(i, j int) bool { return st.Links[i].Index < st.Links[j].Index })
	return st, nil
}

// SetSysctls 在非 Linux 上直接报错，而不是静默成功 —— 静默成功会让用户
// 以为转发已打开，而实际上根本没有。
func (otherProvider) SetSysctls(ctx context.Context, s []Sysctl) ([]Change, error) {
	return nil, fmt.Errorf("%w（当前为 %s）", ErrUnsupported, runtime.GOOS)
}
