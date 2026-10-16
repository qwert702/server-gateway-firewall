// Package webui 内嵌并提供 Web 管理界面。
//
// 刻意不引入任何前端构建链：产物是手写的 HTML/CSS/JS，用 go:embed 打进二进制。
// 这样网关机器上不需要 Node，交叉编译、单文件部署、离线环境全部照常工作。
//
// 同理也没有引用任何外部字体或 CDN —— 防火墙所在的环境常常是隔离网络，
// 界面必须能在完全离线的情况下正常显示。
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed dist
var distFS embed.FS

// FS 返回界面静态资源。
func FS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		// 只可能在 embed 指令写错时发生，属于编译期问题。
		panic("webui: 内嵌资源缺失: " + err.Error())
	}
	return sub
}

// Handler 返回管理界面的处理器，挂在 prefix 之下（如 "/ui/"）。
//
// 未匹配到静态文件的路径一律回落到 index.html：界面是单页应用，
// 路由在前端处理，直接刷新 /ui/bans 不该 404。
func Handler(prefix string) http.Handler {
	assets := http.FileServerFS(FS())
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 界面是内嵌的，URL 里没有内容哈希，因此用 ETag 协商而不是长缓存，
		// 免得升级二进制后浏览器还在跑旧界面。
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		rel := strings.TrimPrefix(r.URL.Path, prefix)
		if rel == "" {
			serveIndex(w, r)
			return
		}
		if _, err := fs.Stat(FS(), rel); err != nil {
			serveIndex(w, r)
			return
		}
		http.StripPrefix(prefix, assets).ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	f, err := FS().Open("index.html")
	if err != nil {
		http.Error(w, "界面资源缺失", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	data, err := fs.ReadFile(FS(), "index.html")
	if err != nil {
		http.Error(w, "界面资源缺失", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}
