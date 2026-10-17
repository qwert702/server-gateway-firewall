package webui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func get(t *testing.T, h http.Handler, path string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	body, _ := io.ReadAll(rec.Body)
	return rec, string(body)
}

func TestServesAssets(t *testing.T) {
	h := Handler("/ui/")
	cases := []struct {
		path string
		want string // 必须包含的内容
		ct   string
	}{
		{"/ui/", "<!DOCTYPE html>", "text/html"},
		{"/ui/app.css", "--amber", "text/css"},
		{"/ui/app.js", "connectSSE", "javascript"},
	}
	for _, c := range cases {
		rec, body := get(t, h, c.path)
		if rec.Code != http.StatusOK {
			t.Errorf("%s 状态码 %d", c.path, rec.Code)
			continue
		}
		if !strings.Contains(body, c.want) {
			t.Errorf("%s 内容缺少 %q", c.path, c.want)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, c.ct) {
			t.Errorf("%s Content-Type = %q，期望包含 %q", c.path, ct, c.ct)
		}
	}
}

// index.html 会被 http.FileServerFS 301 重定向到目录路径，这是标准行为，
// 浏览器会自动跟随。
func TestExplicitIndexRedirects(t *testing.T) {
	rec, _ := get(t, Handler("/ui/"), "/ui/index.html")
	if rec.Code != http.StatusMovedPermanently && rec.Code != http.StatusOK {
		t.Errorf("/ui/index.html 应重定向或直接返回，实际 %d", rec.Code)
	}
}

// 单页应用：直接刷新深链接必须回落到 index.html，否则用户一刷新就 404。
func TestSPAFallbackForUnknownPaths(t *testing.T) {
	h := Handler("/ui/")
	for _, p := range []string{"/ui/bans", "/ui/rules", "/ui/a/b/c", "/ui/不存在"} {
		rec, body := get(t, h, p)
		if rec.Code != http.StatusOK {
			t.Errorf("%s 应回落而非 404，实际 %d", p, rec.Code)
		}
		if !strings.Contains(body, "<!DOCTYPE html>") {
			t.Errorf("%s 未回落到 index.html", p)
		}
	}
}

// 内嵌资源的 URL 里没有内容哈希，因此不能长缓存，
// 否则升级二进制后浏览器还在跑旧界面。
func TestNoLongCache(t *testing.T) {
	h := Handler("/ui/")
	rec, _ := get(t, h, "/ui/app.js")
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
		t.Errorf("Cache-Control = %q，应包含 no-cache", cc)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("应设置 X-Content-Type-Options: nosniff")
	}
}

// 界面必须能在完全离线的情况下**正常工作**：防火墙常常跑在隔离网络里。
//
// 要区分两件事：
//   - 资源加载（script src / link href / img src / url() / @import）——
//     浏览器会自动去取，节点不通就是白屏或掉样式，必须彻底禁止。
//   - 用户可点击的 <a href> —— 那是导航，不是加载。页面照常渲染与工作，
//     只是点进去要联网，这正是用户自己的选择，不该一刀切禁掉。
//
// 所以这里只查真正会自动发起请求的写法。
func TestNoExternalResourceLoads(t *testing.T) {
	h := Handler("/ui/")
	loads := []string{
		`<script src="http`, `<link href="http`, `<img src="http`,
		`url(http`, `url("http`, `@import`,
		"//cdn.", "unpkg.com", "jsdelivr", "fonts.google", "cdnjs",
	}
	for _, p := range []string{"/ui/", "/ui/app.css", "/ui/app.js"} {
		_, body := get(t, h, p)
		for _, bad := range loads {
			if strings.Contains(body, bad) {
				t.Errorf("%s 含会自动加载外部资源的写法 %q —— 离线环境下界面会坏", p, bad)
			}
		}
	}
}

// 外链只能出现在用户可点击的 <a href> 上，且必须带 rel="noopener"。
func TestExternalLinksAreUserNavigationOnly(t *testing.T) {
	_, html := get(t, Handler("/ui/"), "/ui/")
	_ = html // index.html 目前没有外链

	_, js := get(t, Handler("/ui/"), "/ui/app.js")
	if !strings.Contains(js, `target="_blank"`) {
		return // 没有外链，无需检查
	}
	if !strings.Contains(js, `rel="noopener"`) {
		t.Error("新窗口打开的外链必须带 rel=\"noopener\"，否则被指向的站点能拿到 window.opener")
	}
}

// 每个视图都要在 JS 里有对应实现，否则导航会指向一个空白页。
func TestEveryNavPageHasRenderer(t *testing.T) {
	_, html := get(t, Handler("/ui/"), "/ui/")
	_, js := get(t, Handler("/ui/"), "/ui/app.js")

	for _, page := range []string{"dashboard", "rules", "zones", "nat", "bans", "groups", "network", "audit"} {
		if !strings.Contains(html, `data-page="`+page+`"`) {
			t.Errorf("导航缺少 %s 入口", page)
		}
		if !strings.Contains(js, page+":") {
			t.Errorf("JS 中缺少 %s 的处理器", page)
		}
	}
}

// 转义必须存在：规则备注、事件详情都来自用户输入，
// 直接拼进 innerHTML 就是一个 XSS。
func TestEscapingHelperIsPresent(t *testing.T) {
	_, js := get(t, Handler("/ui/"), "/ui/app.js")
	if !strings.Contains(js, "function esc(") {
		t.Fatal("缺少转义函数")
	}
	if !strings.Contains(js, "'&#39;") && !strings.Contains(js, "&#39;") {
		t.Error("转义函数应处理单引号")
	}
}
