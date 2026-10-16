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

// 界面必须完全自包含：防火墙常常跑在隔离网络里，引用外部字体或 CDN
// 会导致界面无法正常显示。
//
// 只看 "http://" 会误报：CSS 里的内联 SVG 带着
// xmlns='http://www.w3.org/2000/svg'，那是 XML 命名空间标识符，永远不会被请求。
// 所以这里只找真正会发起网络请求的写法。
func TestNoExternalReferences(t *testing.T) {
	h := Handler("/ui/")
	fetches := []string{
		`src="http`, `src='http`, `href="http`, `href='http`,
		`url(http`, `url("http`, "@import", "//cdn.", "unpkg.com", "jsdelivr", "fonts.google",
	}
	for _, p := range []string{"/ui/", "/ui/app.css", "/ui/app.js"} {
		_, body := get(t, h, p)
		for _, bad := range fetches {
			if strings.Contains(body, bad) {
				t.Errorf("%s 含会发起外部请求的写法 %q —— 界面必须能离线工作", p, bad)
			}
		}
	}
}

// 每个视图都要在 JS 里有对应实现，否则导航会指向一个空白页。
func TestEveryNavPageHasRenderer(t *testing.T) {
	_, html := get(t, Handler("/ui/"), "/ui/")
	_, js := get(t, Handler("/ui/"), "/ui/app.js")

	for _, page := range []string{"dashboard", "rules", "zones", "nat", "bans", "network", "audit"} {
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
