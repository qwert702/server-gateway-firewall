/* ============================================================
   fwdd 管理界面
   ------------------------------------------------------------
   无框架、无构建：一个 hash 路由 + 一组渲染函数。
   目标是"值班时能一眼看懂"，所以每个视图都优先把**状态**摆出来，
   而不是把操作摆出来。
   ============================================================ */

'use strict';

/* ---------- 小工具 ---------- */

const $ = (sel, root = document) => root.querySelector(sel);

const RAW = Symbol('raw');
const raw = (s) => ({ [RAW]: String(s) });

/** 转义插值。所有来自 API 的文本（规则备注、事件详情、日志行）都必须经过它。 */
function esc(v) {
  if (v && typeof v === 'object' && v[RAW] !== undefined) return v[RAW];
  return String(v ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** html`...${x}...`：插值自动转义，需要插入已构造的 HTML 时用 raw()。 */
function html(strings, ...vals) {
  let out = '';
  strings.forEach((s, i) => {
    out += s;
    if (i < vals.length) out += esc(vals[i]);
  });
  return out;
}

const pad = (n, w = 2) => String(n).padStart(w, '0');

function ago(iso) {
  if (!iso) return '—';
  const d = (Date.now() - new Date(iso).getTime()) / 1000;
  if (d < 60) return `${Math.max(0, Math.floor(d))} 秒前`;
  if (d < 3600) return `${Math.floor(d / 60)} 分钟前`;
  if (d < 86400) return `${Math.floor(d / 3600)} 小时前`;
  return `${Math.floor(d / 86400)} 天前`;
}

function hhmmss(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function dur(seconds) {
  if (seconds == null || seconds < 0) return '—';
  const s = Math.floor(seconds % 60), m = Math.floor(seconds / 60) % 60;
  const h = Math.floor(seconds / 3600) % 24, d = Math.floor(seconds / 86400);
  if (d) return `${d}天${h}时`;
  if (h) return `${h}时${m}分`;
  if (m) return `${m}分${s}秒`;
  return `${s}秒`;
}

const list = (a) => (Array.isArray(a) ? a : []);
const orDash = (v) => (v === '' || v == null || (Array.isArray(v) && !v.length) ? '—' : v);

/* ---------- API ---------- */

const TOKEN_KEY = 'fwdd.token';

const api = {
  token: localStorage.getItem(TOKEN_KEY) || new URLSearchParams(location.search).get('token') || '',

  setToken(t) {
    this.token = t || '';
    if (t) localStorage.setItem(TOKEN_KEY, t);
    else localStorage.removeItem(TOKEN_KEY);
  },

  async call(method, path, body) {
    const init = { method, headers: {} };
    if (this.token) init.headers['Authorization'] = 'Bearer ' + this.token;
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    const resp = await fetch('/api/v1' + path, init);
    const text = await resp.text();

    if (resp.status === 401 || resp.status === 403) {
      const err = new Error('需要访问令牌');
      err.needsToken = true;
      throw err;
    }
    if (!resp.ok) {
      let msg = text;
      try {
        const j = JSON.parse(text);
        if (j.problems?.length) {
          msg = '策略校验失败：\n' + j.problems.map((p) => `  ${p.where}: ${p.message}`).join('\n');
        } else if (j.error) {
          msg = j.error;
        }
      } catch { /* 原样用文本 */ }
      throw new Error(msg || `HTTP ${resp.status}`);
    }
    if (!text) return null;
    try { return JSON.parse(text); } catch { return text; }
  },

  get(p) { return this.call('GET', p); },
  post(p, b) { return this.call('POST', p, b); },
  put(p, b) { return this.call('PUT', p, b); },
  del(p) { return this.call('DELETE', p); },
};

/* ---------- 全局状态 ---------- */

const state = {
  page: 'dashboard',
  status: null,
  plan: null,
  events: [],
  pendingTick: null,
  timer: null,
};

/* ---------- 吐司 ---------- */

function toast(title, body, sev = 'ok', ms = 4200) {
  const node = document.createElement('div');
  node.className = 'toast';
  node.dataset.sev = sev;
  node.innerHTML = html`<b>${title}</b>${body ? esc(body) : ''}`;
  $('#toasts').appendChild(node);
  setTimeout(() => {
    node.style.transition = 'opacity .25s, transform .25s';
    node.style.opacity = '0';
    node.style.transform = 'translateX(14px)';
    setTimeout(() => node.remove(), 260);
  }, ms);
}

async function guard(fn, okTitle) {
  try {
    const r = await fn();
    if (okTitle) toast(okTitle, '已在期望状态中生效，执行「下发」后写入内核', 'ok');
    return r;
  } catch (e) {
    if (e.needsToken) { showTokenGate(); return; }
    toast('操作失败', e.message, 'err', 9000);
    throw e;
  }
}

/* ---------- 模态 ---------- */

let modalOnOk = null;

function openModal(title, bodyHTML, onOk, okLabel = '保存') {
  $('#modalTitle').textContent = title;
  $('#modalBody').innerHTML = bodyHTML;
  const foot = $('#modalFoot');
  foot.innerHTML = '';
  const cancel = document.createElement('button');
  cancel.className = 'btn';
  cancel.textContent = '取消';
  cancel.onclick = closeModal;
  foot.appendChild(cancel);
  if (onOk) {
    const ok = document.createElement('button');
    ok.className = 'btn btn-primary';
    ok.textContent = okLabel;
    ok.onclick = async () => {
      ok.disabled = true;
      try { await onOk(); closeModal(); }
      catch (e) { toast('失败', e.message, 'err', 9000); }
      finally { ok.disabled = false; }
    };
    foot.appendChild(ok);
    modalOnOk = onOk;
  }
  $('#modalBackdrop').hidden = false;
  const first = $('#modalBody input, #modalBody select, #modalBody textarea');
  if (first) first.focus();
}

function closeModal() {
  $('#modalBackdrop').hidden = true;
  $('#modalBody').innerHTML = '';
  modalOnOk = null;
}

$('#modalClose').onclick = closeModal;
$('#modalBackdrop').onclick = (e) => { if (e.target.id === 'modalBackdrop') closeModal(); };
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !$('#modalBackdrop').hidden) closeModal();
});

/* ---------- 安全性确认 ---------- */

/** 危险操作一律要求显式确认，并把后果写清楚。 */
function confirmDangerous(title, lines, confirmWord, onOk) {
  openModal(title, html`
    <div class="banner" data-sev="warn">
      <span class="banner-icon">!</span>
      <div>${raw(lines.map((l) => `<div>${esc(l)}</div>`).join(''))}</div>
    </div>
    <div class="field">
      <label>输入 ${confirmWord} 以确认</label>
      <input type="text" id="dangerWord" placeholder="${confirmWord}" autocomplete="off" spellcheck="false">
    </div>
  `, async () => {
    if ($('#dangerWord').value.trim() !== confirmWord) {
      throw new Error(`请准确输入 ${confirmWord}`);
    }
    await onOk();
  }, '确认执行');
}

/* ---------- 令牌门 ---------- */

function showTokenGate() {
  $('#tokenGate').hidden = false;
  $('#tokenHint').textContent = '令牌不正确或已失效';
}

$('#tokenForm').onsubmit = (e) => {
  e.preventDefault();
  api.setToken($('#tokenInput').value.trim());
  $('#tokenGate').hidden = true;
  $('#tokenHint').textContent = '';
  boot();
};

/* ---------- 路由 ---------- */

const PAGES = {
  dashboard: { title: '总览', render: viewDashboard },
  rules: { title: '规则', render: viewRules },
  zones: { title: '安全域', render: viewZones },
  nat: { title: 'NAT', render: viewNAT },
  bans: { title: '封禁', render: viewBans },
  network: { title: '网络', render: viewNetwork },
  audit: { title: '审计', render: viewAudit },
};

function currentPage() {
  const h = location.hash.replace(/^#\//, '');
  return PAGES[h] ? h : 'dashboard';
}

function navigate() {
  state.page = currentPage();
  $('#pageTitle').textContent = PAGES[state.page].title;
  document.querySelectorAll('#nav a').forEach((a) => {
    a.classList.toggle('active', a.dataset.page === state.page);
  });
  render();
}

window.addEventListener('hashchange', navigate);

/* ---------- 渲染 ---------- */

async function render() {
  const view = $('#view');
  view.innerHTML = html`<div class="empty">读取中…</div>`;
  try {
    await PAGES[state.page].render(view);
  } catch (e) {
    if (e.needsToken) { showTokenGate(); return; }
    view.innerHTML = html`
      <div class="banner" data-sev="bad">
        <span class="banner-icon">✕</span>
        <div><b>无法读取数据</b><div>${e.message}</div></div>
      </div>`;
  }
}

/* ---------- 顶栏与左轨的状态 ---------- */

function syncIndicator(st) {
  let ledState = 'ok', text = '已同步';
  if (st.pending) { ledState = 'warn'; text = '待确认'; }
  else if (!st.in_sync) { ledState = 'warn'; text = '未同步'; }
  if (st.runtime_error) { ledState = 'bad'; text = '运行态不可读'; }
  return { ledState, text };
}

function paintChrome(st) {
  const { ledState, text } = syncIndicator(st);
  $('#syncLed').dataset.state = ledState;
  $('#syncText').textContent = text;
  $('#footBackend').textContent = orDash(st.backend);
  $('#footTable').textContent = orDash(st.table);

  const chips = [];
  if (st.pending) {
    const left = (new Date(st.pending.deadline) - Date.now()) / 1000;
    chips.push({
      sev: 'warn',
      text: `变更待确认 · ${dur(Math.max(0, left))} 后自动回滚`,
      action: '确认',
      onClick: async () => {
        await guard(() => api.post('/confirm'), '变更已确认');
        refresh();
      },
    });
  }
  if (!st.in_sync && !st.pending) {
    chips.push({ sev: 'warn', text: '期望状态与内核不一致' });
  }
  if (st.runtime_error) {
    chips.push({ sev: 'bad', text: '运行态不可读：' + st.runtime_error });
  }

  const box = $('#annunc');
  box.innerHTML = '';
  for (const c of chips) {
    const el = document.createElement('span');
    el.className = 'annun-chip';
    el.dataset.sev = c.sev;
    el.textContent = c.text;
    if (c.action) {
      const b = document.createElement('button');
      b.className = 'btn btn-xs';
      b.textContent = c.action;
      b.onclick = c.onClick;
      el.appendChild(b);
    }
    box.appendChild(el);
  }
}

/* ============================================================
   视图：总览
   ============================================================ */

async function viewDashboard(view) {
  const [st, plan, recent, banEng] = await Promise.all([
    api.get('/status'),
    api.get('/plan').catch(() => null),
    api.get('/events/recent?limit=40').catch(() => ({ events: [] })),
    api.get('/ban/engine').catch(() => null),
  ]);
  state.status = st;
  state.plan = plan;
  paintChrome(st);

  const d = st.desired || {};
  const tiles = [
    { label: '安全域', value: d.zones ?? 0 },
    { label: '规则', value: d.rules ?? 0, sub: `${d.rules_enabled ?? 0} 条启用` },
    { label: 'NAT', value: d.nat_rules ?? 0 },
    { label: '封禁中', value: d.bans ?? 0, tone: (d.bans ? 'red' : null) },
    {
      label: '同步状态',
      value: st.in_sync ? '一致' : '不一致',
      tone: st.in_sync ? 'green' : 'amber',
      sub: `${st.revisions ?? 0} 次下发`,
    },
  ];

  const fp = plan?.chain_details?.length
    ? fingerprint(plan.chain_details)
    : html`<div class="empty"><strong>规则集为空</strong>尚未编译出任何链</div>`;

  view.innerHTML = html`
    ${raw(banners(st, plan))}
    <section class="sec">
      <div class="tiles">
        ${raw(tiles.map((t) => html`
          <div class="tile" ${raw(t.tone ? `data-tone="${t.tone}"` : '')}>
            <span class="tile-label">${t.label}</span>
            <span class="tile-value">${t.value}</span>
            ${raw(t.sub ? `<span class="tile-sub">${esc(t.sub)}</span>` : '')}
          </div>`).join(''))}
      </div>
    </section>

    <section class="sec">
      <div class="sec-head">
        <h2 class="sec-title">规则指纹</h2>
        <span class="sec-note">每条链按求值顺序展开；颜色即裁决。链尾斜纹是默认策略。</span>
      </div>
      ${raw(fp)}
    </section>

    <section class="sec">
      <div class="sec-head">
        <h2 class="sec-title">实时事件</h2>
        <span class="sec-note" id="evNote">通过事件流推送，不轮询</span>
      </div>
      ${raw(eventsTable(recent.events || []))}
    </section>

    ${raw(banEng && banEng.enabled ? banPanel(banEng) : '')}
  `;
}

function banners(st, plan) {
  const out = [];

  if (st.pending) {
    out.push(html`
      <div class="banner" data-sev="warn">
        <span class="banner-icon">◷</span>
        <div>
          <b>有一批变更等待确认</b>
          <div>在截止时间前没有确认的话，防火墙会自动回滚到变更前的规则。
          这是防止远程改错规则把自己锁在外面的兜底机制。</div>
        </div>
      </div>`);
  }
  if (!st.in_sync && !st.pending) {
    out.push(html`
      <div class="banner" data-sev="warn">
        <span class="banner-icon">≠</span>
        <div>
          <b>期望状态与内核不一致</b>
          <div>当前期望哈希 <code>${orDash(st.desired_hash)}</code>，
          内核中为 <code>${orDash(st.applied_hash)}</code>。
          点右上角「下发」把期望状态写入内核。</div>
        </div>
      </div>`);
  }
  if (st.runtime_error) {
    out.push(html`
      <div class="banner" data-sev="bad">
        <span class="banner-icon">!</span>
        <div><b>读不到内核运行态</b><div>${st.runtime_error}</div></div>
      </div>`);
  }
  if (plan?.warnings?.length) {
    out.push(html`
      <div class="banner" data-sev="info">
        <span class="banner-icon">i</span>
        <div>
          <b>编译提示</b>
          ${raw(plan.warnings.map((w) => `<div>${esc(w.where)}：${esc(w.message)}</div>`).join(''))}
        </div>
      </div>`);
  }
  return out.join('');
}

/** 规则指纹：把一条链画成一条色带，每格一条规则。 */
function fingerprint(chains) {
  const order = ['prerouting', 'input', 'forward', 'output', 'postrouting'];
  const sorted = [...chains].sort(
    (a, b) => (order.indexOf(a.name) + 1 || 99) - (order.indexOf(b.name) + 1 || 99));

  const rows = sorted.map((c) => {
    const segs = c.segments || [];
    const body = segs.length
      ? segs.map((s, i) => html`<div class="fp-seg" data-v="${s.verdict}"
            style="animation-delay:${i * 14}ms"
            title="${(s.id || '') + (s.comment ? ' · ' + s.comment : '') + ' → ' + s.verdict}"></div>`).join('')
      : html`<div class="fp-seg" data-v="other" title="无规则，直接落到默认策略"></div>`;

    const policy = c.policy
      ? html`<div class="fp-policy" data-p="${c.policy}" title="默认策略：${c.policy}"></div>`
      : '';

    return html`
      <div class="fp-row">
        <span class="fp-name">${c.name}
          <span class="fp-hook">${orDash(c.hook)}${c.priority ? ' · ' + c.priority : ''}</span>
        </span>
        <div class="fp-bar">${raw(body)}${raw(policy)}</div>
        <span class="fp-count">${segs.length}</span>
      </div>`;
  }).join('');

  const legend = [
    ['accept', 'accept 放行'],
    ['drop', 'drop 丢弃'],
    ['reject', 'reject 拒绝'],
    ['log', 'log 仅记录'],
    ['nat', 'NAT'],
  ].map(([v, t]) => html`
    <span><i class="fp-swatch" style="background:var(--${v === 'accept' ? 'green'
      : v === 'drop' ? 'red' : v === 'reject' ? 'amber' : v === 'log' ? 'cyan' : 'violet'})"></i>${t}</span>`).join('');

  return html`
    <div class="fingerprint">${raw(rows)}</div>
    <div class="fp-legend">${raw(legend)}
      <span><i class="fp-swatch" style="background:repeating-linear-gradient(45deg,var(--line-hot) 0 3px,transparent 3px 6px)"></i>默认策略</span>
    </div>`;
}

function eventsTable(events) {
  if (!events.length) {
    return html`<div class="empty"><strong>暂无事件</strong>本进程启动以来的写操作与封禁会出现在这里</div>`;
  }
  const rows = events.map((e) => html`
    <tr>
      <td class="nowrap muted">${hhmmss(e.at)}</td>
      <td class="nowrap">${raw(badge(e.kind))}</td>
      <td class="strong nowrap">${orDash(e.target)}</td>
      <td>${orDash(e.detail)}</td>
    </tr>`).join('');
  return html`
    <div class="tbl-wrap">
      <table class="tbl" id="evTable">
        <thead><tr><th>时间</th><th>类型</th><th>对象</th><th>详情</th></tr></thead>
        <tbody>${raw(rows)}</tbody>
      </table>
    </div>`;
}

const EVENT_LABEL = {
  apply: ['已下发', 'plain'],
  rollback: ['已回滚', 'reject'],
  'rollback.reset': ['撤销全部规则', 'drop'],
  confirm: ['已确认', 'accept'],
  'policy.set': ['策略变更', 'plain'],
  'policy.init': ['初始导入', 'plain'],
  'ban.add': ['封禁', 'drop'],
  'ban.remove': ['解封', 'accept'],
  'rule.add': ['新增规则', 'plain'],
  'rule.update': ['修改规则', 'plain'],
  'rule.delete': ['删除规则', 'plain'],
  'rule.enable': ['规则开关', 'plain'],
  'rule.move': ['调整顺序', 'plain'],
  'rule.reorder': ['重排规则', 'plain'],
  'nat.add': ['新增 NAT', 'nat'],
  'nat.update': ['修改 NAT', 'nat'],
  'nat.delete': ['删除 NAT', 'nat'],
};

function badge(kind) {
  const [label, tone] = EVENT_LABEL[kind] || [kind, 'plain'];
  return `<span class="badge" data-t="${tone}">${esc(label)}</span>`;
}

function banPanel(be) {
  const s = be.settings || {}, st = be.stats || {};
  const mode = s.enabled ? '封禁中' : '仅观察（不真的封）';
  return html`
    <section class="sec">
      <div class="sec-head">
        <h2 class="sec-title">自动封禁</h2>
        <span class="sec-note">${mode}</span>
      </div>
      <div class="tiles">
        <div class="tile"><span class="tile-label">跟踪中地址</span><span class="tile-value">${st.tracked ?? 0}</span></div>
        <div class="tile" ${raw(st.banned ? 'data-tone="red"' : '')}><span class="tile-label">判定封禁中</span><span class="tile-value">${st.banned ?? 0}</span></div>
        <div class="tile"><span class="tile-label">累计事件</span><span class="tile-value">${st.observed ?? 0}</span></div>
        <div class="tile"><span class="tile-label">触发阈值</span><span class="tile-value">${s.threshold ?? 0}<span class="unit">/ ${orDash(s.window)}</span></span></div>
      </div>
      ${raw((be.offenders || []).length ? offendersTable(be.offenders) : '')}
    </section>`;
}

function offendersTable(off) {
  const rows = off.slice(0, 8).map((o) => {
    const banned = o.banned_until && new Date(o.banned_until) > new Date();
    return html`
      <tr>
        <td class="strong nowrap">${o.ip}</td>
        <td>${o.score}</td>
        <td>${o.events}</td>
        <td>${o.strikes}</td>
        <td>${raw(banned ? '<span class="badge" data-t="drop">封禁中</span>' : '<span class="badge" data-t="plain">观察中</span>')}</td>
        <td class="muted">${orDash(list(o.sources).join(', '))}</td>
      </tr>`;
  }).join('');
  return html`
    <div class="tbl-wrap" style="margin-top:12px">
      <table class="tbl">
        <thead><tr><th>地址</th><th>可疑度</th><th>事件</th><th>违规次数</th><th>状态</th><th>来源</th></tr></thead>
        <tbody>${raw(rows)}</tbody>
      </table>
    </div>`;
}

/* ============================================================
   视图：规则
   ============================================================ */

async function viewRules(view) {
  const [rulesResp, st] = await Promise.all([api.get('/rules'), api.get('/status')]);
  paintChrome(st);
  const rules = list(rulesResp.rules);

  if (!rules.length) {
    view.innerHTML = html`
      <div class="empty"><strong>还没有规则</strong>没有规则时，forward 链会落到默认策略</div>
      <div style="margin-top:14px">${raw(addRuleBtn())}</div>`;
    bindAddRule();
    return;
  }

  const rows = rules.map((r) => html`
    <tr data-off="${r.enabled === false ? 1 : 0}">
      <td class="strong nowrap">${r.id}</td>
      <td>${r.priority}</td>
      <td class="nowrap">${orDash(r.src_zone || 'any')} → ${orDash(r.dst_zone || 'any')}</td>
      <td>${orDash(r.proto || 'any')}</td>
      <td class="nowrap">${orDash(list(r.dst_port).join(','))}</td>
      <td class="nowrap">${orDash(list(r.state).join(','))}</td>
      <td>${raw(`<span class="badge" data-t="${r.action}">${esc(r.action)}</span>`)}</td>
      <td>${raw(r.enabled === false ? '<span class="badge" data-t="off">停用</span>' : '<span class="badge" data-t="plain">启用</span>')}</td>
      <td class="nowrap">
        <button class="btn btn-xs" data-act="toggle" data-id="${r.id}" data-on="${r.enabled === false}">${r.enabled === false ? '启用' : '停用'}</button>
        <button class="btn btn-xs" data-act="up" data-id="${r.id}">↑</button>
        <button class="btn btn-xs" data-act="down" data-id="${r.id}">↓</button>
        <button class="btn btn-xs btn-danger" data-act="del" data-id="${r.id}">删除</button>
      </td>
    </tr>`).join('');

  view.innerHTML = html`
    <section class="sec">
      <div class="sec-head">
        <h2 class="sec-title">转发与本机策略</h2>
        <span class="sec-note">按优先级从小到大求值；越靠前越先匹配</span>
      </div>
      <div class="tbl-wrap">
        <table class="tbl">
          <thead><tr>
            <th>ID</th><th>优先级</th><th>域（源 → 目的）</th><th>协议</th>
            <th>目的端口</th><th>连接状态</th><th>动作</th><th>状态</th><th></th>
          </tr></thead>
          <tbody>${raw(rows)}</tbody>
        </table>
      </div>
      <div style="margin-top:14px">${raw(addRuleBtn())}</div>
    </section>`;

  view.querySelectorAll('button[data-act]').forEach((b) => {
    b.onclick = () => ruleAction(b.dataset.act, b.dataset.id, rules);
  });
  bindAddRule();
}

function addRuleBtn() {
  return `<button class="btn" id="addRule">+ 新增规则</button>`;
}

function bindAddRule() {
  const b = $('#addRule');
  if (b) b.onclick = () => openModal('新增规则', ruleForm({}), async () => {
    await api.post('/rules', readRuleForm());
    toast('规则已添加', '执行「下发」后写入内核');
    render();
  }, '添加');
}

function ruleForm(r) {
  const opt = (v, cur) => `<option value="${v}" ${cur === v ? 'selected' : ''}>${v}</option>`;
  return html`
    <div class="grid-2">
      <div class="field"><label>源域</label><input type="text" id="f_src" value="${r.src_zone || 'any'}" placeholder="any / lan / local"></div>
      <div class="field"><label>目的域</label><input type="text" id="f_dst" value="${r.dst_zone || 'any'}" placeholder="any / wan / local"></div>
    </div>
    <div class="grid-3">
      <div class="field"><label>协议</label><select id="f_proto">
        ${raw(['any', 'tcp', 'udp', 'icmp', 'icmpv6'].map((p) => opt(p, r.proto || 'any')).join(''))}
      </select></div>
      <div class="field"><label>目的端口</label><input type="text" id="f_dport" value="${list(r.dst_port).join(',')}" placeholder="80,443,1000-2000"></div>
      <div class="field"><label>优先级</label><input type="number" id="f_prio" value="${r.priority || ''}" placeholder="留空自动"></div>
    </div>
    <div class="grid-2">
      <div class="field"><label>连接状态</label><input type="text" id="f_state" value="${list(r.state).join(',')}" placeholder="new,established"></div>
      <div class="field"><label>动作</label><select id="f_action">
        ${raw(['accept', 'drop', 'reject', 'log'].map((a) => opt(a, r.action || 'accept')).join(''))}
      </select></div>
    </div>
    <div class="grid-2">
      <div class="field"><label>源地址（可选）</label><input type="text" id="f_saddr" value="${list(r.src_addr).join(',')}" placeholder="10.0.0.0/8"></div>
      <div class="field"><label>目的地址（可选）</label><input type="text" id="f_daddr" value="${list(r.dst_addr).join(',')}" placeholder="192.168.20.10"></div>
    </div>
    <div class="field"><label>备注</label><input type="text" id="f_comment" value="${r.comment || ''}"></div>
    <div class="field-hint">目的域填 <code>local</code> 表示防火墙本机（规则会进 input/output 链）。</div>`;
}

function readRuleForm() {
  const split = (v) => v.split(',').map((s) => s.trim()).filter(Boolean);
  const out = {
    src_zone: $('#f_src').value.trim() || 'any',
    dst_zone: $('#f_dst').value.trim() || 'any',
    proto: $('#f_proto').value,
    dst_port: split($('#f_dport').value),
    state: split($('#f_state').value),
    src_addr: split($('#f_saddr').value),
    dst_addr: split($('#f_daddr').value),
    action: $('#f_action').value,
    comment: $('#f_comment').value.trim(),
  };
  const prio = parseInt($('#f_prio').value, 10);
  if (!Number.isNaN(prio)) out.priority = prio;
  return out;
}

async function ruleAction(act, id, rules) {
  const idx = rules.findIndex((r) => r.id === id);
  const r = rules[idx];

  if (act === 'toggle') {
    const on = r.enabled === false;
    await guard(() => api.post(`/rules/${encodeURIComponent(id)}/enable?enabled=${on}`), on ? '规则已启用' : '规则已停用');
    return render();
  }
  if (act === 'del') {
    return confirmDangerous('删除规则', [
      `将删除规则 ${id}。`,
      '该改动只写入期望状态，内核不受影响，直到你执行「下发」。',
    ], id, async () => {
      await guard(() => api.del(`/rules/${encodeURIComponent(id)}`), '规则已删除');
      render();
    });
  }
  if (act === 'up' || act === 'down') {
    const j = act === 'up' ? idx - 1 : idx + 1;
    if (j < 0 || j >= rules.length) return;
    const ids = rules.map((x) => x.id);
    [ids[idx], ids[j]] = [ids[j], ids[idx]];
    await guard(() => api.post('/rules/order', { ids }), '顺序已调整');
    return render();
  }
}

/* ============================================================
   视图：安全域
   ============================================================ */

async function viewZones(view) {
  const [zr, st] = await Promise.all([api.get('/zones'), api.get('/status')]);
  paintChrome(st);
  const zones = list(zr.zones);

  const rows = zones.length ? zones.map((z) => html`
    <tr>
      <td class="strong">${z.name}</td>
      <td>${raw(`<span class="badge" data-t="${z.trust === 'untrusted' ? 'drop' : z.trust === 'dmz' ? 'reject' : 'ok'}">${esc(orDash(z.trust))}</span>`)}</td>
      <td class="nowrap">${orDash(list(z.interfaces).join(', '))}</td>
      <td class="nowrap">${orDash(list(z.networks).join(', '))}</td>
      <td class="muted">${orDash(z.comment)}</td>
      <td class="nowrap"><button class="btn btn-xs" data-act="edit" data-name="${z.name}">编辑</button>
      <button class="btn btn-xs btn-danger" data-act="del" data-name="${z.name}">删除</button></td>
    </tr>`).join('') : '';

  view.innerHTML = html`
    <section class="sec">
      <div class="sec-head">
        <h2 class="sec-title">安全域</h2>
        <span class="sec-note">域把接口与网段分组；规则在域之间描述策略</span>
      </div>
      ${raw(zones.length ? html`
        <div class="tbl-wrap"><table class="tbl">
          <thead><tr><th>名称</th><th>信任级别</th><th>接口</th><th>网段</th><th>备注</th><th></th></tr></thead>
          <tbody>${raw(rows)}</tbody>
        </table></div>`
        : html`<div class="empty"><strong>还没有安全域</strong>先定义域，规则才有依附的对象</div>`)}
      <div style="margin-top:14px"><button class="btn" id="addZone">+ 新增安全域</button></div>
    </section>
    <section class="sec">
      <div class="banner" data-sev="info">
        <span class="banner-icon">i</span>
        <div><b>域绑定接口时，网段不参与匹配</b>
        <div>既有 <code>interfaces</code> 又有 <code>networks</code> 时，以接口为边界。
        只有未绑定接口的域才用网段做地址匹配 —— 否则会意外收窄匹配范围。</div></div>
      </div>
    </section>`;

  $('#addZone').onclick = () => openModal('新增安全域', zoneForm({}), async () => {
    await api.post('/zones', readZoneForm());
    toast('安全域已创建', '执行「下发」后写入内核');
    render();
  }, '创建');

  view.querySelectorAll('button[data-act]').forEach((b) => {
    const name = b.dataset.name;
    const z = zones.find((x) => x.name === name);
    if (b.dataset.act === 'edit') {
      b.onclick = () => openModal('编辑安全域 ' + name, zoneForm(z), async () => {
        await api.put('/zones/' + encodeURIComponent(name), readZoneForm());
        toast('安全域已更新', '执行「下发」后写入内核');
        render();
      });
    } else {
      b.onclick = () => confirmDangerous('删除安全域', [
        `将删除安全域「${name}」。`,
        '若仍有规则引用它，删除会被拒绝 —— 这是有意的，避免留下悬空引用让编译失败。',
      ], name, async () => {
        await guard(() => api.del('/zones/' + encodeURIComponent(name)), '安全域已删除');
        render();
      });
    }
  });
}

function zoneForm(z) {
  return html`
    <div class="grid-2">
      <div class="field"><label>名称</label><input type="text" id="z_name" value="${z.name || ''}" placeholder="lan" autocomplete="off"></div>
      <div class="field"><label>信任级别</label><select id="z_trust">
        ${raw(['untrusted', 'dmz', 'lan', 'local'].map((t) =>
          `<option value="${t}" ${z.trust === t ? 'selected' : ''}>${t}</option>`).join(''))}
      </select></div>
    </div>
    <div class="field"><label>接口（逗号分隔）</label><input type="text" id="z_ifaces"
      value="${list(z.interfaces).join(',')}" placeholder="eth0,eth1.10"></div>
    <div class="field"><label>网段（逗号分隔）</label><input type="text" id="z_nets"
      value="${list(z.networks).join(',')}" placeholder="10.0.0.0/8"></div>
    <div class="field"><label>备注</label><input type="text" id="z_comment" value="${z.comment || ''}"></div>`;
}

function readZoneForm() {
  const split = (v) => v.split(',').map((s) => s.trim()).filter(Boolean);
  return {
    name: $('#z_name').value.trim(),
    trust: $('#z_trust').value,
    interfaces: split($('#z_ifaces').value),
    networks: split($('#z_nets').value),
    comment: $('#z_comment').value.trim(),
  };
}

/* ============================================================
   视图：NAT
   ============================================================ */

const NAT_LABEL = { dnat: 'DNAT 端口映射', snat: 'SNAT 源地址改写', masquerade: 'MASQUERADE 伪装' };

async function viewNAT(view) {
  const [nr, st] = await Promise.all([api.get('/nat'), api.get('/status')]);
  paintChrome(st);
  const rules = list(nr.nat_rules);

  const rows = rules.map((n) => {
    const match = list(n.match_addr).join(',') + (n.match_port ? ':' + n.match_port : '');
    const to = n.kind === 'masquerade' ? `出接口（${orDash(n.out_zone)}）` : `${orDash(n.to_addr)}${n.to_port ? ':' + n.to_port : ''}`;
    return html`
      <tr>
        <td class="strong">${n.id}</td>
        <td>${n.priority}</td>
        <td>${raw(`<span class="badge" data-t="nat">${esc(n.kind)}</span>`)}</td>
        <td>${orDash(n.proto || 'any')}</td>
        <td class="nowrap">${orDash(match.replace(/^:/, ''))}</td>
        <td class="nowrap strong">${to}</td>
        <td><button class="btn btn-xs btn-danger" data-id="${n.id}">删除</button></td>
      </tr>`;
  }).join('');

  view.innerHTML = html`
    <section class="sec">
      <div class="sec-head">
        <h2 class="sec-title">地址转换</h2>
        <span class="sec-note">DNAT 在 prerouting 生效，SNAT/MASQUERADE 在 postrouting</span>
      </div>
      ${raw(rules.length ? html`
        <div class="tbl-wrap"><table class="tbl">
          <thead><tr><th>ID</th><th>优先级</th><th>类型</th><th>协议</th><th>匹配</th><th>转换为</th><th></th></tr></thead>
          <tbody>${raw(rows)}</tbody>
        </table></div>`
        : html`<div class="empty"><strong>还没有 NAT 规则</strong>网关做地址转换时在这里添加</div>`)}
      <div style="margin-top:14px;display:flex;gap:8px">
        <button class="btn" id="addDnat">+ 端口映射（DNAT）</button>
        <button class="btn" id="addSnat">+ 源地址改写（SNAT）</button>
        <button class="btn" id="addMasq">+ 出网伪装（MASQUERADE）</button>
      </div>
    </section>
    <section class="sec">
      <div class="banner" data-sev="info">
        <span class="banner-icon">i</span>
        <div><b>别忘了放行对应的转发规则</b>
        <div>DNAT 只改变目的地址，流量仍要经过 forward 链。
        如果没写放行规则，默认策略会把它丢掉 —— 表现为"映射配了但连不上"。</div></div>
      </div>
    </section>`;

  $('#addDnat').onclick = () => openModal('新增 DNAT', natForm('dnat'), async () => {
    await api.post('/nat', readNATForm('dnat'));
    toast('DNAT 已添加', '执行「下发」后写入内核'); render();
  }, '添加');
  $('#addSnat').onclick = () => openModal('新增 SNAT', natForm('snat'), async () => {
    await api.post('/nat', readNATForm('snat'));
    toast('SNAT 已添加', '执行「下发」后写入内核'); render();
  }, '添加');
  $('#addMasq').onclick = () => openModal('新增 MASQUERADE', natForm('masquerade'), async () => {
    await api.post('/nat', readNATForm('masquerade'));
    toast('MASQUERADE 已添加', '执行「下发」后写入内核'); render();
  }, '添加');

  view.querySelectorAll('button[data-id]').forEach((b) => {
    b.onclick = () => confirmDangerous('删除 NAT 规则', [`将删除 NAT 规则 ${b.dataset.id}。`], b.dataset.id, async () => {
      await guard(() => api.del('/nat/' + encodeURIComponent(b.dataset.id)), 'NAT 规则已删除');
      render();
    });
  });
}

function natForm(kind) {
  const needTo = kind !== 'masquerade';
  return html`
    <div class="banner" data-sev="info"><span class="banner-icon">i</span>
      <div>${NAT_LABEL[kind]}</div></div>
    <div class="grid-2">
      <div class="field"><label>协议</label><select id="n_proto">
        ${raw(['tcp', 'udp', 'any'].map((p) => `<option value="${p}">${p}</option>`).join(''))}
      </select></div>
      <div class="field"><label>来源域</label><input type="text" id="n_src_zone" placeholder="wan"></div>
    </div>
    ${raw(kind === 'dnat' ? `
      <div class="grid-2">
        <div class="field"><label>外部端口</label><input type="text" id="n_mport" placeholder="8080"></div>
        <div class="field"><label>匹配目的地址（可选）</label><input type="text" id="n_maddr" placeholder="203.0.113.1"></div>
      </div>` : '')}
    ${raw(needTo ? `
      <div class="grid-2">
        <div class="field"><label>转换为地址</label><input type="text" id="n_to_addr" placeholder="${kind === 'dnat' ? '192.168.20.10' : '203.0.113.1'}"></div>
        <div class="field"><label>转换为端口（可选）</label><input type="text" id="n_to_port" placeholder="80"></div>
      </div>` : `
      <div class="field"><label>出接口所属的域</label><input type="text" id="n_out_zone" placeholder="wan"></div>`)}
    <div class="field"><label>备注</label><input type="text" id="n_comment"></div>`;
}

function readNATForm(kind) {
  const v = (id) => ($(id) ? $(id).value.trim() : '');
  const out = {
    kind,
    proto: v('#n_proto'),
    src_zone: v('#n_src_zone'),
    comment: v('#n_comment'),
  };
  if (kind === 'dnat') {
    out.match_port = v('#n_mport');
    out.match_addr = v('#n_maddr') ? [v('#n_maddr')] : [];
    out.to_addr = v('#n_to_addr');
    out.to_port = v('#n_to_port');
  } else if (kind === 'snat') {
    out.to_addr = v('#n_to_addr');
    out.to_port = v('#n_to_port');
  } else {
    out.out_zone = v('#n_out_zone');
  }
  return out;
}

/* ============================================================
   视图：封禁
   ============================================================ */

async function viewBans(view) {
  const [br, be, st] = await Promise.all([
    api.get('/bans'),
    api.get('/ban/engine').catch(() => null),
    api.get('/status'),
  ]);
  paintChrome(st);
  const bans = list(br.bans);

  const rows = bans.map((b) => {
    const left = b.expires_at ? (new Date(b.expires_at) - Date.now()) / 1000 : null;
    const auto = b.source === 'auto';
    return html`
      <tr>
        <td class="strong nowrap">${b.ip}</td>
        <td class="nowrap">${raw(auto ? '<span class="badge" data-t="reject">自动</span>' : '<span class="badge" data-t="plain">手工</span>')}</td>
        <td class="nowrap">${left == null ? '永久' : dur(left)}</td>
        <td class="muted">${orDash(b.reason)}</td>
        <td><button class="btn btn-xs" data-ip="${b.ip}">解封</button></td>
      </tr>`;
  }).join('');

  view.innerHTML = html`
    <section class="sec">
      <div class="sec-head">
        <h2 class="sec-title">当前封禁</h2>
        <span class="sec-note">内核集合中的元素带超时，到点自动解封</span>
      </div>
      ${raw(bans.length ? html`
        <div class="tbl-wrap"><table class="tbl">
          <thead><tr><th>地址</th><th>来源</th><th>剩余</th><th>原因</th><th></th></tr></thead>
          <tbody>${raw(rows)}</tbody>
        </table></div>`
        : html`<div class="empty"><strong>当前没有被封禁的地址</strong></div>`)}
      <div style="margin-top:14px"><button class="btn" id="addBan">+ 手工封禁</button></div>
    </section>

    ${raw(be && be.enabled ? html`
      <section class="sec">
        <div class="sec-head">
          <h2 class="sec-title">自动封禁引擎</h2>
          <span class="sec-note">${be.settings?.enabled ? '封禁中' : '仅观察（不真的封）'}</span>
        </div>
        <div class="tiles">
          <div class="tile"><span class="tile-label">窗口</span><span class="tile-value" style="font-size:17px">${orDash(be.settings?.window)}</span></div>
          <div class="tile"><span class="tile-label">触发阈值</span><span class="tile-value">${be.settings?.threshold ?? 0}</span></div>
          <div class="tile"><span class="tile-label">首次封禁</span><span class="tile-value" style="font-size:17px">${orDash(be.settings?.base_ttl)}</span></div>
          <div class="tile"><span class="tile-label">跟踪中</span><span class="tile-value">${be.stats?.tracked ?? 0}</span></div>
          <div class="tile" ${raw((be.stats?.banned ?? 0) ? 'data-tone="red"' : '')}><span class="tile-label">判定封禁</span><span class="tile-value">${be.stats?.banned ?? 0}</span></div>
        </div>
        <div style="margin-top:14px;display:flex;gap:8px;align-items:center">
          <button class="btn" id="banToggle">${be.settings?.enabled ? '转为仅观察' : '开始真的封禁'}</button>
          <span class="field-hint">建议先用观察模式跑一段，确认不会误封监控探针或 NAT 出口。</span>
        </div>
        ${raw(list(be.offenders).length ? offendersTable(be.offenders) : '')}
      </section>`
      : html`<section class="sec">
        <div class="banner" data-sev="info"><span class="banner-icon">i</span>
        <div><b>自动封禁未启用</b><div>在配置里设置 <code>auto_ban.enabled: true</code> 后重启。</div></div></div>
      </section>`)}
  `;

  $('#addBan').onclick = () => openModal('手工封禁', html`
    <div class="field"><label>地址</label><input type="text" id="b_ip" placeholder="203.0.113.9" autocomplete="off"></div>
    <div class="grid-2">
      <div class="field"><label>时长（秒，留空 24 小时）</label><input type="number" id="b_ttl" placeholder="3600"></div>
      <div class="field"><label>原因</label><input type="text" id="b_reason" placeholder="SSH 爆破"></div>
    </div>
    <div class="field-hint">封禁会立即写入内核集合，并持久化到数据库 —— 重启后仍然有效。</div>
  `, async () => {
    const ip = $('#b_ip').value.trim();
    if (!ip) throw new Error('请填写地址');
    await api.post('/bans', {
      ip,
      ttl_sec: parseInt($('#b_ttl').value, 10) || 0,
      reason: $('#b_reason').value.trim(),
    });
    toast('已封禁 ' + ip, '已立即写入内核集合并落库');
    render();
  }, '封禁');

  const tg = $('#banToggle');
  if (tg) tg.onclick = async () => {
    const turningOn = !be.settings.enabled;
    if (turningOn) {
      return confirmDangerous('开启自动封禁', [
        '开启后，达到阈值的来源地址会被真的封禁，而不是只记录。',
        '请确认白名单里已经有你的管理网段 —— 否则一次误判可能把你挡在门外。',
      ], '开启', async () => {
        await guard(() => api.post('/ban/engine', { enabled: true }), '自动封禁已开启');
        render();
      });
    }
    await guard(() => api.post('/ban/engine', { enabled: false }), '已转为仅观察模式');
    render();
  };

  view.querySelectorAll('button[data-ip]').forEach((b) => {
    b.onclick = async () => {
      await guard(() => api.del('/bans/' + encodeURIComponent(b.dataset.ip)), '已解封 ' + b.dataset.ip);
      render();
    };
  });
}

/* ============================================================
   视图：网络
   ============================================================ */

async function viewNetwork(view) {
  const [nr, st] = await Promise.all([api.get('/net'), api.get('/status')]);
  paintChrome(st);

  const s = nr.state || {};
  const sysctls = s.sysctls || {};
  const diff = list(nr.sysctl_diff);

  const links = list(s.links).map((l) => html`
    <tr>
      <td class="strong">${l.name}</td>
      <td>${raw(l.up ? '<span class="badge" data-t="ok">up</span>' : '<span class="badge" data-t="off">down</span>')}</td>
      <td>${l.mtu}</td>
      <td class="muted">${orDash(list(l.flags).join(', '))}</td>
    </tr>`).join('');

  const addrs = list(s.addresses).map((a) => html`
    <tr><td class="strong">${orDash(a.interface)}</td><td class="strong">${a.cidr}</td><td class="muted">${orDash(a.family)}</td></tr>`).join('');

  const routes = list(s.routes).map((r) => html`
    <tr><td class="strong">${r.dst}</td><td>${orDash(r.via)}</td><td>${orDash(r.dev)}</td><td class="muted">${r.metric || 0}</td></tr>`).join('');

  const fwdOK = nr.forwarding_ok;
  view.innerHTML = html`
    ${raw(!nr.supported ? html`
      <div class="banner" data-sev="info"><span class="banner-icon">i</span>
      <div><b>当前平台不支持管理内核网络参数（${orDash(s.platform)}）</b>
      <div>转发开关、路由与策略路由只在 Linux 上可读。这里展示的是能拿到的部分。</div></div></div>`
      : fwdOK ? '' : html`
      <div class="banner" data-sev="bad"><span class="banner-icon">!</span>
      <div><b>IPv4 转发未开启 —— 防火墙策略对跨网段流量不生效</b>
      <div>规则集看起来会是完全正确的、nft 也加载成功，但转发流量根本不会到达
      forward 钩子。这大概是最容易被忽略的一条。</div>
      <div style="margin-top:6px">修复：<code>sysctl -w net.ipv4.ip_forward=1</code>，
      或在配置中打开 <code>manage_sysctls: true</code>。</div></div></div>`)}

    <section class="sec">
      <div class="sec-head"><h2 class="sec-title">内核参数</h2>
        <span class="sec-note">${diff.length ? diff.length + ' 项与基线不一致' : '与基线一致'}</span></div>
      ${raw(diff.length ? html`
        <div class="tbl-wrap"><table class="tbl">
          <thead><tr><th>参数</th><th>当前</th><th>建议</th></tr></thead>
          <tbody>${raw(diff.map((c) => html`<tr>
            <td class="strong">${c.target}</td>
            <td>${raw(c.from ? esc(c.from) : '<span class="muted">（读不到）</span>')}</td>
            <td class="strong">${c.to}</td></tr>`).join(''))}</tbody>
        </table></div>
        ${raw(nr.supported ? html`<div style="margin-top:14px"><button class="btn" id="applySysctl">按基线写入这些参数</button></div>` : '')}`
        : html`<div class="empty"><strong>内核参数符合基线</strong></div>`)}
    </section>

    <section class="sec">
      <div class="sec-head"><h2 class="sec-title">接口</h2></div>
      ${raw(links ? html`<div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>名称</th><th>状态</th><th>MTU</th><th>标志</th></tr></thead>
        <tbody>${raw(links)}</tbody></table></div>` : html`<div class="empty"><strong>读不到接口</strong></div>`)}
    </section>

    <section class="sec">
      <div class="sec-head"><h2 class="sec-title">地址</h2></div>
      ${raw(addrs ? html`<div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>接口</th><th>地址</th><th>族</th></tr></thead>
        <tbody>${raw(addrs)}</tbody></table></div>` : html`<div class="empty"><strong>读不到地址</strong></div>`)}
    </section>

    <section class="sec">
      <div class="sec-head"><h2 class="sec-title">路由</h2></div>
      ${raw(routes ? html`<div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>目的</th><th>网关</th><th>接口</th><th>度量</th></tr></thead>
        <tbody>${raw(routes)}</tbody></table></div>` : html`<div class="empty"><strong>读不到路由</strong></div>`)}
    </section>`;

  const b = $('#applySysctl');
  if (b) b.onclick = () => {
    const lines = diff.map((c) => `${c.target}: ${c.from || '（读不到）'} → ${c.to}`);
    confirmDangerous('写入内核参数', [
      '将执行以下变更：',
      ...lines,
      '这些改动立即生效，不需要「下发」。',
    ], 'write', async () => {
      await guard(() => api.post('/net/sysctls', { sysctls: [] }), '内核参数已写入');
      render();
    });
  };
}

/* ============================================================
   视图：审计
   ============================================================ */

async function viewAudit(view) {
  const [ar, rev, st] = await Promise.all([
    api.get('/audit?limit=200').catch(() => ({ audit: [] })),
    api.get('/revisions').catch(() => ({ revisions: [] })),
    api.get('/status'),
  ]);
  paintChrome(st);

  const audit = list(ar.audit);
  const auditRows = audit.map((e) => html`
    <tr>
      <td class="nowrap muted">${hhmmss(e.at)}</td>
      <td class="nowrap">${raw(badge(e.action))}</td>
      <td class="muted nowrap">${orDash(e.actor)}</td>
      <td class="strong nowrap">${orDash(e.target)}</td>
      <td>${orDash(e.detail)}</td>
    </tr>`).join('');

  const revs = list(rev.revisions);
  const revRows = revs.map((r) => html`
    <tr>
      <td>${r.seq}</td>
      <td class="nowrap muted">${hhmmss(r.at)}</td>
      <td>${r.rules}</td>
      <td class="nowrap"><code>${orDash(r.hash)}</code></td>
      <td>${orDash(r.note)}</td>
    </tr>`).join('');

  view.innerHTML = html`
    <section class="sec">
      <div class="sec-head"><h2 class="sec-title">下发历史</h2>
        <span class="sec-note">最近 ${revs.length} 次</span></div>
      ${raw(revs.length ? html`
        <div class="tbl-wrap"><table class="tbl">
          <thead><tr><th>#</th><th>时间</th><th>规则数</th><th>哈希</th><th>说明</th></tr></thead>
          <tbody>${raw(revRows)}</tbody></table></div>`
        : html`<div class="empty"><strong>还没有下发记录</strong></div>`)}
    </section>

    <section class="sec">
      <div class="sec-head"><h2 class="sec-title">操作审计</h2>
        <span class="sec-note">所有写操作：谁、什么时候、改了什么</span></div>
      ${raw(audit.length ? html`
        <div class="tbl-wrap"><table class="tbl">
          <thead><tr><th>时间</th><th>动作</th><th>操作者</th><th>对象</th><th>详情</th></tr></thead>
          <tbody>${raw(auditRows)}</tbody></table></div>`
        : html`<div class="empty"><strong>暂无审计记录</strong></div>`)}
    </section>`;
}

/* ============================================================
   顶栏动作
   ============================================================ */

$('#refreshBtn').onclick = () => { refresh(); toast('已刷新', '', 'ok', 1400); };

$('#applyBtn').onclick = () => confirmDangerous('下发到内核', [
  '将用当前期望状态整体替换内核中的规则集。',
  '替换是单事务的：要么全部生效，要么内核保持原样。',
  '如果现在开着 commit-confirm，下发后需要及时确认，否则会自动回滚。',
], 'apply', async () => {
  const r = await guard(() => api.post('/apply'));
  toast('已下发', `${r.rules} 条规则 · 哈希 ${r.hash}`, 'ok');
  refresh();
});

$('#modalClose').onclick = closeModal;

/* ============================================================
   事件流
   ============================================================ */

let sse = null;

// ?live=off 关闭实时推送。有些反向代理会缓冲或直接掐掉 SSE，
// 隔离网络里也可能不通；关掉之后界面退化为定时刷新，功能不受影响。
const LIVE = new URLSearchParams(location.search).get('live') !== 'off';

function connectSSE() {
  if (!LIVE) {
    $('#sseLed').dataset.state = 'off';
    $('#sseText').textContent = '已关闭';
    return;
  }
  if (sse) sse.close();
  const url = '/api/v1/events' + (api.token ? '?token=' + encodeURIComponent(api.token) : '');
  sse = new EventSource(url);

  sse.addEventListener('open', () => {
    $('#sseLed').dataset.state = 'ok';
    $('#sseText').textContent = '已连接';
  });

  sse.addEventListener('fwdd', (ev) => {
    let e;
    try { e = JSON.parse(ev.data); } catch { return; }
    state.events.unshift(e);
    if (state.events.length > 200) state.events.pop();
    applyEvent(e);
  });

  sse.addEventListener('error', () => {
    $('#sseLed').dataset.state = 'bad';
    $('#sseText').textContent = '已断开';
  });
}

/** 把新事件插入总览页的表格顶部 —— 不重排整页，避免打断阅读。 */
function applyEvent(e) {
  const tbody = document.querySelector('#evTable tbody');
  if (!tbody) { if (!e.fromSSE) refreshSoon(); return; }

  const tr = document.createElement('tr');
  tr.className = 'row-enter';
  tr.innerHTML = html`
    <td class="nowrap muted">${hhmmss(e.at)}</td>
    <td class="nowrap">${raw(badge(e.kind))}</td>
    <td class="strong nowrap">${orDash(e.target)}</td>
    <td>${orDash(e.detail)}</td>`;
  tbody.prepend(tr);
  while (tbody.children.length > 60) tbody.lastElementChild.remove();

  // 触及全局状态的事件，顺手刷新一下顶栏与统计
  if (['apply', 'rollback', 'confirm', 'ban.add', 'ban.remove', 'policy.set'].includes(e.kind)) {
    refreshSoon();
  }
}

let refreshTimer = null;
function refreshSoon() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(refresh, 350);
}

/* ============================================================
   刷新循环
   ============================================================ */

async function refresh() {
  try {
    const st = await api.get('/status');
    state.status = st;
    paintChrome(st);
    if (state.page === 'dashboard') await render();
    setStatusLine('已刷新 · ' + new Date().toLocaleTimeString('zh-CN'));
  } catch (e) {
    if (e.needsToken) return showTokenGate();
    $('#syncLed').dataset.state = 'bad';
    $('#syncText').textContent = '失联';
    setStatusLine('无法连接 fwdd：' + e.message);
  }
}

function setStatusLine(t) { $('#statLineLeft').textContent = t; }

function startClock() {
  const tick = () => { $('#statLineClock').textContent = new Date().toLocaleString('zh-CN', { hour12: false }); };
  tick();
  setInterval(tick, 1000);
}

/* ============================================================
   启动
   ============================================================ */

async function boot() {
  try {
    await api.get('/status');
  } catch (e) {
    if (e.needsToken) return showTokenGate();
  }
  $('#tokenGate').hidden = true;
  connectSSE();
  await navigate();
  refresh();
  clearInterval(state.timer);
  state.timer = setInterval(() => {
    if (document.hidden) return;       // 页面不可见时不打扰服务端
    refresh();
  }, 15000);
}

document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });

startClock();
boot();
