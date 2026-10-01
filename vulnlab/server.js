/* 本地漏洞练习靶场 —— 仅供个人在自己电脑上学习使用
 * 只监听 127.0.0.1，外网无法访问。
 * 启动： node server.js   然后浏览器打开 http://localhost:3000
 */
const http = require('http');
const querystring = require('querystring');

const HOST = '127.0.0.1';
const PORT = 3000;

/* ---------------- 关卡与 flag ---------------- */
const CHALLENGES = [
  { key: 'weakpass', name: '弱口令登录',        url: '/login',        hint: '管理员账号是 admin，密码试着猜一猜（很多人用 123456 / admin123 / 88888888）' },
  { key: 'sqli',     name: 'SQL 注入',          url: '/user?id=1',    hint: 'id 参数背后是字符串拼接。想一次性取出所有人的记录，怎么构造？' },
  { key: 'idor',     name: '越权访问（IDOR）',  url: '/orders',       hint: '你自己的订单号是 1001。把接口里的 id 换成别的数字试试。' },
  { key: 'logic',    name: '金额篡改',          url: '/shop',         hint: '下单时金额由浏览器提交。如果把它改成很小很小会怎样？' },
  { key: 'xss_ref',  name: '反射型 XSS',        url: '/search?q=hi',  hint: '搜索关键词会不会被原样显示在页面上？试着让它执行一段脚本。' },
  { key: 'xss_sto',  name: '存储型 XSS',        url: '/guestbook',    hint: '留言会被永久保存并展示给所有人。' },
  { key: 'leak',     name: '敏感文件泄露',      url: '/robots.txt',   hint: 'robots.txt 里写了"不希望被搜索引擎抓取"的目录，那种目录往往有东西。' },
];
const FLAGS = {
  weakpass: 'FLAG{n0_m0re_123456}',
  sqli:     'FLAG{sql1_str1ng_c0nc4t_w1ns}',
  idor:     'FLAG{1d0r_ch4nge_the_1d}',
  logic:    'FLAG{trust_n0_client_4mount}',
  xss_ref:  'FLAG{reflected_xss_1s_y0urs}',
  xss_sto:  'FLAG{stored_xss_h1ts_everyone}',
  leak:     'FLAG{b4ckup_f1les_4re_g0ld}',
};

const solved = new Set();
function mark(k) { solved.add(k); }

/* ---------------- 假数据库 ---------------- */
const USERS = [
  { id: 1, username: 'alice',  role: '普通用户', secret: '我的生日是 1998-03-12' },
  { id: 2, username: 'admin',  role: '管理员',   secret: FLAGS.sqli },
  { id: 3, username: 'bob',    role: '普通用户', secret: '我的手机是 138****1234' },
];
const ORDERS = {
  1001: { owner: 'you',   item: '机械键盘', amount: 399, note: '这是你自己的订单' },
  1002: { owner: 'alice', item: '显示器',   amount: 1899, note: '这是别人的订单', secret: FLAGS.idor },
};
let commentList = [
  { user: '管理员', text: '欢迎来到留言板，请文明发言。' },
];
let ordersCreated = [];

/* ---------------- 极简 SQL 语义模拟 ----------------
 * 真实世界里 SQL 注入的成因是：把用户输入直接拼进 SQL 语句字符串。
 * 这里用同样的方式还原它 —— 拼接 → 求值。
 */
function runQuery(sql) {
  const wherePart = sql.split(/where/i)[1] || '';
  let expr = wherePart
    .replace(/'([^']*)'/g, '"$1"')          // SQL 字符串字面量 → JS 字符串
    .replace(/\bor\b/gi, '||')
    .replace(/\band\b/gi, '&&')
    .replace(/([^<>!=])=([^=])/g, '$1===$2'); // SQL 的 = 是相等判断
  try {
    const fn = new Function('id', 'username', 'return (' + expr + ');');
    return { ok: true, rows: USERS.filter((u) => fn(u.id, u.username)) };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/* ---------------- 页面骨架 ---------------- */
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function flagBox(key) {
  if (!solved.has(key)) return '';
  return `<div class="flag">已通关 &nbsp;·&nbsp; ${FLAGS[key]}</div>`;
}
function page(title, body) {
  const done = solved.size;
  const bar = CHALLENGES.map((c) => `<span class="chip ${solved.has(c.key) ? 'ok' : ''}">${esc(c.name)}</span>`).join('');
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · 本地靶场</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#F5F6F4;color:#1F2321;font-family:system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;font-size:15px;line-height:1.7}
.wrap{max-width:860px;margin:0 auto;padding:32px 22px 70px}
.warn{background:#FCEBEB;border:1px solid #F0BEBE;color:#791F1F;border-radius:12px;padding:14px 18px;font-size:13.5px;margin-bottom:24px}
.nav{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-bottom:8px}
.nav a{color:#185FA5;text-decoration:none;font-size:14px;border-bottom:1px solid #B5D4F4}
h1{font-size:24px;font-weight:600;margin:0 0 6px}
h2{font-size:17px;font-weight:600;margin:28px 0 10px}
p{color:#5A605C;font-size:14px}
.progress{display:flex;flex-wrap:wrap;gap:7px;margin:14px 0 4px}
.chip{font-size:12px;padding:3px 10px;border-radius:999px;background:#F1EFE8;color:#888780;border:1px solid #D3D1C7}
.chip.ok{background:#E1F5EE;color:#085041;border-color:#9FE1CB}
.card{background:#fff;border:1px solid #E3E5E0;border-radius:14px;padding:18px 20px;margin-bottom:12px}
.card h3{margin:0 0 6px;font-size:15px;font-weight:600}
.card .hint{color:#8A908C;font-size:13px;margin:0 0 10px}
.card code{background:#F1EFE8;padding:2px 6px;border-radius:4px;font-size:12.5px;color:#444441}
.flag{background:#E1F5EE;border:1px solid #9FE1CB;color:#085041;border-radius:10px;padding:12px 16px;margin:14px 0;font-family:ui-monospace,Consolas,monospace;font-size:14px;font-weight:600}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #E3E5E0;border-radius:10px;overflow:hidden;font-size:13.5px;margin:12px 0}
th{background:#F1EFE8;text-align:left;padding:9px 12px;font-size:13px}
td{padding:9px 12px;border-top:1px solid #E3E5E0;color:#5A605C}
form{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
input,button{font:inherit;font-size:14px;padding:8px 12px;border-radius:8px;border:1px solid #D2D5CE;background:#fff}
input:focus{outline:2px solid #B5D4F4;border-color:#378ADD}
button{background:#185FA5;color:#fff;border-color:#185FA5;cursor:pointer}
button:hover{background:#0C447C}
.err{background:#FCEBEB;border:1px solid #F0BEBE;color:#791F1F;border-radius:10px;padding:10px 14px;font-size:13.5px;margin:12px 0;font-family:ui-monospace,Consolas,monospace}
.msg{border-bottom:1px solid #E3E5E0;padding:10px 0}
.msg:last-child{border-bottom:0}
.msg .who{font-size:12.5px;color:#8A908C}
.msg .txt{margin-top:2px}
.foot{margin-top:40px;padding-top:18px;border-top:1px solid #E3E5E0;color:#8A908C;font-size:12.5px}
</style></head><body><div class="wrap">
<div class="warn"><b>这是跑在你自己电脑上的练习靶场</b>（只监听 127.0.0.1，外网访问不到）。请只在这里练习。真实网站上未经授权发一个包就是违法行为。</div>
<div class="nav"><a href="/">首页</a><span style="color:#8A908C;font-size:13px">进度 ${done} / ${CHALLENGES.length}</span></div>
<div class="progress">${bar}</div>
${body}
<div class="foot">本地靶场 · 仅供个人学习 · <a href="/reset" style="color:#185FA5">重置进度</a></div>
</div></body></html>`;
}

/* ---------------- 路由 ---------------- */
const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://' + HOST);
  const p = u.pathname;

  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const send = (html, code = 200) => {
      res.writeHead(code, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    };
    const form = querystring.parse(body);

    /* 首页 */
    if (p === '/') {
      const cards = CHALLENGES.map((c, i) => `
        <div class="card">
          <h3>${i + 1}. ${esc(c.name)} ${solved.has(c.key) ? '✅' : ''}</h3>
          <p class="hint">${esc(c.hint)}</p>
          <p class="hint">入口：<code>${esc(c.url)}</code></p>
        </div>`).join('');
      return send(page('首页', `<h1>本地漏洞练习靶场</h1>
        <p>一共 ${CHALLENGES.length} 关，目标是在每一关里拿到对应的 flag。每关都故意留了一个缺陷，用前一步讲的"改值 / 改身份 / 改顺序 / 改类型"去想。</p>
        ${cards}`));
    }

    if (p === '/reset') { solved.clear(); commentList = commentList.slice(0, 1); ordersCreated = []; return send(page('已重置', '<h1>进度已重置</h1><p><a href="/">返回首页</a></p>')); }

    /* 第 1 关：弱口令 */
    if (p === '/login' && req.method === 'GET') {
      const msg = u.searchParams.get('msg') || '';
      return send(page('弱口令登录', `<h1>管理员登录</h1>
        <p>这是一个后台登录入口。真实世界里大量系统就毁在弱密码上。</p>
        ${msg === 'fail' ? '<div class="err">用户名或密码错误</div>' : ''}
        ${flagBox('weakpass')}
        <form method="POST" action="/login">
          <input name="username" placeholder="用户名" autocomplete="off">
          <input name="password" placeholder="密码" type="text" autocomplete="off">
          <button>登录</button>
        </form>`));
    }
    if (p === '/login' && req.method === 'POST') {
      if (form.username === 'admin' && form.password === 'admin123') {
        mark('weakpass');
        return send(page('登录成功', `<h1>登录成功</h1>${flagBox('weakpass')}
          <p>你刚刚做的事叫「弱口令爆破」。实际测试中，平台通常禁止对登录接口做大量尝试（会锁账号），所以弱口令一般只试少数几个常见组合就够了。</p>
          <p><a href="/">返回首页</a></p>`));
      }
      res.writeHead(302, { Location: '/login?msg=fail' }); return res.end();
    }

    /* 第 2 关：SQL 注入 */
    if (p === '/user') {
      const id = u.searchParams.get('id') || '1';
      const sql = 'SELECT * FROM users WHERE id = ' + id;   // ← 缺陷就在这一行：直接拼接
      const r = runQuery(sql);
      let out = `<h1>用户查询</h1>
        <p>服务端实际执行的语句：</p><div class="err">${esc(sql)}</div>`;
      if (!r.ok) {
        out += `<div class="err">SQL 语法错误：${esc(r.error)}</div>`;
      } else if (r.rows.length === 0) {
        out += '<p>没有查到任何记录。</p>';
      } else {
        out += '<table><tr><th>id</th><th>用户名</th><th>角色</th><th>备注</th></tr>' +
          r.rows.map((x) => `<tr><td>${x.id}</td><td>${esc(x.username)}</td><td>${esc(x.role)}</td><td>${esc(x.secret)}</td></tr>`).join('') +
          '</table>';
        if (r.rows.some((x) => x.id === 2)) mark('sqli');
      }
      out += flagBox('sqli');
      return send(page('用户查询', out));
    }

    /* 第 3 关：越权 */
    if (p === '/orders') {
      return send(page('我的订单', `<h1>我的订单</h1>
        <p>你只有一个订单，编号 1001。</p>
        <table><tr><th>订单号</th><th>商品</th><th>金额</th></tr>
        <tr><td>1001</td><td>机械键盘</td><td>¥399</td></tr></table>
        <p>查看订单详情的接口是 <code>/api/order?id=1001</code>。服务端只按 id 查数据，没有校验这个订单是不是你的。</p>`));
    }
    if (p === '/api/order') {
      const id = u.searchParams.get('id') || '';
      const o = ORDERS[id];
      let out = `<h1>订单详情 #${esc(id)}</h1>`;
      if (!o) out += '<p>订单不存在。</p>';
      else {
        out += `<table><tr><th>商品</th><td>${esc(o.item)}</td></tr>
          <tr><th>金额</th><td>¥${o.amount}</td></tr>
          <tr><th>说明</th><td>${esc(o.note)}</td></tr></table>`;
        if (o.secret) { mark('idor'); out += flagBox('idor'); }
      }
      out += '<p><a href="/orders">返回</a></p>';
      return send(page('订单详情', out));
    }

    /* 第 4 关：金额篡改 */
    if (p === '/shop') {
      return send(page('下单', `<h1>商品：机械键盘 ¥399</h1>
        <p>注意看下面这个表单：金额是浏览器提交给服务端的，服务端直接信了它。</p>
        ${flagBox('logic')}
        <form method="POST" action="/api/pay">
          <input name="item" value="机械键盘">
          <input name="amount" value="399">
          <button>提交订单</button>
        </form>
        <p style="font-size:13px;color:#8A908C">提示：不改商品，只改金额，先把它改小一点，再改小很多。</p>`));
    }
    if (p === '/api/pay') {
      const amount = Number(form.amount);
      let out = `<h1>下单结果</h1>`;
      if (Number.isNaN(amount)) out += '<div class="err">金额格式不正确</div>';
      else if (amount <= 0.01) {
        mark('logic');
        out += `<p>下单成功：${esc(form.item)}，实付 ¥${amount}</p>${flagBox('logic')}
          <p>这就是"过度信任客户端"：金额本该由服务端根据商品编号自己算，而不是听浏览器说多少就是多少。</p>`;
        ordersCreated.push({ item: form.item, amount });
      } else {
        out += `<p>下单成功：${esc(form.item)}，实付 ¥${amount}</p>
          <p style="color:#8A908C;font-size:13px">这次你付的是全价。服务端没拦你，只是因为还没改到它"觉得不合理"的程度。</p>`;
        ordersCreated.push({ item: form.item, amount });
      }
      out += '<p><a href="/shop">返回商品页</a></p>';
      return send(page('下单结果', out));
    }

    /* 第 5 关：反射型 XSS */
    if (p === '/search') {
      const q = u.searchParams.get('q');
      if (q === null) return send(page('搜索', `<h1>搜索</h1>
        <form method="GET" action="/search"><input name="q" placeholder="输入关键词"><button>搜索</button></form>`));
      let out = `<h1>搜索结果</h1>
        <p>关键词：<b>${q}</b></p>`;   // ← 缺陷：没有转义，用户输入被当成 HTML 渲染
      if (/<script|\son\w+\s*=|javascript:/i.test(q)) {
        mark('xss_ref');
        out += `<p>你输入的这段内容被浏览器当成"代码"而不是"文字"执行了。</p>${flagBox('xss_ref')}
          <p>正确做法是输出时把 &lt; &gt; &quot; 这些字符转义掉（本靶场首页的进度条就是用转义写的，你可以对照看）。</p>`;
      }
      out += `<p><a href="/search">再搜一次</a></p>`;
      return send(page('搜索结果', out));
    }

    /* 第 6 关：存储型 XSS */
    if (p === '/guestbook' && req.method !== 'POST') {
      const list = commentList.map((c) => `<div class="msg"><div class="who">${esc(c.user)}</div><div class="txt">${c.text}</div></div>`).join('');
      return send(page('留言板', `<h1>留言板</h1>
        <p>留言会保存在服务端，展示给每一个访问者。这就是它比反射型更危险的原因。</p>
        <form method="POST" action="/guestbook">
          <input name="user" placeholder="昵称" style="width:120px">
          <input name="text" placeholder="说点什么" style="flex:1;min-width:200px">
          <button>留言</button>
        </form>
        ${flagBox('xss_sto')}
        <div class="card" style="margin-top:16px">${list}</div>`));
    }
    if (p === '/guestbook' && req.method === 'POST') {
      const text = form.text || '';
      commentList.push({ user: form.user || '游客', text });   // ← 缺陷：原样存，原样显示
      if (/<script|\son\w+\s*=|javascript:|<img/i.test(text)) mark('xss_sto');
      res.writeHead(302, { Location: '/guestbook' }); return res.end();
    }

    /* 第 7 关：敏感文件泄露 */
    if (p === '/robots.txt') {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('User-agent: *\nDisallow: /backup/\nDisallow: /admin/\n');
    }
    if (p === '/backup/config.bak') {
      mark('leak');
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end(`# 站点备份配置 —— 本该永远不放在公网
DB_HOST=127.0.0.1
DB_USER=root
DB_PASS=${FLAGS.leak}   <- 顺手把这关的 flag 藏这儿了
SECRET_KEY=9f3a2b7c1e8d
`);
    }

    send(page('404', `<h1>404 页面不存在</h1><p>路径：<code>${esc(p)}</code></p><p><a href="/">返回首页</a></p>`), 404);
  });
});

server.listen(PORT, HOST, () => {
  console.log('本地靶场已启动： http://localhost:' + PORT);
  console.log('只监听 ' + HOST + '，外网无法访问。按 Ctrl+C 停止。');
});
