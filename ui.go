package main

import (
	"fmt"
	"strings"
)

// ---------------- theme + base style ----------------

// themeHeadJS runs before first paint so the chosen theme never flashes.
const themeHeadJS = `<script>(function(){try{var t=localStorage.getItem('huboze-theme');
if(t!=='light'&&t!=='dark'){t=window.matchMedia&&matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'}
document.documentElement.dataset.theme=t}catch(e){document.documentElement.dataset.theme='dark'}})();</script>`

const baseStyle = themeHeadJS + `
<style>
:root{--bg:#0b0f19;--panel:#111725;--panel2:#18202f;--hover:#1d2638;--border:#222c3d;--input:#0d1320;--input-border:#2c3850;
--text:#e6e9ef;--muted:#8a94a6;--label:#c3cad6;--accent:#3b82f6;--accent-2:#6366f1;--accent-text:#93c5fd;
--ok:#34d399;--ok-bg:rgba(52,211,153,.13);--bad:#f87171;--bad-bg:rgba(248,113,113,.14);--warn:#fbbf24;--warn-bg:rgba(251,191,36,.13);
--info:#60a5fa;--info-bg:rgba(96,165,250,.13);--mute-bg:rgba(148,163,184,.13);
--btn:#2563eb;--btn-h:#1d4ed8;--btn2:#263043;--btn2-h:#2f3b52;--btn2-text:#dbe1ea;--danger:#dc2626;--danger-h:#b91c1c;--on:#059669;--off:#475569;
--shadow:0 12px 32px rgba(0,0,0,.45);--radius:14px;color-scheme:dark}
:root[data-theme=light]{--bg:#f4f6fa;--panel:#ffffff;--panel2:#f6f8fb;--hover:#eef2f7;--border:#e2e7ef;--input:#ffffff;--input-border:#cfd7e3;
--text:#0f172a;--muted:#667085;--label:#344054;--accent:#2563eb;--accent-2:#4f46e5;--accent-text:#1d4ed8;
--ok:#059669;--ok-bg:#e7f8f1;--bad:#dc2626;--bad-bg:#fdecec;--warn:#b45309;--warn-bg:#fdf4e3;--info:#2563eb;--info-bg:#eaf1fe;--mute-bg:#eef1f5;
--btn:#2563eb;--btn-h:#1d4ed8;--btn2:#eef1f5;--btn2-h:#e2e7ef;--btn2-text:#344054;--danger:#dc2626;--danger-h:#b91c1c;--on:#059669;--off:#98a2b3;
--shadow:0 12px 32px rgba(15,23,42,.14);color-scheme:light}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei","Noto Sans CJK SC",sans-serif;-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:none}a.link{color:var(--accent-text)}a.link:hover{text-decoration:underline}
code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:12px}
.wrap{display:flex;min-height:100vh}

/* ---- sidebar ---- */
.side{width:232px;background:var(--panel);border-right:1px solid var(--border);padding:20px 12px;position:fixed;top:0;bottom:0;display:flex;flex-direction:column;z-index:20}
.brand{display:flex;align-items:center;gap:10px;margin:0 8px 22px}
.logo{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--accent-2));display:grid;place-items:center;color:#fff;font-weight:800;font-size:16px;flex:none}
.brand-name{font-weight:700;font-size:15px;line-height:1.2}.ver{font-size:11px;color:var(--muted);font-weight:400}
.nav a{display:flex;align-items:center;gap:10px;padding:9px 12px;margin:2px 0;border-radius:9px;color:var(--muted);font-weight:500}
.nav a svg{width:18px;height:18px;flex:none}
.nav a:hover{background:var(--hover);color:var(--text)}.nav a.on{background:var(--info-bg);color:var(--accent-text)}
.side-foot{margin-top:auto;display:flex;flex-direction:column;gap:4px;padding:12px 0 0;border-top:1px solid var(--border)}
.side-btn{display:flex;align-items:center;gap:10px;width:100%;background:transparent;color:var(--muted);padding:8px 12px;border-radius:9px;font-size:13px;font-weight:500}
.side-btn:hover{background:var(--hover);color:var(--text)}.side-btn svg{width:17px;height:17px;flex:none}.side-btn>span{display:inline-flex}

/* ---- main ---- */
.main{margin-left:232px;width:calc(100% - 232px);padding:28px 32px 40px;max-width:1680px}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;gap:12px;flex-wrap:wrap}
.top-sub{color:var(--muted);font-size:13px;margin-top:2px}
h1{font-size:22px;margin:0;font-weight:700;letter-spacing:.2px}h2{font-size:16px;margin:2px 0 12px;font-weight:650}h3{font-size:14px;margin:0;font-weight:650}
.card{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:18px 20px;margin-bottom:16px}
.card-head{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap}.card-head h2{margin:0}
.card-head .muted{margin-top:2px}
.count{display:inline-block;min-width:20px;padding:0 7px;margin-left:6px;border-radius:999px;background:var(--mute-bg);color:var(--muted);font-size:12px;text-align:center;font-weight:600;vertical-align:1px}
.tbl{overflow-x:auto;margin:0 -4px;padding:0 4px}
:root[data-theme=light] .t-dark,:root:not([data-theme=light]) .t-light{display:none!important}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.metric{font-size:24px;font-weight:700}
.muted{color:var(--muted);font-size:13px}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.info{color:var(--info)}
.hint{background:var(--panel2);border:1px solid var(--border);border-radius:10px;padding:10px 12px;color:var(--muted);font-size:13px;margin:8px 0 12px}
.section-title{font-size:12px;font-weight:700;color:var(--muted);letter-spacing:.5px;margin:18px 0 10px;padding-top:14px;border-top:1px solid var(--border)}

/* ---- tables ---- */
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px}
th,td{text-align:left;padding:10px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);white-space:nowrap;font-weight:600;font-size:12px;background:var(--panel2);border-bottom:1px solid var(--border)}
th:first-child{border-top-left-radius:8px}th:last-child{border-top-right-radius:8px}
tr:last-child td{border-bottom:0}tr:hover td{background:color-mix(in srgb,var(--hover) 55%,transparent)}
td.nm{white-space:nowrap}td.ip,td.ipc{font-family:ui-monospace,Consolas,monospace;font-size:12px;min-width:120px;max-width:220px;word-break:break-all}
td.act .actions{flex-wrap:nowrap}td.dia{white-space:pre-line;font-family:ui-monospace,Consolas,monospace;font-size:12px;min-width:220px;max-width:300px;word-break:break-all}
td.err{min-width:170px;max-width:270px}

/* ---- forms & buttons ---- */
input,select,textarea{width:100%;padding:9px 11px;background:var(--input);border:1px solid var(--input-border);border-radius:8px;color:var(--text);margin-top:5px;font:inherit}
input[type=checkbox],input[type=radio]{width:auto;margin:0 6px 0 0;accent-color:var(--accent)}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--info-bg)}
label{font-size:13px;color:var(--label);display:block;margin-bottom:12px;font-weight:500}.row{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.row.row3{grid-template-columns:repeat(3,minmax(0,1fr))}
button,.btn{display:inline-flex;align-items:center;gap:6px;border:0;border-radius:8px;padding:8px 14px;background:var(--btn);color:#fff;cursor:pointer;font:inherit;font-size:13px;font-weight:600;white-space:nowrap;line-height:1.4}
button:hover,.btn:hover{background:var(--btn-h)}button svg,.btn svg{width:15px;height:15px}
.btn2{background:var(--btn2);color:var(--btn2-text)}.btn2:hover{background:var(--btn2-h)}
.danger{background:var(--danger);color:#fff}.danger:hover{background:var(--danger-h)}
.menu-pop .danger{background:transparent;color:var(--bad)}.menu-pop .danger:hover{background:var(--bad-bg)}
button:disabled{opacity:.6;cursor:wait}
.small{padding:5px 10px;font-size:12px}
.actions{display:flex;gap:6px;flex-wrap:wrap;align-items:center}.actions form{margin:0}
.toggle-on{background:var(--on)}.toggle-off{background:var(--off)}
.password-wrap{position:relative}.password-wrap input{padding-right:92px}.pw-toggle{position:absolute;right:6px;top:7px;width:auto;background:var(--btn2);color:var(--btn2-text);padding:5px 10px}
.match-ok{color:var(--ok)}.match-bad{color:var(--bad)}
.code{font-family:ui-monospace,Consolas,monospace;background:var(--input);border:1px solid var(--border);padding:10px;border-radius:8px;white-space:pre-wrap;word-break:break-all;font-size:12px}

/* ---- badges / pills ---- */
.status-badge,.pill{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:999px;background:var(--mute-bg);color:var(--muted);font-weight:600;font-size:12px;white-space:nowrap;line-height:20px}
.ok .status-badge,.status-badge.ok,.pill.ok{background:var(--ok-bg);color:var(--ok)}
.bad .status-badge,.status-badge.bad,.pill.bad{background:var(--bad-bg);color:var(--bad)}
.warn .status-badge,.status-badge.warn,.pill.warn{background:var(--warn-bg);color:var(--warn)}
.info .status-badge,.status-badge.info,.pill.info{background:var(--info-bg);color:var(--info)}
.pill::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}.pill.plain::before{display:none}
.tag{display:inline-block;padding:0 6px;border-radius:5px;border:1px solid var(--border);color:var(--muted);font-size:11px;font-weight:600;line-height:18px;vertical-align:1px;white-space:nowrap}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--muted);flex:none}
.dot.ok{background:var(--ok);box-shadow:0 0 0 3px var(--ok-bg)}.dot.bad{background:var(--bad);box-shadow:0 0 0 3px var(--bad-bg)}
.dot.warn{background:var(--warn);box-shadow:0 0 0 3px var(--warn-bg)}.dot.info{background:var(--info);box-shadow:0 0 0 3px var(--info-bg)}
.saved{display:inline-block;margin-left:6px;padding:1px 8px;border-radius:999px;background:var(--ok-bg);color:var(--ok);font-size:11px;font-weight:700}

/* ---- flash ---- */
.msg{position:relative;padding:11px 40px 11px 14px;border-radius:10px;margin-bottom:12px;background:var(--panel);border:1px solid var(--border);transition:opacity .4s}
.msg.success{border-left:4px solid var(--ok)}.msg.error{border-left:4px solid var(--bad)}.msg.warning{border-left:4px solid var(--warn)}
.msg-x{position:absolute;right:6px;top:6px;background:transparent;color:var(--muted);font-size:18px;line-height:1;padding:3px 8px}.msg-x:hover{background:var(--hover)}

/* ---- relative time, clip, menus ---- */
.ts{border-bottom:1px dotted var(--muted);cursor:help;white-space:nowrap}
details.clip summary{cursor:pointer;list-style:none}details.clip summary::-webkit-details-marker{display:none}
details.clip summary::after{content:" 展开";color:var(--info);font-size:12px}details.clip[open] summary::after{content:" 收起"}
details.clip[open] summary .clip-short{display:none}.clip-full{white-space:pre-wrap;word-break:break-all}
details.menu{display:inline-block}details.menu>summary{list-style:none}details.menu>summary::-webkit-details-marker{display:none}
.menu-pop{position:fixed;z-index:50;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:6px;min-width:170px;box-shadow:var(--shadow);display:flex;flex-direction:column;gap:2px}
.menu-pop form{margin:0}.menu-pop button,.menu-pop .btn{width:100%;justify-content:flex-start;background:transparent;color:var(--text);font-weight:500}
.menu-pop button:hover,.menu-pop .btn:hover{background:var(--hover)}
details.fold>summary{cursor:pointer;list-style:none;display:flex;align-items:center;justify-content:space-between;gap:10px}
details.fold>summary::-webkit-details-marker{display:none}details.fold>summary::after{content:"展开 ▾";color:var(--muted);font-size:12px}
details.fold[open]>summary::after{content:"收起 ▴"}details.fold[open]>summary{margin-bottom:12px}details.fold>summary h2{margin:0}

/* ---- onboarding ---- */
.steps{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin-top:10px}
.step{border:1px solid var(--border);border-radius:12px;padding:14px;background:var(--panel2)}.step b{display:block;margin-bottom:6px}
.step.done{opacity:.6}.step.done b::before{content:"✓ ";color:var(--ok)}.step.next{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent) inset}
.filters{display:grid;grid-template-columns:140px 160px 1fr auto;gap:10px;align-items:end}.filters label{margin:0}
.pager{display:flex;gap:6px;align-items:center;justify-content:flex-end;margin-top:12px;flex-wrap:wrap}

/* ---- dashboard ---- */
.hero{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:16px;overflow:hidden;position:relative}
.hero::before{content:"";position:absolute;inset:0 0 auto 0;height:3px;background:var(--ok)}
.hero.s-warn::before{background:var(--warn)}.hero.s-bad::before{background:var(--bad)}.hero.s-idle::before{background:var(--info)}
.hero-main{display:flex;align-items:center;gap:16px;padding:20px 22px}.hero-main form{margin:0}
.hero-icon{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;background:var(--ok-bg);color:var(--ok);flex:none}
.hero-icon svg{width:24px;height:24px}
.s-warn .hero-icon{background:var(--warn-bg);color:var(--warn)}.s-bad .hero-icon{background:var(--bad-bg);color:var(--bad)}.s-idle .hero-icon{background:var(--info-bg);color:var(--info)}
.hero-text{flex:1;min-width:0}.hero-title{font-size:18px;font-weight:700}.hero-sub{color:var(--muted);font-size:13px;margin-top:2px}
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));border-top:1px solid var(--border)}
.kpi{padding:14px 22px;border-right:1px solid var(--border);display:block}.kpi:last-child{border-right:0}.kpi:hover{background:var(--hover)}
.kpi-label{color:var(--muted);font-size:12px;font-weight:600}
.kpi-val{font-size:24px;font-weight:700;margin-top:2px;line-height:1.3}.kpi-val small{font-size:14px;color:var(--muted);font-weight:600;margin-left:2px}
.bar{display:block;height:4px;border-radius:4px;background:var(--mute-bg);margin-top:8px;overflow:hidden}.bar i{display:block;height:100%;background:var(--ok);border-radius:4px}
.bar.warn i{background:var(--warn)}.bar.bad i{background:var(--bad)}.bar.none i{background:transparent}
.issue{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:12px;align-items:start;padding:12px 4px;border-top:1px solid var(--border)}
.issue:first-child{border-top:0;padding-top:2px}.issue .dot{margin-top:7px}
.issue-title{font-weight:600}.issue-detail{color:var(--muted);font-size:13px;margin-top:2px;word-break:break-word}
.issue-side{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:12px;white-space:nowrap}
.dash-cols{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(340px,1fr);gap:16px;align-items:start;margin-bottom:16px}
.dash-cols>.card{margin-bottom:0}
.dom-name{font-weight:600;white-space:nowrap}.sub.nm{white-space:nowrap}.sub{color:var(--muted);font-size:12px;margin-top:3px}
.dev{border:1px solid var(--border);border-radius:12px;padding:14px;background:var(--panel2)}.dev+.dev{margin-top:12px}
.dev-head{display:flex;justify-content:space-between;align-items:center;gap:8px}
.lines{margin-top:10px;display:flex;flex-direction:column;gap:4px}
.line{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:10px;align-items:start;padding:8px 10px;border-radius:9px;background:var(--panel)}
.line .dot{margin-top:6px}.line-name{font-weight:600;font-size:13px}.line-ip{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--label);word-break:break-all}
.line-ip.v6{color:var(--muted)}.chips{display:flex;flex-wrap:wrap;gap:4px;justify-content:flex-end;max-width:190px}
.chip{font-size:11px;padding:1px 7px;border-radius:6px;background:var(--mute-bg);color:var(--label);white-space:nowrap;max-width:180px;overflow:hidden;text-overflow:ellipsis}
.chip.bad{background:var(--bad-bg);color:var(--bad)}.chip.warn{background:var(--warn-bg);color:var(--warn)}
.event{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:12px;padding:9px 2px;border-top:1px solid var(--border);align-items:start}
.event:first-child{border-top:0}.event .dot{margin-top:6px}.event-msg{word-break:break-word}.event-meta{color:var(--muted);font-size:12px;white-space:nowrap;text-align:right}
.sysline{display:flex;flex-wrap:wrap;gap:6px 18px;color:var(--muted);font-size:12px;padding:0 4px}
.empty{text-align:center;padding:28px 10px;color:var(--muted)}.empty .btn{margin-top:12px}.empty b{display:block;color:var(--text);font-size:15px;margin-bottom:4px}

/* ---- list pages ---- */
.devgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(420px,1fr));gap:16px}.devgrid>.card{margin:0}
.dcard{display:flex;flex-direction:column}.dcard .lines{flex:1}.dcard-foot{margin-top:14px;padding-top:12px;border-top:1px solid var(--border)}
.dcard .line{background:var(--panel2)}
.errbox{margin-top:10px;padding:8px 10px;border-radius:8px;background:var(--bad-bg);color:var(--bad);font-size:13px;word-break:break-word}
.form-card{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent) inset}
.ptype{display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:9px;font-weight:800;font-size:13px;color:#fff;flex:none}
.ptype.cloudflare{background:#f38020}.ptype.tencent{background:#0052d9}.ptype.aliyun{background:#ff6a00}.ptype.huawei{background:#c7000b}
.choice{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin:6px 0 14px}
.choice label{margin:0;display:flex;align-items:center;gap:8px;padding:10px 12px;border:1px solid var(--input-border);border-radius:10px;cursor:pointer;background:var(--input)}
.choice label:has(input:checked){border-color:var(--accent);box-shadow:0 0 0 1px var(--accent) inset;background:var(--info-bg)}
.choice input{position:absolute;opacity:0;pointer-events:none}

details.clip-more{margin-top:6px;font-size:12px;color:var(--muted)}details.clip-more summary{cursor:pointer;color:var(--accent-text)}

/* ---- dns page ---- */
.sumbar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}
.sum{display:flex;align-items:center;gap:8px;padding:8px 14px;border-radius:10px;background:var(--panel);border:1px solid var(--border);font-size:13px;color:var(--muted)}
.sum b{font-size:18px;color:var(--text)}
.dnsgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(520px,1fr));gap:16px}.dnsgrid>.card{margin:0}
.kv{display:grid;grid-template-columns:110px minmax(0,1fr);gap:6px 12px;margin:12px 0;font-size:13px}.kv>div:nth-child(odd){color:var(--muted)}
.kv code{word-break:break-all}
table.res td,table.res th{padding:7px 10px}table.res td{font-size:12px}
.dns-off{opacity:.6}

/* ---- how it works ---- */
.flow{display:grid;grid-template-columns:minmax(0,1fr) auto minmax(0,1fr) auto minmax(0,1fr) auto minmax(0,1fr);gap:10px;align-items:stretch}
.flow-step{border:1px solid var(--border);border-radius:12px;padding:14px;background:var(--panel2)}.flow-step b{display:block;margin:8px 0 4px}
.flow-icon{width:34px;height:34px;border-radius:9px;display:grid;place-items:center;background:var(--info-bg);color:var(--accent-text)}.flow-icon svg{width:18px;height:18px}
.flow-arrow{display:flex;align-items:center;color:var(--muted);font-size:18px}

/* ---- help ---- */
.help{display:grid;grid-template-columns:200px minmax(0,1fr);gap:20px;align-items:start}
.toc{position:sticky;top:20px;display:flex;flex-direction:column;gap:2px}.toc a{padding:7px 12px;border-radius:8px;color:var(--muted);font-size:13px}.toc a:hover{background:var(--hover);color:var(--text)}
.help .card{scroll-margin-top:16px}.help p{margin:6px 0 10px;line-height:1.75}.help ul,.help ol{margin:6px 0 10px;padding-left:22px;line-height:1.85}
.problem{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:6px}
.problem>div{border:1px solid var(--border);border-radius:12px;padding:14px;background:var(--panel2)}.problem b{display:block;margin-bottom:6px}
.faq details{border-top:1px solid var(--border);padding:12px 2px}.faq details:first-of-type{border-top:0}
.faq summary{cursor:pointer;font-weight:600;list-style:none}.faq summary::-webkit-details-marker{display:none}.faq summary::before{content:"▸ ";color:var(--muted)}
.faq details[open] summary::before{content:"▾ "}.faq details>div{color:var(--label);margin-top:8px;line-height:1.75}
.cmds{display:grid;grid-template-columns:auto minmax(0,1fr);gap:6px 16px;font-size:13px}.cmds code{color:var(--accent-text)}

/* ---- self check ---- */
.checks{display:flex;flex-direction:column}
.check{display:grid;grid-template-columns:auto 200px minmax(0,1fr);gap:12px;align-items:start;padding:12px 4px;border-top:1px solid var(--border)}
.check:first-child{border-top:0}.check .dot{margin-top:6px}.check-name{font-weight:600}.check-detail{color:var(--muted);word-break:break-word}

/* ---- login ---- */
.login{min-height:100vh;display:grid;place-items:center;padding:20px}
.login .card{width:100%;max-width:400px;padding:30px;box-shadow:var(--shadow)}
.login .brand{margin:0 0 6px}.login button{width:100%;justify-content:center;padding:10px;margin-top:4px}

@media(max-width:1200px){.dash-cols{grid-template-columns:minmax(0,1fr)}}
@media(max-width:800px){
.side{position:static;width:100%;padding:12px;border-right:0;border-bottom:1px solid var(--border)}
.brand{margin:0 4px 10px}.nav{display:flex;overflow-x:auto;gap:2px}.nav a{white-space:nowrap;margin:0;padding:8px 10px}
.side-foot{flex-direction:row;margin-top:8px;padding-top:8px}.side-btn{width:auto}
.wrap{display:block}.main{margin:0;width:100%;padding:16px}.row,.row.row3,.filters{grid-template-columns:1fr}
.grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.grid .card{padding:12px;margin-bottom:0}.metric{font-size:20px}.card{padding:14px}
.hero-main{flex-wrap:wrap;padding:16px}.hero-main form{width:100%}.hero-main form button{width:100%;justify-content:center}
.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.kpi{padding:12px 16px}.kpi:nth-child(2){border-right:0}.kpi:nth-child(-n+2){border-bottom:1px solid var(--border)}
.issue,.event{grid-template-columns:auto minmax(0,1fr)}.issue-side,.event-meta{grid-column:2;text-align:left}
.check{grid-template-columns:auto minmax(0,1fr)}.check-detail{grid-column:2}
.chips{max-width:120px}.help{grid-template-columns:minmax(0,1fr)}.toc{position:static;flex-direction:row;flex-wrap:wrap}.problem{grid-template-columns:minmax(0,1fr)}.cmds{grid-template-columns:minmax(0,1fr)}.flow{grid-template-columns:minmax(0,1fr)}.flow-arrow{justify-content:center;transform:rotate(90deg);height:14px}.devgrid,.dnsgrid{grid-template-columns:minmax(0,1fr)}.kv{grid-template-columns:90px minmax(0,1fr)}table.res td,table.res th{padding:6px 4px}table.res td .sub{display:none}table.res code{font-size:11px}table.res .pill{padding:1px 7px}table.res .pill::before{display:none}.choice{grid-template-columns:repeat(2,minmax(0,1fr))}
table.stack tr:first-child{display:none}table.stack tr{display:block;padding:12px 0;border-bottom:1px solid var(--border)}table.stack tr:last-child{border-bottom:0}
table.stack td{display:block;border:0;padding:3px 0;max-width:none;min-width:0!important}table.stack td.nm{display:flex;gap:10px;align-items:baseline}table.stack td.nm .sub{margin:0}}
</style>
`

// icons are small inline SVGs (no external assets), stroke = currentColor.
var icons = map[string]string{
	"dashboard":     `<path d="M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 9h8V3h-8z"/>`,
	"devices":       `<rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 17h.01M10 17h.01M12 13V9M8.5 6.5a5 5 0 0 1 7 0M5.5 3.5a9 9 0 0 1 13 0"/>`,
	"providers":     `<path d="M17.5 19a4.5 4.5 0 0 0 .5-8.97A7 7 0 0 0 4.3 11.5 4 4 0 0 0 6 19z"/>`,
	"mappings":      `<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>`,
	"dns_page":      `<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>`,
	"logs_page":     `<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>`,
	"settings_page": `<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6"/>`,
	"help_page":     `<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3M12 17h.01"/>`,
	"sun":           `<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>`,
	"moon":          `<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>`,
	"logout":        `<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>`,
	"check":         `<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="M22 4 12 14.01l-3-3"/>`,
	"alert":         `<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01"/>`,
	"x":             `<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6M9 9l6 6"/>`,
	"clock":         `<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>`,
	"refresh":       `<path d="M21 12a9 9 0 1 1-2.64-6.36L21 8"/><path d="M21 3v5h-5"/>`,
	"plus":          `<path d="M12 5v14M5 12h14"/>`,
}

func icon(name string) string {
	return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">` + icons[name] + `</svg>`
}

const brandHTML = `<div class="brand"><div class="logo">H</div><div><div class="brand-name">huboze DDNS</div><div class="ver">Agent v` + Version + `</div></div></div>`

// uiJS: theme toggle, dismissible flash messages, relative times, "更多" menus.
const uiJS = `<script>
function toggleTheme(){const t=document.documentElement.dataset.theme==='light'?'dark':'light';
  document.documentElement.dataset.theme=t;try{localStorage.setItem('huboze-theme',t)}catch(e){}}
// flash: success messages fade out automatically; all can be closed
document.querySelectorAll('.msg.success').forEach(function(m){setTimeout(function(){m.style.opacity='0';setTimeout(function(){m.remove()},450)},6000)});
// relative times: timestamps are server-local "YYYY-MM-DD HH:MM:SS"
(function(){
  function parse(s){const m=/^(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)$/.exec(s||'');return m?Date.UTC(+m[1],m[2]-1,+m[3],+m[4],+m[5],+m[6]):null}
  const sn=parse(document.body.dataset.now);const skew=sn===null?0:sn-Date.now();
  function rel(s){const t=parse(s);if(t===null)return s||'-';const a=Math.round((Date.now()+skew-t)/1000);
    if(a<-60)return s;if(a<60)return '刚刚';if(a<3600)return Math.floor(a/60)+' 分钟前';if(a<86400)return Math.floor(a/3600)+' 小时前';
    if(a<30*86400)return Math.floor(a/86400)+' 天前';return s.slice(0,10)}
  function render(el){const v=el.dataset.ts||'';el.textContent=v?rel(v):'-';el.title=v||''}
  window.setTs=function(id,v){const el=document.getElementById(id);if(!el)return;el.dataset.ts=v||'';render(el)};
  window.renderTs=function(){document.querySelectorAll('.ts').forEach(render)};
  renderTs();setInterval(renderTs,30000);
})();
// "更多" menus: fixed-position popover so table scrolling never clips it
(function(){
  function closeAll(except){document.querySelectorAll('details.menu[open]').forEach(function(d){if(d!==except)d.open=false})}
  document.addEventListener('toggle',function(ev){const d=ev.target;if(!d.matches||!d.matches('details.menu')||!d.open)return;
    closeAll(d);const s=d.querySelector('summary').getBoundingClientRect();const p=d.querySelector('.menu-pop');
    p.style.top=(s.bottom+4)+'px';p.style.left='0px';const w=p.offsetWidth;p.style.left=Math.max(8,Math.min(s.right-w,innerWidth-w-8))+'px';
    const h=p.offsetHeight;if(s.bottom+4+h>innerHeight-8)p.style.top=Math.max(8,s.top-h-4)+'px'},true);
  document.addEventListener('click',function(ev){if(!ev.target.closest('details.menu'))closeAll(null)});
  window.addEventListener('scroll',function(){closeAll(null)},true);window.addEventListener('resize',function(){closeAll(null)});
  document.addEventListener('keydown',function(ev){if(ev.key==='Escape')closeAll(null)});
})();
</script>`

func (c *Ctx) layout(title, content, active string) string {
	return c.layoutWith(title, "", "", content, active)
}

// layoutWith renders the page shell. sub is a one-line description under the
// title; headExtra (buttons) is placed on the right of the title.
func (c *Ctx) layoutWith(title, sub, headExtra, content, active string) string {
	var nav strings.Builder
	for _, n := range navItems {
		fmt.Fprintf(&nav, `<a class="%s" href="%s">%s<span>%s</span></a>`, ifs(n[0] == active, "on", ""), n[1], icon(n[0]), n[2])
	}
	logout := ""
	if c.loggedIn() {
		logout = `<a class="side-btn" href="/logout">` + icon("logout") + `<span>退出登录</span></a>`
	}
	subHTML := ""
	if sub != "" {
		subHTML = `<div class="top-sub">` + sub + `</div>`
	}
	return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>` + e(title) + ` - huboze DDNS Agent</title>
` + baseStyle + `</head><body data-now="` + e(nowStr()) + `"><div class="wrap"><aside class="side">` + brandHTML + `
<nav class="nav">` + nav.String() + `</nav><div class="side-foot"><button type="button" class="side-btn" onclick="toggleTheme()"><span class="t-dark">` + icon("sun") + `</span><span class="t-light">` + icon("moon") + `</span><span class="t-dark">浅色主题</span><span class="t-light">深色主题</span></button>` + logout + `</div></aside>
<main class="main"><div class="top"><div><h1>` + e(title) + `</h1>` + subHTML + `</div><div class="actions">` + headExtra + `</div></div>` + c.flashHTML() + content + `</main></div>` + uiJS + submitGuardJS + `</body></html>`
}

func (c *Ctx) flashHTML() string {
	var b strings.Builder
	for _, f := range c.popFlashes() {
		fmt.Fprintf(&b, `<div class="msg %s">%s<button type="button" class="msg-x" title="关闭" onclick="this.parentNode.remove()">×</button></div>`, e(f[0]), e(f[1]))
	}
	return b.String()
}

// ---------------- small render helpers ----------------

// tsSpan renders a timestamp shown as relative time ("3 分钟前") with the absolute time on hover.
func tsSpan(id, ts string) string {
	idAttr := ""
	if id != "" {
		idAttr = ` id="` + e(id) + `"`
	}
	return `<span class="ts"` + idAttr + ` data-ts="` + e(ts) + `" title="` + e(ts) + `">` + e(dash(ts)) + `</span>`
}

// clip shows long text as a one-line summary that expands on click.
func clip(text string, n int) string {
	text = strings.TrimSpace(zhErr(text))
	r := []rune(text)
	if len(r) <= n {
		return e(text)
	}
	return `<details class="clip"><summary><span class="clip-short">` + e(string(r[:n])) + `…</span></summary><div class="clip-full">` + e(text) + `</div></details>`
}

// moreMenu groups secondary/dangerous row actions behind a "更多" button.
func moreMenu(items ...string) string {
	return `<details class="menu"><summary class="btn btn2 small">更多 ▾</summary><div class="menu-pop">` + strings.Join(items, "") + `</div></details>`
}

// savedBadge marks a credential field that already has a stored value.
func savedBadge(v string, showTail bool) string {
	if v == "" {
		return ""
	}
	text := "已保存"
	if r := []rune(v); showTail && len(r) > 8 {
		text += " ••••" + string(r[len(r)-4:])
	}
	return `<span class="saved">✓ ` + e(text) + `</span>`
}

// pill renders a coloured status pill (cls: ok / bad / warn / info / "").
func pill(text, cls string) string {
	return `<span class="pill ` + cls + `">` + e(text) + `</span>`
}

// humanDuration is a coarse "3 天 11 小时" style duration.
func humanDuration(sec int) string {
	switch {
	case sec < 60:
		return "不到 1 分钟"
	case sec < 3600:
		return fmt.Sprintf("%d 分钟", sec/60)
	case sec < 86400:
		return fmt.Sprintf("%d 小时 %d 分", sec/3600, sec%3600/60)
	}
	return fmt.Sprintf("%d 天 %d 小时", sec/86400, sec%86400/3600)
}

// emptyState renders a friendly placeholder with an optional call to action.
func emptyState(title, desc, href, action string) string {
	btn := ""
	if href != "" {
		btn = `<div><a class="btn" href="` + href + `">` + icon("plus") + e(action) + `</a></div>`
	}
	return `<div class="empty"><b>` + e(title) + `</b>` + e(desc) + btn + `</div>`
}

// formCard wraps an add/edit form. It is shown only when requested (?new=1 /
// ?edit=N) or when the list is still empty, so list pages lead with the list.
func formCard(title, desc, cancelHref, inner string, closable bool) string {
	cancel := ""
	if closable {
		cancel = `<a class="btn btn2 small" href="` + cancelHref + `">取消</a>`
	}
	d := ""
	if desc != "" {
		d = `<div class="muted">` + desc + `</div>`
	}
	return `<section class="card form-card" id="form"><div class="card-head"><div><h2>` + e(title) + `</h2>` + d + `</div>` + cancel + `</div>` + inner + `</section>`
}

// addButton is the "+ 添加" button shown in a page header.
func addButton(href, label string) string {
	return `<a class="btn" href="` + href + `#form">` + icon("plus") + e(label) + `</a>`
}

// liveRegion renders a server fragment that the browser re-fetches every 5s
// from url (which must answer with header X-Fragment: name) and swaps in when
// it changed. Expanded details, open menus and busy forms pause the refresh.
func liveRegion(id, url, name, inner string) string {
	return `<div id="` + id + `">` + inner + `</div><script>
(function(){
  const live = document.getElementById('` + id + `');
  let last = live.innerHTML;
  async function refresh(){
    if (document.hidden) return;
    if (live.querySelector('details[open]') || live.querySelector('form[data-busy="1"]')) return;
    try {
      const r = await fetch('` + url + `', {cache:'no-store'});
      if (!r.ok || r.headers.get('X-Fragment') !== '` + name + `') return; // e.g. session expired -> login page
      const h = await r.text();
      if (h !== last) { live.innerHTML = h; last = live.innerHTML; renderTs(); }
    } catch (e) { console.debug('refresh failed', e); }
  }
  setInterval(refresh, 5000);
  document.addEventListener('visibilitychange', function(){ if (!document.hidden) refresh(); });
})();
</script>`
}

func (c *Ctx) fragment(name, html string) {
	c.W.Header().Set("X-Fragment", name)
	c.W.Header().Set("Cache-Control", "no-store")
	c.html(html)
}

const togglePasswordJS = `<script>function togglePassword(id, btn){const el=document.getElementById(id);const show=el.type==='password';el.type=show?'text':'password';btn.textContent=show?'隐藏':'显示';}</script>`
