package main

import (
	"fmt"
	"strings"
)

// ---------------- 帮助 ----------------

func helpHandler(c *Ctx) {
	poll := getSettingInt("poll_interval", 60)
	check := getSettingInt("domain_check_interval", 300)

	sections := []struct{ id, title string }{
		{"problem", "解决什么问题"},
		{"how", "工作原理"},
		{"plan", "推荐用法"},
		{"start", "快速上手"},
		{"status", "状态说明"},
		{"faq", "常见问题"},
		{"security", "安全说明"},
		{"cli", "服务器命令"},
	}
	var toc strings.Builder
	for _, s := range sections {
		fmt.Fprintf(&toc, `<a href="#%s">%s</a>`, s.id, e(s.title))
	}

	steps := []struct{ icon, title, desc string }{
		{"devices", "① 登录路由器", "通过 SSH 登录 H3C MSR，只执行 display 查看命令，不会修改路由器配置。"},
		{"refresh", "② 读取公网 IP", fmt.Sprintf("每 %d 秒读取一次各 Dialer 拨号口的 IPv4 / IPv6。线路断开、私网地址、运营商 NAT 地址（100.64.x.x）都不会使用。", poll)},
		{"providers", "③ 更新解析", "IP 有变化时，调用 DNS 服务商 API 更新绑定的 A / AAAA 记录；没变化就不调用。"},
		{"dns_page", "④ 确认生效", fmt.Sprintf("每 %d 秒直接查询阿里、腾讯、Cloudflare、Google 公共 DNS，确认解析已生效；记录被外部改动会自动改回。", check)},
	}
	var flow strings.Builder
	for i, s := range steps {
		if i > 0 {
			flow.WriteString(`<div class="flow-arrow">→</div>`)
		}
		fmt.Fprintf(&flow, `<div class="flow-step"><div class="flow-icon">%s</div><b>%s</b><div class="muted">%s</div></div>`, icon(s.icon), e(s.title), e(s.desc))
	}

	faq := []struct{ q, a string }{
		{"设备卡片上 Dialer 的 IP 是 100.64.x.x 或 10.x / 192.168.x，为什么不同步？",
			"这类地址不是真正的公网 IP（运营商 NAT 或内网地址），外面访问不进来，写进 DNS 也没有用，所以 Agent 会拒绝同步。需要联系运营商开通公网 IP。"},
		{"线路明明在用，为什么提示“协议状态为 down，跳过同步”？",
			"Agent 读到该 Dialer 接口的协议状态不是 up（拨号未成功或正在重拨）。为避免把域名指向断开的线路，这一轮会跳过，等线路恢复后自动同步。"},
		{"“DNS 解析”页显示“传播中”是什么意思？",
			"服务商上的记录已经改成新 IP，但部分公共 DNS 还缓存着旧值，要等缓存（TTL）过期才会变。页面会显示预计还需多久，一般不需要处理。"},
		{"显示“解析异常”怎么办？",
			"公共 DNS 返回的 IP 与当前线路 IP 不一致且不是缓存原因。先在“DNS 解析”页看服务商记录值是否正确，再点“立即检测”；如果记录被人在服务商控制台改过，Agent 会自动改回。"},
		{"设备被“自动停用”了？",
			"登录 MSR 时遇到密码错误、账号被锁或要求首次改密，Agent 会自动停用该设备，避免每分钟重试把 H3C 账号锁死。到“MSR 设备”页编辑并核对密码（首次登录的设备用“首次登录改密”），然后重新启用。"},
		{"提示“SSH Host Key 已变化”？",
			"路由器的 SSH 指纹和第一次连接时不一样，可能是设备更换/重置，也可能是中间人攻击。确认管理 IP 对应的确实是你的设备后，在“MSR 设备”的“更多”里点“清除 Host Key”，再重新测试。"},
		{"ping 显示“ICMP 无响应”，是不是线路不通？",
			"不一定，很多运营商和防火墙默认不回应 ping。在映射里填写实际对外开放的 TCP 端口（如 443），可达性检测会改用 TCP 连接，结果更准确。"},
		{"IP 变了之后多久能生效？",
			fmt.Sprintf("最长约为 轮询周期（当前 %d 秒）+ DNS 缓存时间（TTL）。DNSPod / 阿里云新建记录默认 TTL 600 秒，华为云 300 秒，Cloudflare 为自动（约 300 秒）。可以在服务商控制台把 TTL 改短，Agent 更新时会保留你设置的 TTL。", poll)},
		{"可以让一个域名同时解析到 3 条线路吗？",
			"当前不支持，也不推荐：线路断开时旧 IP 不会被移除，访问者会随机连到断开的线路。推荐每条线路一个域名（见“推荐用法”）。"},
		{"删除映射后，DNS 记录会被删掉吗？",
			"不会。删除映射只是不再自动更新，服务商上的记录保持原样；不再使用请到服务商控制台手动删除。"},
		{"忘记管理员密码或白名单配错被锁在外面？",
			"在服务器上执行 huboze-ddns-agent reset-password 重置密码；执行 huboze-ddns-agent reset-whitelist 清空来源白名单。"},
	}
	var faqHTML strings.Builder
	for _, f := range faq {
		fmt.Fprintf(&faqHTML, `<details><summary>%s</summary><div>%s</div></details>`, e(f.q), e(f.a))
	}

	cmds := [][2]string{
		{"huboze-ddns-agent info", "显示部署信息：访问地址、账号、目录"},
		{"huboze-ddns-agent status", "查看运行状态"},
		{"huboze-ddns-agent logs", "查看实时日志"},
		{"huboze-ddns-agent selfcheck", "运行环境自检"},
		{"huboze-ddns-agent restart", "重启服务"},
		{"huboze-ddns-agent backup", "备份（含数据库与加密密钥）"},
		{"huboze-ddns-agent restore 备份包", "从备份恢复"},
		{"huboze-ddns-agent reset-password", "重置管理员密码"},
		{"huboze-ddns-agent reset-whitelist", "清空来源 IP 白名单"},
		{"bash deploy.sh", "用发布包一键安装 / 升级（数据与密码保留）"},
	}
	var cmdHTML strings.Builder
	for _, c := range cmds {
		fmt.Fprintf(&cmdHTML, `<code>%s</code><span class="muted">%s</span>`, e(c[0]), e(c[1]))
	}

	content := `<div class="help"><nav class="toc">` + toc.String() + `</nav><div>

<section class="card" id="problem"><h2>解决什么问题</h2>
<p>企业和门店常用 H3C MSR 路由器接多条宽带（电信、移动、联通），每条都是<b>拨号获得的动态公网 IP</b>，运营商随时可能重新分配地址。IP 一变，远程访问、VPN、对外服务就连不上了。</p>
<div class="problem">
  <div><b>IP 经常变</b><span class="muted">拨号线路重拨、断电、运营商调整后公网 IP 会变化，手工改 DNS 不现实。</span></div>
  <div><b>多条线路难管理</b><span class="muted">一台路由器 3 条线路就有 3 个 IP，还可能各有 IPv6，需要分别对应各自的域名。</span></div>
  <div><b>不知道解析是否生效</b><span class="muted">改了 DNS 不代表用户已经能访问到新 IP，缓存、外部改动、线路断开都可能导致访问失败。</span></div>
</div>
<p style="margin-top:14px">huboze DDNS Agent 自动完成这一切：<b>定时从路由器读取每条线路的公网 IP，变化后自动更新对应域名的解析，并持续确认解析已经生效</b>。支持 Cloudflare、腾讯云 DNSPod、阿里云、华为云，支持 IPv4（A 记录）和 IPv6（AAAA 记录）。</p>
</section>

<section class="card" id="how"><h2>工作原理</h2><div class="flow">` + flow.String() + `</div>
<div class="hint" style="margin:14px 0 0">每条拨号线路绑定自己的域名，哪条线路换了 IP 就只更新哪个域名；每轮只登录路由器一次，就能读出所有线路的 IP。登录 MSR 时如果密码错误或账号被锁，Agent 会自动停用该设备，避免 H3C 账号被反复锁定。</div>
</section>

<section class="card" id="plan"><h2>推荐用法：每条线路一个域名</h2>
<p>例如一台 MSR 有 3 条拨号线路：</p>
<div class="tbl"><table><tr><th>线路</th><th>域名</th><th>记录</th></tr>
<tr><td>Dialer1 电信</td><td><code>hq-ct.example.com</code></td><td>A（+ 有 IPv6 时 AAAA）</td></tr>
<tr><td>Dialer2 移动</td><td><code>hq-cm.example.com</code></td><td>A</td></tr>
<tr><td>Dialer3 联通</td><td><code>hq-cu.example.com</code></td><td>A</td></tr></table></div>
<ul>
<li>某条线路断开只影响它自己的域名，另外两条照常可用，排查时也一眼能看出是哪条线路的问题。</li>
<li>域名建议带上地点和运营商（hq-ct、shop1-cm…），以后增加门店也不会混。</li>
<li>路由器上需要为每条 Dialer 配置端口映射（NAT Server），并保证回程流量走原线路；本软件只负责解析，不修改路由器配置。</li>
</ul>
</section>

<section class="card" id="start"><h2>快速上手</h2>
<ol>
<li><b>添加 DNS 服务商</b>：“DNS 服务商” → 添加服务商，填写 API 凭据（建议用只授权 DNS 的子账号 / Token）。</li>
<li><b>添加 MSR</b>：“MSR 设备” → 添加设备，填写管理 IP、SSH 账号密码，点“保存并测试 SSH”。</li>
<li><b>确认线路</b>：设备卡片上会列出各 Dialer 的 IP，确认都是公网 IP 且显示“已连通”。</li>
<li><b>创建映射</b>：“DNS 映射” → 添加映射，每条线路选一个 Dialer 接口、填一个主机记录；保存时记录不存在会自动创建。</li>
<li><b>检查</b>：首页“域名正常”数量正确，“DNS 解析”页各公共 DNS 都显示“已生效”即完成。</li>
</ol>
</section>

<section class="card" id="status"><h2>状态说明</h2>
<div class="tbl"><table><tr><th>状态</th><th>含义</th></tr>
<tr><td>` + pill("正常", "ok") + ` ` + pill("已生效", "ok") + `</td><td>解析与线路当前 IP 一致，公共 DNS 已返回新 IP。</td></tr>
<tr><td>` + pill("传播中", "info") + `</td><td>记录已更新，部分公共 DNS 还缓存着旧值，等缓存过期即可。</td></tr>
<tr><td>` + pill("等待同步", "info") + ` ` + pill("等待检测", "info") + `</td><td>刚创建或刚启动，下一轮轮询会处理。</td></tr>
<tr><td>` + pill("线路不可达", "warn") + ` ` + pill("验证不足", "warn") + `</td><td>解析正确，但 ping / TCP 检测不通，或可用的公共 DNS 结果太少，仅供参考。</td></tr>
<tr><td>` + pill("设备离线", "warn") + ` ` + pill("设备已停用", "warn") + `</td><td>读不到路由器，域名保持上一次的 IP 不变。</td></tr>
<tr><td>` + pill("同步失败", "bad") + ` ` + pill("解析异常", "bad") + `</td><td>无法更新记录（凭据、权限、线路断开等），或公共 DNS 返回了错误的 IP，需要处理。</td></tr>
</table></div>
</section>

<section class="card faq" id="faq"><h2>常见问题</h2>` + faqHTML.String() + `</section>

<section class="card" id="security"><h2>安全说明</h2>
<ul>
<li>对路由器只执行 <code>display</code> 查看命令，不修改任何配置；首次连接会记录 SSH 指纹，之后指纹变化会拒绝连接并提示。</li>
<li>MSR 密码、DNS 服务商凭据使用加密密钥加密保存在本机数据库，页面上不会回显。</li>
<li>Web 为 HTTP 明文访问：请只在内网使用，或在前面加 HTTPS 反向代理；在“设置”中配置来源 IP 白名单。</li>
<li>迁移或备份时，<code>config/</code> 下的加密密钥必须和数据库一起保存，否则已保存的密码和凭据无法解密。</li>
<li>服务以非 root 用户在只读容器中运行，不需要任何额外权限。</li>
</ul>
</section>

<section class="card" id="cli"><h2>服务器命令</h2><div class="cmds">` + cmdHTML.String() + `</div></section>

<div class="sysline">huboze DDNS Agent v` + Version + `</div>
</div></div>`
	c.html(c.layoutWith("帮助", "这个软件解决什么问题、怎么工作、怎么用", "", content, "help_page"))
}
