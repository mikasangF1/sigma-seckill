/*
------------------------------------------
@Author: Akino
@Date: 2026.08.21
@Description: Sigma 燃烧我的卡路里 积分秒杀
逆向分析: 签名体系 Native 层不可纯静态还原，采用凭据复用策略
  mua JWT(464B RSA签名) + shield(100B) 从抓包获取静态使用
  x-mini-sig/nsig/s1 由 Native 签名栈生成，脚本不发送
------------------------------------------
new Env("Sigma-积分秒杀");
cron 0 58 17 * * * sigma_seckill.js
脚本兼容：Surge、QuantumultX、Loon、Shadowrocket，不支持青龙

[rewrite_local]
^https://api\.sigma\.run url script-request-header https://raw.githubusercontent.com/mikasangF1/sigma-seckill/master/sigma_seckill.js
[MITM]
hostname = api.sigma.run

⚠️【免责声明】
------------------------------------------
1、此脚本仅用于学习研究，不保证其合法性、准确性、有效性
2、由于此脚本仅用于学习研究，您必须在下载后 24 小时内删除
3、请勿用于任何商业或非法目的
4、本人对任何脚本引发的问题概不负责
*/
const $ = new Env("Sigma-积分秒杀");
const notify = $.isNode() ? require('./sendNotify') : '';
const ckName = "sigma_data";

// 从 HAR 抓包提取的固定认证信息
// 抓包后填入 QuantumultX 的 [persist]sigma_data
// 格式: {"sid":"xxx","cookie":"xxx","gid":"xxx","mua":"xxx","shield":"xxx","deviceId":"xxx","launch_id":"xxx"}
// mua/shield 有有效期，失效后需重新抓包
var userCookie = $.toObj($.isNode() ? process.env[ckName] : $.getdata(ckName)) || [];

$.userIdx = 0, $.userList = [], $.notifyMsg = [];
$.succCount = 0;
$.is_debug = ($.isNode() ? process.env.IS_DEDUG : $.getdata('is_debug')) || 'false';

// Sigma 商品规则：每天 18:00 放库存（stockBegin=18:00）
// productId: 2001=柠季 2002=霸王茶姬 2004=超级碗 2005=CoCo
$.rules = [
    { min: 17, max: 18, productId: 2004, name: "蜜汁鸡腿超级碗", kcalCost: 1500 },
];

const BASE_URL = "https://api.sigma.run";
const AS_BASE_URL = "https://as.sigma.run";
const UA = "Bludger/2.17 (iPhone; iOS 16.3.1; Scale/3.00) Resolution/1179*2556 Version/2.17 Build/2170168 Device/(Apple Inc.;iPhone15,2) NetType/WiFi";

//------------------------------------------
async function main() {
    const hour = new Date().getHours();
    $.ruleItem = $.rules.find(({ min, max }) => hour >= min && hour < max);
    if (!$.ruleItem) return $.error("当前时间段无活动场次");
    
    let accountList = [];
    for (let user of $.userList) {
        if (user.sid) {
            $.info(`[${user.userName}] 初始化成功`);
            accountList.push(user);
        }
    }

    $.info(`过滤后 ${accountList.length} 个账号需要抢购...`)
    if (accountList.length > 0) {
        // 等待到 17:59:59.974
        await waitTarget($.ruleItem.min, 59, 59, 974);
        // 开始并发抢购
        await proccessMain(accountList);
    }
    $.title = `共${accountList.length}个账号,抢购成功${$.succCount}个`
    await sendMsg($.notifyMsg.join("\n"), { $media: $.avatar });
}

// 并发执行
async function proccessMain(userList) {
    const concurrencyLimit = 20;
    let index = 0;

    async function processBatch() {
        const batch = userList.slice(index, index + concurrencyLimit);
        index += concurrencyLimit;
        await Promise.allSettled(batch.map(user => todo(user)));
        if (index < userList.length) {
            await processBatch();
        }
    }

    await processBatch();

    async function todo(user) {
        try {
            for (let i = 1; i <= 200; i++) {
                let res = await user.preRedeem($.ruleItem.productId);
                if ((res?.success || res?.code === 0) && res?.data && Object.keys(res.data).length > 0) {
                    $.info(`[${user.userName}] ${$.ruleItem.name} 抢购成功！`);
                    $.succCount++;
                    $.notifyMsg.push(`[${user.userName}] ${$.ruleItem.name} 抢购成功！`);
                    break;
                } else if (/已兑完|库存不足|抢光|上限|已抢|兑过/.test(res?.msg)) {
                    $.info(`[${user.userName}] ${$.ruleItem.name}: ${res?.msg}`);
                    !$.notifyMsg.length && $.notifyMsg.push(`[${user.userName}] ${$.ruleItem.name}: ${res?.msg}`);
                    break;
                } else if ((res?.success || res?.code === 0) && (!res?.data || Object.keys(res.data || {}).length === 0)) {
                    $.info(`[${user.userName}] 假成功(data空), 等待100ms重试 ${i}/200`);
                    await new Promise(r => setTimeout(r, 100));
                    continue;
                }
                await new Promise(r => setTimeout(r, 50));
            }
        } catch (e) {
            $.error(e)
        }
    }
}

// 用户
class UserInfo {
    constructor(user) {
        this.index = ++$.userIdx;
        this.sid = user.sid || "";
        this.cookie = user.cookie || "";
        this.gid = user.gid || "";
        this.mua = user.mua || "";
        this.shield = user.shield || "";
        this.deviceId = user.deviceId || "";
        this.launch_id = user.launch_id || "";
        this.userName = user.userName || "sigma_user";
        this.ckStatus = true;

        this.baseUrl = BASE_URL;
        this.baseHeaders = {
            'Host': 'api.sigma.run',
            'Content-Type': 'application/json;charset=utf-8',
            'User-Agent': UA,
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip;q=1.0,compress;q=0.5',
            'Accept-Language': 'zh-Hans-CN;q=1, zh-Hant-CN;q=0.9, en-CN;q=0.8',
            'Connection': 'Keep-Alive',
            'X-Ext-XHS-TrackerType': '7',
            'netapm': 'true',
            'xy-scene': 'point=&fs=1',
            'X-EXT-XHS-CustomRequestTimeout': '15.0',
            'rn-version': '3.28.0',
            'rn-name': 'snitch-rn',
            'Authorization': this.sid,
            'Cookie': this.cookie || '',
            'x-mini-gid': this.gid,
            'x-mini-mua': this.mua,
            'shield': this.shield,
            'xy-platform-info': `platform=iOS&version=2.17&build=2170168&deviceId=${this.deviceId}&bundle=com.lab1327.sigma`,
        };

        this.fetch = async (o) => {
            try {
                if (typeof o === 'string') o = { url: o };
                if ((!o?.url) || o?.url?.startsWith("/") || o?.url?.startsWith(":")) {
                    const base = o?.baseUrl || this.baseUrl;
                    o.url = base + (o.url || '')
                }
                const res = await Request({ ...o, headers: { ...this.baseHeaders, ...(o.headers || {}) }, url: o.url || this.baseUrl })
                debug(res, o?.url?.split('/').pop() || 'fetch');
                return res;
            } catch (e) {
                this.ckStatus = false;
                $.error(`[${this.userName}] 请求失败!${e}`);
            }
        }
    }

    // 根据不同 API 域返回对应 app_id
    // HAR 分析: api.sigma.run 用 ECFAAF02, fe-platform 用 C67E71, as.sigma.run 用 4BFEF600
    getAppIdFromUrl(url) {
        if (url.includes('as.sigma.run')) return '4BFEF600';
        if (url.includes('fe-platform')) return 'C67E71';
        return 'ECFAAF02';  // 默认 api.sigma.run
    }

    // 生成 requestId（客户端生成，格式: kcal_{时间戳13位}_{8位随机}）
    genRequestId() {
        const ts = Date.now();
        const rnd = Math.random().toString(36).substring(2, 10);
        return `kcal_${ts}_${rnd}`;
    }

    // 生成时间戳参数
    genT() {
        return Math.floor(Date.now() / 1000).toString();
    }

    // 更新 xy-common-params
    // app_id 和 project_id 根据目标 URL 自动切换
    updateCommonParams(url) {
        const t = this.genT();
        const appId = this.getAppIdFromUrl(url || '');
        const projectId = appId === '4BFEF600' ? 'C67E71' : (appId === 'C67E71' ? 'C67E71' : 'ECFAAF');
        return `SUE=1&appAlias=sigma&app_id=${appId}&auto_trans=0&build=2170168&channel=AppStore&data_ctry=CN&deviceId=${this.deviceId}&device_model=phone&dlang=zh&fid=&gid=${this.gid}&holder_ctry=CN&identifier_flag=0&is_mac=0&launch_id=${this.launch_id}&mlanguage=zh_cn&overseas_channel=0&platform=iOS&project_id=${projectId}&sid=${this.sid}&t=${t}&tz=Asia/Shanghai&uis=light&version=2.17`;
    }

    // 生成随机 TraceId
    genTraceId() {
        return Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
    }

    // 秒杀抢购
    async preRedeem(productId) {
        try {
            const requestId = this.genRequestId();
            const traceId = this.genTraceId();
            const url = "/quidd/kcal/act/pre_redeem";
            const headers = {
                'X-B3-TraceId': traceId,
                'x-xray-traceid': `d00d${traceId.substring(0, 24)}`,
                'xy-common-params': this.updateCommonParams(url),
            };
            const opts = {
                url: url,
                type: "post",
                dataType: "json",
                headers: headers,
                body: JSON.stringify({
                    activityId: 1001,
                    productId: productId,
                    requestId: requestId,
                }),
            }
            let res = await this.fetch(opts);
            $.info(`[${this.userName}] productId=${productId} res: ${res?.code} ${res?.msg}`);
            return res;
        } catch (e) {
            $.error(`[${this.userName}] preRedeem错误: ${e}`);
            return null;
        }
    }

    // 查活动首页（余额+商品+库存）
    async getHome() {
        try {
            const traceId = this.genTraceId();
            const url = "/quidd/kcal/act/home";
            const opts = {
                url: url,
                type: "post",
                dataType: "json",
                headers: {
                    'X-B3-TraceId': traceId,
                    'xy-common-params': this.updateCommonParams(url),
                },
                body: JSON.stringify({ activityId: 1001 }),
            }
            let res = await this.fetch(opts);
            if (res?.data) {
                $.info(`[${this.userName}] 余额: ${res.data?.account?.availKcal} kcal, 额度: ${res.data?.account?.remainQuota}`);
                if (res.data?.goodsList) {
                    for (const g of res.data.goodsList) {
                        $.info(`  商品: ${g.name} (${g.brand}) kcalCost=${g.kcalCost} stockStatus=${g.stockStatus} redeemStatus=${g.redeemStatus}`);
                    }
                }
            }
            return res?.data;
        } catch (e) {
            $.error(`[${this.userName}] getHome错误: ${e}`);
            return null;
        }
    }

    // 查兑换记录
    async getRedeemList() {
        try {
            const traceId = this.genTraceId();
            const url = "/quidd/kcal/act/redeem/list";
            const opts = {
                url: url,
                type: "post",
                dataType: "json",
                headers: {
                    'X-B3-TraceId': traceId,
                    'xy-common-params': this.updateCommonParams(url),
                },
                body: JSON.stringify({ activityId: 1001 }),
            }
            let res = await this.fetch(opts);
            return res?.data?.items || [];
        } catch (e) {
            $.error(`[${this.userName}] getRedeemList错误: ${e}`);
            return [];
        }
    }

    // 刷新 mua 和 shield（通过 as.sigma.run 注册机）
    // 注：as.sigma.run 的请求体包含加密的 device 数据，需要真机抓包
    // 此函数仅作为预留接口，需配合注册机使用
    async refreshMua() {
        try {
            const traceId = this.genTraceId();
            const url = "/api/v1/register/ios";
            const opts = {
                url: url,
                baseUrl: AS_BASE_URL,
                type: "post",
                dataType: "json",
                headers: {
                    'X-B3-TraceId': traceId,
                    'xy-common-params': this.updateCommonParams(url),
                },
                body: JSON.stringify({
                    // register 请求体需要加密的 device 数据
                    // 从抓包获取，或通过注册机生成
                }),
            }
            let res = await this.fetch(opts);
            if (res?.success && res?.data?.g) {
                this.gid = res.data.g;
                $.info(`[${this.userName}] 注册成功, gid更新: ${this.gid.substring(0, 16)}...`);
                return true;
            }
            return false;
        } catch (e) {
            $.error(`[${this.userName}] refreshMua错误: ${e}`);
            return false;
        }
    }
}

// 等待到指定时间
async function waitTarget(hour, minute = 0, second = 0, millisecond = 0) {
    const now = new Date();
    const targetTime = new Date(
        now.getFullYear(),
        now.getMonth(),
        now.getDate(),
        hour,
        minute,
        second,
        millisecond
    );

    if (now < targetTime) {
        const waitMilliseconds = targetTime - now;
        console.log(`等待到 ${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}:${second.toString().padStart(2, '0')}.${millisecond}, 预计等待 ${waitMilliseconds} 毫秒`);
        await new Promise(resolve => setTimeout(resolve, waitMilliseconds));
    }
}

// 主程序执行入口
!(async () => {
    try {
        if (typeof $request != "undefined") {
            await getCookie();
        } else {
            await checkEnv();
            await main();
        }
    } catch (e) {
        throw e;
    }
})()
    .catch((e) => { $.logErr(e), $.msg($.name, `⛔️ script run error!`, e.message || e) })
    .finally(async () => {
        $.done({});
    });

/** ---------------------------------固定不动区域----------------------------------------- */
// 获取Cookie（通过 QX 抓包自动填充）
async function getCookie() {
    try {
        if ($request && $request.method === 'OPTIONS') return;
        const Headers = ObjectKeys2LowerCase($request.headers);
        const url = $request.url;
        
        // 只处理 sigma.run 的请求
        if (!url.includes('sigma.run')) return;
        
        // 提取认证信息
        const sid = Headers["authorization"] || "";
        const cookie = Headers["cookie"] || "";
        const gid = Headers["x-mini-gid"] || "";
        const mua = Headers["x-mini-mua"] || "";
        const shield = Headers["shield"] || "";
        
        // 从 xy-common-params 提取 deviceId 和 launch_id
        const commonParams = Headers["xy-common-params"] || "";
        const deviceIdM = commonParams.match(/deviceId=([^&]+)/);
        const launchIdM = commonParams.match(/launch_id=([^&]+)/);
        const deviceId = deviceIdM ? deviceIdM[1] : "";
        const launch_id = launchIdM ? launchIdM[1] : "";
        
        if (!sid) return;
        
        const newData = {
            sid: sid,
            cookie: cookie,
            gid: gid,
            mua: mua,
            shield: shield,
            deviceId: deviceId,
            launch_id: launch_id,
            userName: "sigma_user",
        };
        
        // 保存
        const existing = $.getjson(ckName, []);
        const index = existing.findIndex(e => e.sid == newData.sid);
        if (index >= 0) {
            existing[index] = newData;
        } else {
            existing.push(newData);
        }
        $.setjson(existing, ckName);
        $.msg($.name, `🎉账号更新token成功!`, `sid=${sid.substring(0,8)}...`);
    } catch (e) {
        throw e;
    }
}

async function sendMsg(a, e) { a && ($.isNode() ? await notify.sendNotify($.name, a) : $.msg($.name, $.title || "", a, e)) }
async function checkEnv() {
    try {
        if (!userCookie?.length) throw new Error("未找到账号配置，请在 Sigma app 中打开活动页面触发抓包自动填充");
        $.log(`\n[INFO] 检测到 ${userCookie?.length ?? 0} 个账号\n`);
        $.userList.push(...userCookie.map(o => new UserInfo(o)).filter(Boolean));
    } catch (o) { throw o }
}
function debug(g, e = "debug") { "true" === $.is_debug && ($.log(`\n-----------${e}------------\n`), $.log("string" == typeof g ? g : $.toStr(g) || `debug error => t=${g}`), $.log(`\n-----------${e}------------\n`)) }
function ObjectKeys2LowerCase(obj) { return !obj ? {} : Object.fromEntries(Object.entries(obj).map(([k, v]) => [k.toLowerCase(), v])) };
//From sliverkiss's Request
async function Request(t) { "string" == typeof t && (t = { url: t }); try { if (!t?.url) throw new Error("[URL][ERROR] 缺少 url 参数"); let { url: o, type: e, headers: r = {}, body: s, params: a, dataType: n = "form", resultType: u = "data" } = t; const p = e ? e?.toLowerCase() : "body" in t ? "post" : "get", c = o.concat("post" === p ? "?" + $.queryStr(a) : ""), i = t.timeout ? $.isSurge() ? t.timeout / 1e3 : t.timeout : 1e4; "json" === n && (r["Content-Type"] = "application/json;charset=UTF-8"); const y = "string" == typeof s ? s : (s && "form" == n ? $.queryStr(s) : $.toStr(s)), l = { ...t, ...t?.opts ? t.opts : {}, url: c, headers: r, ..."post" === p && { body: y }, ..."get" === p && a && { params: a }, timeout: i }, m = $.http[p.toLowerCase()](l).then((t => "data" == u ? $.toObj(t.body) || t.body : $.toObj(t) || t)).catch((t => $.log(`[${p.toUpperCase()}][ERROR] ${t}\n`))); return Promise.race([new Promise(((t, o) => setTimeout((() => o("当前请求已超时")), i))), m]) } catch (t) { console.log(`[${p.toUpperCase()}][ERROR] ${t}\n`) } }
//From chavyleung's Env.js
function Env(t, e) { class s { constructor(t) { this.env = t } send(t, e = "GET") { t = "string" == typeof t ? { url: t } : t; let s = this.get; return "POST" === e && (s = this.post), new Promise(((e, i) => { s.call(this, t, ((t, s, o) => { t ? i(t) : e(s) })) })) } get(t) { return this.send.call(this.env, t) } post(t) { return this.send.call(this.env, t, "POST") } } return new class { constructor(t, e) { this.logLevels = { debug: 0, info: 1, warn: 2, error: 3 }, this.logLevelPrefixs = { debug: "[DEBUG] ", info: "[INFO] ", warn: "[WARN] ", error: "[ERROR] " }, this.logLevel = "info", this.name = t, this.http = new s(this), this.data = null, this.dataFile = "box.dat", this.logs = [], this.isMute = !1, this.isNeedRewrite = !1, this.logSeparator = "\n", this.encoding = "utf-8", this.startTime = (new Date).getTime(), Object.assign(this, e), this.log("", `🔔${this.name}, 开始!`) } getEnv() { return "undefined" != typeof $environment && $environment["surge-version"] ? "Surge" : "undefined" != typeof $environment && $environment["stash-version"] ? "Stash" : "undefined" != typeof module && module.exports ? "Node.js" : "undefined" != typeof $task ? "Quantumult X" : "undefined" != typeof $loon ? "Loon" : "undefined" != typeof $rocket ? "Shadowrocket" : void 0 } isNode() { return "Node.js" === this.getEnv() } isQuanX() { return "Quantumult X" === this.getEnv() } isSurge() { return "Surge" === this.getEnv() } isLoon() { return "Loon" === this.getEnv() } isShadowrocket() { return "Shadowrocket" === this.getEnv() } isStash() { return "Stash" === this.getEnv() } toObj(t, e = null) { try { return JSON.parse(t) } catch { return e } } toStr(t, e = null, ...s) { try { return JSON.stringify(t, ...s) } catch { return e } } getjson(t, e) { let s = e; if (this.getdata(t)) try { s = JSON.parse(this.getdata(t)) } catch { } return s } setjson(t, e) { try { return this.setdata(JSON.stringify(t), e) } catch { return !1 } } getScript(t) { return new Promise((e => { this.get({ url: t }, ((t, s, i) => e(i))) })) } runScript(t, e) { return new Promise((s => { let i = this.getdata("@chavy_boxjs_userCfgs.httpapi"); i = i ? i.replace(/\n/g, "").trim() : i; let o = this.getdata("@chavy_boxjs_userCfgs.httpapi_timeout"); o = o ? 1 * o : 20, o = e && e.timeout ? e.timeout : o; const [r, a] = i.split("@"), n = { url: `http://${a}/v1/scripting/evaluate`, body: { script_text: t, mock_type: "cron", timeout: o }, headers: { "X-Key": r, Accept: "*/" }, timeout: o }; this.post(n, ((t, e, i) => s(i))) })).catch((t => this.logErr(t))) } loaddata() { if (!this.isNode()) return {}; { this.fs = this.fs ? this.fs : require("fs"), this.path = this.path ? this.path : require("path"); const t = this.path.resolve(this.dataFile), e = this.path.resolve(process.cwd(), this.dataFile), s = this.fs.existsSync(t), i = !s && this.fs.existsSync(e); if (!s && !i) return {}; { const i = s ? t : e; try { return JSON.parse(this.fs.readFileSync(i)) } catch (t) { return {} } } } } writedata() { if (this.isNode()) { this.fs = this.fs ? this.fs : require("fs"), this.path = this.path ? this.path : require("path"); const t = this.path.resolve(this.dataFile), e = this.path.resolve(process.cwd(), this.dataFile), s = this.fs.existsSync(t), i = !s && this.fs.existsSync(e), o = JSON.stringify(this.data); s ? this.fs.writeFileSync(t, o) : i ? this.fs.writeFileSync(e, o) : this.fs.writeFileSync(t, o) } } lodash_get(t, e, s) { const i = e.replace(/\[(\d+)\]/g, ".$1").split("."); let o = t; for (const t of i) if (o = Object(o)[t], void 0 === o) return s; return o } lodash_set(t, e, s) { return Object(t) !== t || (Array.isArray(e) || (e = e.toString().match(/[^.[\]]+/g) || []), e.slice(0, -1).reduce(((t, s, i) => Object(t[s]) === t[s] ? t[s] : t[s] = Math.abs(e[i + 1]) >> 0 == +e[i + 1] ? [] : {}), t)[e[e.length - 1]] = s), t } getdata(t) { let e = this.getval(t); if (/^@/.test(t)) { const [, s, i] = /^@(.*?)\.(.*?)$/.exec(t), o = s ? this.getval(s) : ""; if (o) try { const t = JSON.parse(o); e = t ? this.lodash_get(t, i, "") : e } catch (t) { e = "" } } return e } setdata(t, e) { let s = !1; if (/^@/.test(e)) { const [, i, o] = /^@(.*?)\.(.*?)$/.exec(e), r = this.getval(i), a = i ? "null" === r ? null : r || "{}" : "{}"; try { const e = JSON.parse(a); this.lodash_set(e, o, t), s = this.setval(JSON.stringify(e), i) } catch (e) { const r = {}; this.lodash_set(r, o, t), s = this.setval(JSON.stringify(r), i) } } else s = this.setval(t, e); return s } getval(t) { switch (this.getEnv()) { case "Surge": case "Loon": case "Stash": case "Shadowrocket": return $persistentStore.read(t); case "Quantumult X": return $prefs.valueForKey(t); case "Node.js": return this.data = this.loaddata(), this.data[t]; default: return this.data && this.data[t] || null } } setval(t, e) { switch (this.getEnv()) { case "Surge": case "Loon": case "Stash": case "Shadowrocket": return $persistentStore.write(t, e); case "Quantumult X": return $prefs.setValueForKey(t, e); case "Node.js": return this.data = this.loaddata(), this.data[e] = t, this.writedata(), !0; default: return this.data && this.data[e] || null } } initGotEnv(t) { this.got = this.got ? this.got : require("got"), this.cktough = this.cktough ? this.cktough : require("tough-cookie"), this.ckjar = this.ckjar ? this.ckjar : new this.cktough.CookieJar, t && (t.headers = t.headers ? t.headers : {}, t && (t.headers = t.headers ? t.headers : {}, void 0 === t.headers.cookie && void 0 === t.headers.Cookie && void 0 === t.cookieJar && (t.cookieJar = this.ckjar))) } get(t, e = (() => { })) { switch (t.headers && (delete t.headers["Content-Type"], delete t.headers["Content-Length"], delete t.headers["content-type"], delete t.headers["content-length"]), t.params && (t.url += "?" + this.queryStr(t.params)), void 0 === t.followRedirect || t.followRedirect || ((this.isSurge() || this.isLoon()) && (t["auto-redirect"] = !1), this.isQuanX() && (t.opts ? t.opts.redirection = !1 : t.opts = { redirection: !1 })), this.getEnv()) { case "Surge": case "Loon": case "Stash": case "Shadowrocket": default: this.isSurge() && this.isNeedRewrite && (t.headers = t.headers || {}, Object.assign(t.headers, { "X-Surge-Skip-Scripting": !1 })), $httpClient.get(t, ((t, s, i) => { !t && s && (s.body = i, s.statusCode = s.status ? s.status : s.statusCode, s.status = s.statusCode), e(t, s, i) })); break; case "Quantumult X": this.isNeedRewrite && (t.opts = t.opts || {}, Object.assign(t.opts, { hints: !1 })), $task.fetch(t).then((t => { const { statusCode: s, statusCode: i, headers: o, body: r, bodyBytes: a } = t; e(null, { status: s, statusCode: i, headers: o, body: r, bodyBytes: a }, r, a) }), (t => e(t && t.error || "UndefinedError"))); break; case "Node.js": let s = require("iconv-lite"); this.initGotEnv(t), this.got(t).on("redirect", ((t, e) => { try { if (t.headers["set-cookie"]) { const s = t.headers["set-cookie"].map(this.cktough.Cookie.parse).toString(); s && this.ckjar.setCookieSync(s, null), e.cookieJar = this.ckjar } } catch (t) { this.logErr(t) } })).then((t => { const { statusCode: i, statusCode: o, headers: r, rawBody: a } = t, n = s.decode(a, this.encoding); e(null, { status: i, statusCode: o, headers: r, rawBody: a, body: n }, n) }), (t => { const { message: i, response: o } = t; e(i, o, o && i.decode(o.rawBody, this.encoding)) })); break } } post(t, e = (() => { })) { const s = t.method ? t.method.toLocaleLowerCase() : "post"; switch (t.body && t.headers && !t.headers["Content-Type"] && !t.headers["content-type"] && (t.headers["content-type"] = "application/x-www-form-urlencoded"), t.headers && (delete t.headers["Content-Length"], delete t.headers["content-length"]), void 0 === t.followRedirect || t.followRedirect || ((this.isSurge() || this.isLoon()) && (t["auto-redirect"] = !1), this.isQuanX() && (t.opts ? t.opts.redirection = !1 : t.opts = { redirection: !1 })), this.getEnv()) { case "Surge": case "Loon": case "Stash": case "Shadowrocket": default: this.isSurge() && this.isNeedRewrite && (t.headers = t.headers || {}, Object.assign(t.headers, { "X-Surge-Skip-Scripting": !1 })), $httpClient[s](t, ((t, s, i) => { !t && s && (s.body = i, s.statusCode = s.status ? s.status : s.statusCode, s.status = s.statusCode), e(t, s, i) })); break; case "Quantumult X": t.method = s, this.isNeedRewrite && (t.opts = t.opts || {}, Object.assign(t.opts, { hints: !1 })), $task.fetch(t).then((t => { const { statusCode: s, statusCode: i, headers: o, body: r, bodyBytes: a } = t; e(null, { status: s, statusCode: i, headers: o, body: r, bodyBytes: a }, r, a) }), (t => e(t && t.error || "UndefinedError"))); break; case "Node.js": let i = require("iconv-lite"); this.initGotEnv(t); const { url: o, ...r } = t; this.got[s](o, r).then((t => { const { statusCode: s, statusCode: o, headers: r, rawBody: a } = t, n = i.decode(a, this.encoding); e(null, { status: s, statusCode: o, headers: r, rawBody: a, body: n }, n) }), (t => { const { message: s, response: o } = t; e(s, o, o && i.decode(o.rawBody, this.encoding)) })); break } } time(t, e = null) { const s = e ? new Date(e) : new Date; let i = { "M+": s.getMonth() + 1, "d+": s.getDate(), "H+": s.getHours(), "m+": s.getMinutes(), "s+": s.getSeconds(), "q+": Math.floor((s.getMonth() + 3) / 3), S: s.getMilliseconds() }; /(y+)/.test(t) && (t = t.replace(RegExp.$1, (s.getFullYear() + "").substr(4 - RegExp.$1.length))); for (const e in i) new RegExp("(" + e + ")").test(t) && (t = t.replace(RegExp.$1, 1 == RegExp.$1.length ? i[e] : ("00" + i[e]).substr(("" + i[e]).length))); return t } queryStr(t) { let e = ""; for (const s in t) { let i = t[s]; null != i && "" !== i && ("object" == typeof i && (i = JSON.stringify(i)), e += `${s}=${i}&`) } return e = e.substring(0, e.length - 1), e } msg(e = t, s = "", i = "", o = {}) { const r = t => { const { $open: e, $copy: s, $media: i, $mediaMime: o } = t; switch (typeof t) { case void 0: return t; case "string": switch (this.getEnv()) { case "Surge": case "Stash": default: return { url: t }; case "Loon": case "Shadowrocket": return t; case "Quantumult X": return { "open-url": t }; case "Node.js": return }case "object": switch (this.getEnv()) { case "Surge": case "Stash": case "Shadowrocket": default: { const r = {}; let a = t.openUrl || t.url || t["open-url"] || e; a && Object.assign(r, { action: "open-url", url: a }); let n = t["update-pasteboard"] || t.updatePasteboard || s; if (n && Object.assign(r, { action: "clipboard", text: n }), i) { let t, e, s; if (i.startsWith("http")) t = i; else if (i.startsWith("data:")) { const [t] = i.split(";"), [, o] = i.split(","); e = o, s = t.replace("data:", "") } else { e = i, s = (t => { const e = { JVBERi0: "application/pdf", R0lGODdh: "image/gif", R0lGODlh: "image/gif", iVBORw0KGgo: "image/png", "/9j/": "image/jpg" }; for (var s in e) if (0 === t.indexOf(s)) return e[s]; return null })(i) } Object.assign(r, { "media-url": t, "media-base64": e, "media-base64-mime": o ?? s }) } return Object.assign(r, { "auto-dismiss": t["auto-dismiss"], sound: t.sound }), r } case "Loon": { const s = {}; let o = t.openUrl || t.url || t["open-url"] || e; o && Object.assign(s, { openUrl: o }); let r = t.mediaUrl || t["media-url"]; return i?.startsWith("http") && (r = i), r && Object.assign(s, { mediaUrl: r }), console.log(JSON.stringify(s)), s } case "Quantumult X": { const o = {}; let r = t["open-url"] || t.url || t.openUrl || e; r && Object.assign(o, { "open-url": r }); let a = t["media-url"] || t.mediaUrl; i?.startsWith("http") && (a = i), a && Object.assign(o, { "media-url": a }); let n = t["update-pasteboard"] || t.updatePasteboard || s; return n && Object.assign(o, { "update-pasteboard": n }), console.log(JSON.stringify(o)), o } case "Node.js": return }default: return } }; if (!this.isMute) switch (this.getEnv()) { case "Surge": case "Loon": case "Stash": case "Shadowrocket": default: $notification.post(e, s, i, r(o)); break; case "Quantumult X": $notify(e, s, i, r(o)); break; case "Node.js": break }if (!this.isMuteLog) { let t = ["", "==============📣系统通知📣=============="]; t.push(e), s && t.push(s), i && t.push(i), console.log(t.join("\n")), this.logs = this.logs.concat(t) } } debug(...t) { this.logLevels[this.logLevel] <= this.logLevels.debug && (t.length > 0 && (this.logs = [...this.logs, ...t]), console.log(`${this.logLevelPrefixs.debug}${t.map((t => t ?? String(t))).join(this.logSeparator)}`)) } info(...t) { this.logLevels[this.logLevel] <= this.logLevels.info && (t.length > 0 && (this.logs = [...this.logs, ...t]), console.log(`${this.logLevelPrefixs.info}${t.map((t => t ?? String(t))).join(this.logSeparator)}`)) } warn(...t) { this.logLevels[this.logLevel] <= this.logLevels.warn && (t.length > 0 && (this.logs = [...this.logs, ...t]), console.log(`${this.logLevelPrefixs.warn}${t.map((t => t ?? String(t))).join(this.logSeparator)}`)) } error(...t) { this.logLevels[this.logLevel] <= this.logLevels.error && (t.length > 0 && (this.logs = [...this.logs, ...t]), console.log(`${this.logLevelPrefixs.error}${t.map((t => t ?? String(t))).join(this.logSeparator)}`)) } log(...t) { t.length > 0 && (this.logs = [...this.logs, ...t]), console.log(t.map((t => t ?? String(t))).join(this.logSeparator)) } logErr(t, e) { switch (this.getEnv()) { case "Surge": case "Loon": case "Stash": case "Shadowrocket": case "Quantumult X": default: this.log("", `❗️${this.name}, 错误!`, e, t); break; case "Node.js": this.log("", `❗️${this.name}, 错误!`, e, void 0 !== t.message ? t.message : t, t.stack); break } } wait(t) { return new Promise((e => setTimeout(e, t))) } done(t = {}) { const e = ((new Date).getTime() - this.startTime) / 1e3; switch (this.log("", `🔔${this.name}, 结束! 🕛 ${e} 秒`), this.log(), this.getEnv()) { case "Surge": case "Loon": case "Stash": case "Shadowrocket": case "Quantumult X": default: $done(t); break; case "Node.js": process.exit(1) } } }(t, e) }