// wry-web.js - wry合金防护 v2 Web 监控面板
// v2 变更（2026-07-04）：
//   1. 强制开启密码仅存储在后端，不暴露在前端 HTML 中
//   2. 强制开启按钮：后端验证密码后立即启用 RDP + 写 force_open.json
//   3. 强制取消：后端验证密码后删除 force_open.json
//   4. 端口状态用防火墙规则状态判断（更准确）
//   5. UI 优化：按钮状态动态联动、强制开启倒计时显示

const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

const FORCE_OPEN_PASSWORD = process.env.RDP_GUARD_PASSWORD || '147369';  // ⚠️ 首次使用请修改！通过环境变量设置更安全
const FORCE_OPEN_DURATION_MS = 5 * 60 * 1000;
const FORCE_OPEN_FILE = os.homedir() + '\\Documents\\rdp_force_open.json';
const STATE_FILE         = os.homedir() + '\\Documents\\rdp_guard_state.json';
const LOG_FILE           = os.homedir() + '\\Documents\\rdp_block.log';
const ATTACK_HISTORY_FILE = os.homedir() + '\\Documents\\rdp_attack_history.json';
const HTML_FILE = __dirname + '\\wry-web.html';
const PORT = 19888;
const TZ = 'Asia/Shanghai';

function readJson(file, fallback) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch { return fallback; }
}

function atomicWrite(filePath, data) {
    const tmp = filePath + '.tmp.' + process.pid + '.' + Date.now() + '.tmp';
    try {
        fs.writeFileSync(tmp, data, 'utf8');
        fs.renameSync(tmp, filePath);
    } catch (e) {
        try { fs.unlinkSync(filePath); } catch (_) {}
        try { fs.writeFileSync(filePath, data, 'utf8'); } catch (_2) {}
    }
}

function psRaw(cmd) {
    try {
        const buf = execSync(cmd, { encoding: 'buffer', timeout: 15000, windowsHide: true, shell: 'powershell.exe' });
        if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) {
            return new TextDecoder('utf-16le').decode(buf.subarray(2));
        }
        return new TextDecoder('gb18030', { fatal: false }).decode(buf);
    } catch (_) { return ''; }
}

function formatTime(date) {
    return date.toLocaleString('zh-CN', { timeZone: TZ });
}

function getRDPOpenCount() {
    const out = psRaw(
        'Get-NetFirewallRule -Group \'@FirewallAPI.dll,-28752\' -Direction Inbound -Action Allow -Enabled True | Measure-Object | Select-Object -ExpandProperty Count'
    );
    try { return parseInt(out.trim(), 10) || 0; } catch (_) { return 0; }
}

function getRDPClosedCount() {
    const out = psRaw(
        'Get-NetFirewallRule -Group \'@FirewallAPI.dll,-28752\' -Direction Inbound -Action Allow -Enabled False | Measure-Object | Select-Object -ExpandProperty Count'
    );
    try { return parseInt(out.trim(), 10) || 0; } catch (_) { return 0; }
}

function enableRDPRules() {
    const out = psRaw(
        'Get-NetFirewallRule -Group \'@FirewallAPI.dll,-28752\' -Direction Inbound -Action Allow -Enabled False | Enable-NetFirewallRule; ' +
        'Get-NetFirewallRule -Group \'@FirewallAPI.dll,-28752\' -Direction Inbound -Action Allow -Enabled False | Measure-Object | Select-Object -ExpandProperty Count'
    );
    try {
        const lines = out.trim().split('\n');
        return parseInt(lines[lines.length - 1].trim(), 10) || 0;
    } catch (_) { return 0; }
}

function disableRDPRules() {
    const out = psRaw(
        'Get-NetFirewallRule -Group \'@FirewallAPI.dll,-28752\' -Direction Inbound -Action Allow -Enabled True | Disable-NetFirewallRule; ' +
        'Get-NetFirewallRule -Group \'@FirewallAPI.dll,-28752\' -Direction Inbound -Action Allow -Enabled True | Measure-Object | Select-Object -ExpandProperty Count'
    );
    try {
        const lines = out.trim().split('\n');
        return parseInt(lines[lines.length - 1].trim(), 10) || 0;
    } catch (_) { return 0; }
}

function getState() {
    return readJson(STATE_FILE, { blockedAt: null, lastFailCount: 0, lastTotal: 0 });
}

function getForceOpen() {
    const fo = readJson(FORCE_OPEN_FILE, null);
    if (!fo || !fo.until) return { active: false };
    const remaining = fo.until - Date.now();
    if (remaining <= 0) {
        try { fs.unlinkSync(FORCE_OPEN_FILE); } catch (_) {}
        return { active: false };
    }
    return { active: true, since: fo.since, until: fo.until, remainingMs: remaining };
}

function getRecentLogs() {
    try {
        const lines = fs.readFileSync(LOG_FILE, 'utf8').split('\n').filter(l => l.trim());
        return lines.slice(-50).reverse().map(l => {
            let type = 'info';
            if (l.includes('触发防护') || l.includes('\uD83D\uDD12')) type = 'danger';
            else if (l.includes('已恢复') || l.includes('\uD83D\uDD10') || l.includes('\uD83D\uDD13')) type = 'success';
            else if (l.includes('\u26A0') || l.includes('LAN') || l.includes('强制开启')) type = 'warning';
            return { text: l, type };
        });
    } catch (_) { return []; }
}

function getHistory() {
    const history = readJson(ATTACK_HISTORY_FILE, []);
    return history.slice(-30).reverse().map(h => ({
        time: h.time,
        total: h.total,
        topIPs: Object.entries(h.ipCounts || {}).sort((a, b) => b[1] - a[1]).slice(0, 3)
    }));
}

function getStatus() {
    const state = getState();
    const openCount = getRDPOpenCount();
    const closedCount = getRDPClosedCount();
    const total = openCount + closedCount;
    let portState = 'unknown';
    if (total > 0) portState = openCount > 0 ? 'open' : 'blocked';
    const blockedAt = state.blockedAt ? new Date(state.blockedAt) : null;
    let blockedRemaining = null;
    if (blockedAt) {
        const elapsed = (Date.now() - blockedAt.getTime()) / 60000;
        const remaining = Math.max(0, Math.ceil(5 - elapsed));
        if (remaining > 0) blockedRemaining = remaining;
    }
    // forceOpen
    const forceOpen = getForceOpen();
    let status = 'NORMAL';
    let forceOpenRemaining = null;
    let forceOpenUntil = null;
    if (forceOpen.active) {
        status = 'FORCE_OPEN';
        forceOpenRemaining = forceOpen.remainingMs;
        forceOpenUntil = formatTime(new Date(forceOpen.until));
    } else if (blockedAt && blockedRemaining) {
        status = 'BLOCKED';
    }
    return { status, portState, openCount, closedCount, total, blockedAt, blockedRemaining, forceOpenRemaining, forceOpenUntil, lastFailCount: state.lastFailCount, threshold: 10, lookback: 300 };
}

function loadHtml() {
    try { return fs.readFileSync(HTML_FILE, 'utf8'); } catch (_) { return '<h1>wry合金防护 v2</h1><p>HTML 文件未找到</p>'; }
}

const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1:' + PORT);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(loadHtml()); return;
    }

    const sendJson = (data, status) => {
        res.writeHead(status || 200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
    };

    if (req.method === 'GET' && url.pathname === '/api/status') {
        sendJson(getStatus()); return;
    }

    if (req.method === 'GET' && url.pathname === '/api/force-open') {
        const fo = getForceOpen();
        if (!fo.active) { sendJson({ active: false }); return; }
        sendJson({ active: true, since: new Date(fo.since).toLocaleString('zh-CN', { timeZone: TZ }), until: new Date(fo.until).toLocaleString('zh-CN', { timeZone: TZ }), remainingMs: fo.remainingMs }); return;
    }

    if (req.method === 'POST' && url.pathname === '/api/force-open') {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', () => {
            let json = {};
            try { json = JSON.parse(body); } catch (_) {}
            if (!json.password) { sendJson({ ok: false, error: '请提供密码' }, 400); return; }
            if (json.password !== FORCE_OPEN_PASSWORD) { sendJson({ ok: false, error: '密码错误' }, 401); return; }
            const fo = getForceOpen();
            if (fo.active) { sendJson({ ok: false, error: '强制开启已生效，无需重复开启', until: new Date(fo.until).toLocaleString('zh-CN', { timeZone: TZ }), remainingMs: fo.remainingMs }); return; }
            const restored = enableRDPRules();
            const now = Date.now();
            atomicWrite(FORCE_OPEN_FILE, JSON.stringify({ since: now, until: now + FORCE_OPEN_DURATION_MS }));
            let state = getState();
            if (state.blockedAt) { state.blockedAt = null; state.lastFailCount = 0; atomicWrite(STATE_FILE, JSON.stringify(state, null, 2)); }
            sendJson({ ok: true, since: new Date(now).toLocaleString('zh-CN', { timeZone: TZ }), until: new Date(now + FORCE_OPEN_DURATION_MS).toLocaleString('zh-CN', { timeZone: TZ }), remainingMs: FORCE_OPEN_DURATION_MS, restored });
        });
        return;
    }

    if (req.method === 'POST' && url.pathname === '/api/force-close') {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', () => {
            let json = {};
            try { json = JSON.parse(body); } catch (_) {}
            if (!json.password) { sendJson({ ok: false, error: '请提供密码' }, 400); return; }
            if (json.password !== FORCE_OPEN_PASSWORD) { sendJson({ ok: false, error: '密码错误' }, 401); return; }
            const closed = disableRDPRules();
            let state = getState();
            state.blockedAt = new Date().toISOString();
            atomicWrite(STATE_FILE, JSON.stringify(state, null, 2));
            sendJson({ ok: true, closed, message: 'RDP 端口已手动关闭，5 分钟后自动恢复' });
        });
        return;
    }

    if (req.method === 'POST' && url.pathname === '/api/force-cancel') {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', () => {
            let json = {};
            try { json = JSON.parse(body); } catch (_) {}
            if (!json.password) { sendJson({ ok: false, error: '请提供密码' }, 400); return; }
            if (json.password !== FORCE_OPEN_PASSWORD) { sendJson({ ok: false, error: '密码错误' }, 401); return; }
            const fo = getForceOpen();
            if (!fo.active) { sendJson({ ok: false, error: '强制开启未激活，无需取消' }); return; }
            // 真正关闭 RDP 端口
            const closed = disableRDPRules();
            // 设置封禁状态（让 guard 在 5 分钟后正常恢复）
            let state = getState();
            state.blockedAt = new Date().toISOString();
            atomicWrite(STATE_FILE, JSON.stringify(state, null, 2));
            try { fs.unlinkSync(FORCE_OPEN_FILE); } catch (_) {}
            sendJson({ ok: true, closed, message: 'RDP 端口已关闭，5 分钟后自动恢复' });
        });
        return;
    }

    if (req.method === 'GET' && url.pathname === '/api/logs') { sendJson(getRecentLogs()); return; }
    if (req.method === 'GET' && url.pathname === '/api/log')  { sendJson(getRecentLogs()); return; }
    if (req.method === 'GET' && url.pathname === '/api/history') { sendJson(getHistory()); return; }

    res.writeHead(404); res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, '0.0.0.0', () => {
    console.log('\uD83D\uDEE1 wry\u5408\u91D1\u9632\u62A4 Web \u76D1\u63A7\u5DF2\u542F\u52A8: http://0.0.0.0:' + PORT);
});
