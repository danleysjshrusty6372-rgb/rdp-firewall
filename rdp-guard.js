// rdp-guard.js - wry合金防护 v2
// 
// 新逻辑（v2）：
//   - 无 IP 黑名单，攻击时直接关闭 RDP 端口（禁用防火墙规则）
//   - 5 分钟后自动恢复（启用防火墙规则）
//   - 内网 IP（除 192.168.3.88）跳过检测，直接放行
//   - forceOpen：用户手动强制开启 RDP，有效期 5 分钟
//
// 数据文件：
//   - Documents/rdp_guard_state.json    防护状态（blockedAt / forceOpenUntil）
//   - Documents/rdp_block.log           操作日志
//   - Documents/rdp_force_open.json    强制开启状态
//   - Documents/rdp_attack_history.json 攻击历史
//   - Documents/rdp_snapshots.json     定时快照（验证脚本是否运行）
//   - Documents/rdp_guard.lock         进程锁（防止并发）
//
// 状态机：
//   blockedAt=null && forceOpenUntil=null → NORMAL（监控中）
//   blockedAt!=null                       → BLOCKED（端口关闭，倒计时恢复）
//   forceOpenUntil!=null                  → FORCE_OPEN（端口开启，倒计时关闭）

const { execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

// ============================================================================
// 常量配置
// ============================================================================
const THRESHOLD            = 3;       // 触发关闭端口的同 IP 失败次数阈值
const LOOKBACK_SECONDS     = 60;     // 回溯时间窗口（秒）
const REOPEN_MINUTES       = 5;      // 端口关闭后自动恢复时间（分钟）
const FORCE_OPEN_DURATION   = 5 * 60 * 1000;  // forceOpen 有效期（毫秒）
const LOG_MAX_LINES        = 500;    // 日志最大保留行数
const SNAPSHOT_INTERVAL_MS = 5 * 60 * 1000;  // 快照间隔（5分钟）

// 内网 IP 范围（192.168.3.88 参与检测，其他内网 IP 全部放行）
const PRIVATE_RANGES = [
    { start: '10.0.0.0',      end: '10.255.255.255' },
    { start: '172.16.0.0',    end: '172.31.255.255' },
    { start: '192.168.0.0',   end: '192.168.255.255' },
];
const DETECT_IP = '192.168.3.88';   // 跳板机 IP，参与检测和封禁

// 文件路径
const LOG_FILE           = path.join(os.homedir(), 'Documents', 'rdp_block.log');
const STATE_FILE         = path.join(os.homedir(), 'Documents', 'rdp_guard_state.json');
const LOCK_FILE          = path.join(os.homedir(), 'Documents', 'rdp_guard.lock');
const FORCE_OPEN_FILE    = path.join(os.homedir(), 'Documents', 'rdp_force_open.json');
const ATTACK_HISTORY_FILE = path.join(os.homedir(), 'Documents', 'rdp_attack_history.json');
const SNAPSHOT_FILE      = path.join(os.homedir(), 'Documents', 'rdp_snapshots.json');
const BACKFILL_DONE_FILE  = path.join(os.homedir(), 'Documents', 'rdp_guard_backfill.lock');

// ============================================================================
// 工具函数
// ============================================================================

// 原子写入：先写 .tmp 再 rename，NTFS rename 是原子操作，规避并发写文件损坏
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

// 安全 JSON 读取
function safeReadJson(file, fallback) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch { return fallback; }
}

// 追加日志 + 自动轮转
function writeLog(msg) {
    const ts = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    const line = `${ts} ${msg}\n`;
    try {
        fs.appendFileSync(LOG_FILE, line, 'utf8');
        const lines = fs.readFileSync(LOG_FILE, 'utf8').split('\n');
        if (lines.length > LOG_MAX_LINES + 10) {
            const kept = lines.slice(-LOG_MAX_LINES);
            atomicWrite(LOG_FILE, kept.join('\n') + '\n');
        }
    } catch (_) {}
}

// 判断 IP 是否为内网放行范围（192.168.3.88 不在此列，需参与检测）
function isPrivateIP(ip) {
    if (!ip) return false;
    if (ip === DETECT_IP) return false;  // 跳板机参与检测，不放行
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(isNaN)) return false;
    const n = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];

    for (const r of PRIVATE_RANGES) {
        const s = r.start.split('.').reduce((acc, p, i) => acc | (parseInt(p) << (24 - i * 8)), 0);
        const e = r.end.split('.').reduce((acc, p, i) => acc | (parseInt(p) << (24 - i * 8)), 0);
        if (n >= s && n <= e) return true;
    }
    return false;
}

// ============================================================================
// 持久化
// ============================================================================

function persistAttack(total, ipCounts) {
    try {
        let history = safeReadJson(ATTACK_HISTORY_FILE, []);
        const cutoff = Date.now() - 30 * 24 * 3600 * 1000;
        history = history.filter(h => h.ts > cutoff);
        const ts = Date.now();
        const exists = history.some(h => Math.abs(h.ts - ts) < 5000);
        if (!exists) {
            history.push({
                ts,
                time: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }),
                total,
                ipCounts,
            });
            atomicWrite(ATTACK_HISTORY_FILE, JSON.stringify(history, null, 2));
        }
    } catch (e) {
        writeLog(`[ERROR] persistAttack 失败: ${e.message}`);
    }
}

function persistSnapshot(total, ipCounts) {
    try {
        let snapshots = safeReadJson(SNAPSHOT_FILE, []);
        const cutoff = Date.now() - 7 * 24 * 3600 * 1000;
        snapshots = snapshots.filter(s => s.ts > cutoff);
        const last = snapshots[snapshots.length - 1];
        if (last && (Date.now() - last.ts) < SNAPSHOT_INTERVAL_MS) return;
        snapshots.push({ ts: Date.now(), total, ipCounts: ipCounts || {} });
        atomicWrite(SNAPSHOT_FILE, JSON.stringify(snapshots));
    } catch (e) {
        writeLog(`[ERROR] persistSnapshot 失败: ${e.message}`);
    }
}

function loadState() {
    return safeReadJson(STATE_FILE, { blockedAt: null });
}

function saveState(s) {
    atomicWrite(STATE_FILE, JSON.stringify(s, null, 2));
}

// ============================================================================
// PowerShell 执行（自动检测编码）
// ============================================================================

function ps(command) {
    try {
        const buf = execSync(command, {
            encoding: 'buffer', timeout: 20000, windowsHide: true, shell: 'powershell.exe'
        });
        // 尝试 UTF-16-LE（PowerShell 默认）
        if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) {
            return new TextDecoder('utf-16le').decode(buf.subarray(2));
        }
        // 尝试 UTF-8
        const asUtf8 = new TextDecoder('utf-8', { fatal: false }).decode(buf);
        if (asUtf8.includes('远程') || asUtf8.includes('桌面') || asUtf8.includes('触发') || asUtf8.includes('恢复') || asUtf8.includes('True') || asUtf8.includes('False')) {
            return asUtf8;
        }
        // 回退 GB18030
        return new TextDecoder('gb18030', { fatal: false }).decode(buf);
    } catch (e) {
        writeLog(`[WARN] ps 命令执行失败: ${command.substring(0, 80)} — ${e.message}`);
        return '';
    }
}

// ============================================================================
// 防火墙操作
// ============================================================================

// 获取所有 RDP 入站允许规则
function getRDPRules(enabled) {
    const flag = enabled ? 'True' : 'False';
    const out = ps(`Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Direction Inbound -Action Allow -Enabled ${flag} | Select-Object Name,DisplayName | ConvertTo-Json -Compress`);
    let rules = [];
    try { rules = JSON.parse(out); } catch (_) {}
    return Array.isArray(rules) ? rules : (rules.Name ? [rules] : []);
}

// 禁用所有 RDP 入站允许规则（关闭端口）
function disableRDPRules() {
    const rules = getRDPRules(true);
    let count = 0;
    for (const r of rules) {
        ps(`Disable-NetFirewallRule -Name '${r.Name}'`);
        writeLog(`已禁用 RDP 规则: ${r.DisplayName || r.Name}`);
        count++;
    }
    return count;
}

// 启用所有 RDP 入站允许规则（开启端口）
function enableRDPRules() {
    const rules = getRDPRules(false);
    let count = 0;
    for (const r of rules) {
        ps(`Enable-NetFirewallRule -Name '${r.Name}'`);
        writeLog(`已恢复 RDP 规则: ${r.DisplayName || r.Name}`);
        count++;
    }
    return count;
}

// 判断 RDP 端口当前是否开启（检查是否有 Allow 规则处于启用状态）
function isRDPOpen() {
    const rules = getRDPRules(true);
    return rules.length > 0;
}

// ============================================================================
// 日志分析
// ============================================================================

// 获取最近 N 秒的 4625 事件，过滤掉内网 IP（192.168.3.88 参与检测）
function getRecentFailures(seconds) {
    const since = new Date(Date.now() - seconds * 1000).toISOString();
    try {
        const buf = execSync(
            `wevtutil qe Security /f:text /q:"*[System[EventID=4625]]" /c:500 /rd:true`,
            { encoding: 'buffer', maxBuffer: 100 * 1024 * 1024, windowsHide: true }
        );
        const text = new TextDecoder('gb18030', { fatal: false }).decode(buf);
        const blocks = text.split(/^Event\[\d+\]\s*$/m).filter(b => b.trim());

        const ipCounts = {};
        let total = 0;

        for (const b of blocks) {
            const dm = b.match(/Date:\s*(\S+)/);
            if (!dm) continue;
            const eventTime = new Date(dm[1]);
            if (eventTime < new Date(Date.now() - seconds * 1000)) continue;

            const m = b.match(/源网络地址:\s*([\d\.:a-fA-F]+)/) || b.match(/Source Network Address:\s*([\d\.:a-fA-F]+)/);
            if (!m || !m[1] || m[1] === '-' || m[1] === '127.0.0.1' || m[1] === '::1') continue;

            const ip = m[1];
            // 跳过放行内网 IP（192.168.3.88 不跳过，参与检测）
            if (isPrivateIP(ip)) continue;

            total++;
            ipCounts[ip] = (ipCounts[ip] || 0) + 1;
        }
        return { total, ipCounts };
    } catch (e) {
        return { total: 0, ipCounts: {} };
    }
}

// ============================================================================
// 主流程
// ============================================================================

async function main() {
    const MY_PID = String(process.pid);

    // ---- 进程锁（防止多实例并发）----
    try {
        let lockContent = '';
        try { lockContent = fs.readFileSync(LOCK_FILE, 'utf8').trim(); } catch (_) {}
        if (lockContent) {
            const [lockPid, lockTs] = lockContent.split(':');
            if (lockPid === MY_PID) {
                const lockAge = Date.now() - parseInt(lockTs || '0', 10);
                if (lockAge < 120000) {
                    process.exit(0);  // 120秒内重复调用直接退出
                }
                writeLog(`[WARN] 检测到过期锁 PID=${lockPid}，强制清理`);
            } else {
                const lockAge = Date.now() - parseInt(lockTs || '0', 10);
                if (lockAge < 120000) {
                    process.exit(0);  // 其他进程持有锁
                }
            }
        }
    } catch (_) {}
    try { fs.writeFileSync(LOCK_FILE, MY_PID + ':' + Date.now(), 'utf8'); } catch (_) {}

    try {
        // ---- forceOpen 检查（优先级最高）----
        // forceOpen 时：不阻止任何检测行为，但确保 RDP 规则是开启的
        let forceOpenUntil = null;
        try {
            const fo = safeReadJson(FORCE_OPEN_FILE, null);
            if (fo && fo.until) {
                const remaining = fo.until - Date.now();
                if (remaining > 0) {
                    forceOpenUntil = fo.until;
                    const min = Math.ceil(remaining / 60000);
                    writeLog(`⏸️ forceOpen 生效中（剩余 ${min} 分钟），确保 RDP 端口开启`);
                    // 确保 RDP 规则已启用
                    const open = isRDPOpen();
                    if (!open) {
                        const count = enableRDPRules();
                        writeLog(`⚡ forceOpen 强制启用 RDP（恢复 ${count} 条规则）`);
                    }
                    // 如果当前是封禁状态 → 立即解除
                    const state = loadState();
                    if (state.blockedAt) {
                        const count = enableRDPRules();
                        state.blockedAt = null;
                        saveState(state);
                        writeLog(`⚡ forceOpen 立即解除封禁，恢复 RDP（恢复 ${count} 条规则）`);
                    }
                    persistSnapshot(0, {});
                    unlock(); process.exit(0);
                } else {
                    try { fs.unlinkSync(FORCE_OPEN_FILE); } catch (_) {}
                    writeLog('forceOpen 已到期');
                }
            }
        } catch (_) {}

        // ---- 状态检查：当前是封禁状态吗？----
        let state = loadState();

        if (state.blockedAt) {
            const blockedTime = new Date(state.blockedAt);
            const elapsedMin = (Date.now() - blockedTime.getTime()) / 60000;
            if (elapsedMin >= REOPEN_MINUTES) {
                // 封禁到期，自动恢复
                const count = enableRDPRules();
                state.blockedAt = null;
                saveState(state);
                writeLog(`RDP 端口已自动恢复（关闭 ${REOPEN_MINUTES} 分钟后）`);
            } else {
                const remaining = Math.ceil(REOPEN_MINUTES - elapsedMin);
                writeLog(`RDP 端口封禁中（剩余 ${remaining} 分钟），跳过检测`);
            }
            persistSnapshot(0, {});
            unlock(); process.exit(0);
        }

        // ---- 正常状态：检测攻击 ----
        const { total, ipCounts } = getRecentFailures(LOOKBACK_SECONDS);
        persistSnapshot(total, ipCounts);

        // 无攻击
        if (total === 0) {
            unlock(); process.exit(0);
        }

        // 有攻击，但 RDP 端口已是开启状态才触发封禁
        const rdpOpen = isRDPOpen();
        if (!rdpOpen) {
            writeLog(`RDP 端口已关闭，跳过检测（可能是手动关闭或 forceOpen）`);
            unlock(); process.exit(0);
        }

        // 找超过阈值的 IP
        const triggeredIPs = Object.entries(ipCounts)
            .filter(([, c]) => c >= THRESHOLD)
            .map(([ip]) => ip);

        if (triggeredIPs.length === 0) {
            unlock(); process.exit(0);
        }

        // ---- 触发封禁：关闭 RDP 端口 ----
        writeLog(`⚠️ 检测到暴力破解！最近${LOOKBACK_SECONDS}秒内 ${total} 次失败，` +
            `攻击 IP: ${triggeredIPs.join(', ')}，关闭 RDP 端口`);

        persistAttack(total, ipCounts);

        // 禁用所有 RDP 入站规则
        const disabledCount = disableRDPRules();

        // 更新状态
        state.blockedAt = new Date().toISOString();
        saveState(state);

        writeLog(`RDP 端口已关闭（禁用 ${disabledCount} 条规则），` +
            `${REOPEN_MINUTES} 分钟后自动恢复`);

    } catch (e) {
        writeLog(`[ERROR] guard 异常: ${e.message}`);
    }

    unlock();
}

function unlock() {
    try { fs.unlinkSync(LOCK_FILE); } catch (_) {}
}

main().catch(e => {
    writeLog(`[ERROR] main 未捕获异常: ${e.message}`);
    unlock();
    process.exit(1);
});
