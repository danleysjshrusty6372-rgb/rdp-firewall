# wry合金防护 v3

一个简单高效的 Windows RDP 暴力破解防护系统，使用 Node.js + Windows 防火墙实现。

## 核心功能

- **无 IP 黑名单**：攻击时直接关闭 RDP 端口，5 分钟后自动恢复
- **内网全放行**：10.x.x.x / 172.16-31.x.x / 192.168.x.x（除跳板机 192.168.3.88）跳过检测
- **Web 管理面板**：实时监控 + 一键强制开启/关闭 RDP（密码保护）
- **每日邮件报告**：8:00 和 20:00 自动发送安全报告
- **开机自启**：通过 Windows 计划任务运行

## 文件说明

```
rdp-guard.js          主程序（每分钟检测 + 端口开关）
wry-web.js            Web 面板后端（19888 端口）
wry-web.html          Web 面板 UI（自动加载）
wry-web-watchdog.js   Web 守护进程（端口保活）
send-report-html.js   每日安全报告生成
register-tasks.ps1    计划任务注册脚本
rdp-guard-task.cmd    计划任务启动器
```

## 快速安装

### 1. 注册计划任务（开机自启）

以**管理员身份**运行 PowerShell：

```powershell
powershell -ExecutionPolicy Bypass -File C:\path\to\register-tasks.ps1
```

注册内容：
- `wry合金防护` — 主程序，每分钟运行
- `wry合金防护Web守护` — Web 守护，每分钟检查
- `wry合金防护日报` — 每日 8:00 + 20:00 发邮件

### 2. 手动启动 Web 面板

以**管理员身份**运行桌面上的 `wry-web-admin.bat`，或直接：

```cmd
cd C:\path\to\rdp-firewall
node wry-web.js
```

然后浏览器打开 http://localhost:19888

## Web 面板功能

| 操作 | 说明 |
|------|------|
| 强制开启 RDP | 启用防火墙规则，5 分钟后自动关闭 |
| 手动关闭端口 | 禁用防火墙规则，5 分钟后自动恢复 |
| 取消强制开启 | 立即关闭 RDP 端口 |

**强制开启密码**：后端验证，不在前端暴露（默认 `147369`，首次使用请修改）

修改密码方法：设置环境变量 `RDP_GUARD_PASSWORD`，或在 `wry-web.js` 中修改默认密码。

## 强制开启密码配置

密码存储在后端 `wry-web.js` 中，支持环境变量覆盖：

```cmd
set RDP_GUARD_PASSWORD=你的密码
node wry-web.js
```

或在计划任务中设置环境变量。

## 数据文件

默认保存在用户 Documents 目录：

| 文件 | 内容 |
|------|------|
| `rdp_guard_state.json` | 防护状态（端口开关时间） |
| `rdp_block.log` | 操作日志（最近 500 行） |
| `rdp_attack_history.json` | 攻击历史记录 |
| `rdp_force_open.json` | 强制开启状态（5 分钟超时） |
| `rdp_snapshots.json` | 每小时数据快照（保留 7 天） |

## 邮件报告配置

通过环境变量设置 SMTP 凭据（推荐）：

```cmd
set SMTP_USER=your@email.com
set SMTP_PASS=yourpassword
set REPORT_TO_EMAIL=recipient@email.com
node send-report-html.js
```

也可在计划任务中设置环境变量。默认 SMTP 服务器为 `smtp.yeah.net:465`。
推荐使用 163 邮箱（smtp.yeah.net）或 QQ 邮箱 SMTP。

## 跳板机配置

如需修改跳板机 IP（默认 192.168.3.88），在 `rdp-guard.js` 中修改：

```javascript
const BYPASS_IPS = ['192.168.3.88']; // 放行的内网 IP
```

## 安全建议

1. **修改强制开启密码**（默认 147369）
2. RDP 平时保持关闭状态，只在需要时手动开启
3. 建议配合强密码 + 双因素认证使用 RDP
4. 定期检查 `rdp_attack_history.json` 了解攻击趋势

## 技术细节

- **检测方式**：读取 Windows Security Event Log（Event ID 4625）
- **阈值**：同一 IP 60 秒内 3 次失败即触发封禁
- **封禁时长**：5 分钟（强制关闭 RDP 端口）
- **防护方式**：禁用 RDP 防火墙规则（Inbound Allow → Disabled）
- **快照**：每 5 分钟保存一次系统状态，保留 7 天

## 依赖

- Node.js 16+
- Windows 10/11
- 管理员权限（计划任务使用 SYSTEM 账户）

安装依赖：

```cmd
npm install
```
