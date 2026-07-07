@echo off
REM ============================================================
REM wry合金防护 v3 - 开机自启脚本
REM ============================================================
REM 使用方式：
REM   1. 编辑下面的 RDP_GUARD_PASSWORD 为你的密码
REM   2. 右键本文件 → 创建快捷方式
REM   3. 快捷方式 → 属性 → 高级 → 勾选"以管理员身份运行"
REM   4. 把快捷方式放进以下任一目录即可开机自启：
REM      ① C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup  （所有用户）
REM      ② %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup      （当前用户）
REM
REM 或者直接双击运行，手动启动一次
REM ============================================================
title wry合金防护 v3

REM ===== 在此处设置你的密码 =====
REM set RDP_GUARD_PASSWORD=你的密码
REM ================================

if "%RDP_GUARD_PASSWORD%"=="" (
    echo [!] 错误：未设置 RDP_GUARD_PASSWORD
    echo     请先编辑本文件，取消注释并设置密码行
    echo     或在命令行中运行: set RDP_GUARD_PASSWORD=你的密码
    echo.
    pause
    exit /b 1
)

echo.
echo  ================================
echo   wry合金防护 v3 - 开机自启
echo  ================================
echo.
cd /d %~dp0
echo [+] 启动 guard...
start /b "" node rdp-guard.js
echo [+] 启动 web 面板...
start /b "" node wry-web.js
echo.
echo [OK] wry合金防护 v3 已启动！
echo     Web面板: http://localhost:19888
echo.
echo 按任意键退出...
pause >nul
