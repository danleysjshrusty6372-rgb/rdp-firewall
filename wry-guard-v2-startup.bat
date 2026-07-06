@echo off
REM ============================================================
REM wry合金防护 v2 - 开机自启脚本
REM ============================================================
REM 使用方式：
REM   1. 右键本文件 → 创建快捷方式
REM   2. 快捷方式 → 属性 → 高级 → 勾选"以管理员身份运行"
REM   3. 把快捷方式放进以下任一目录即可开机自启：
REM      ① C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup  （所有用户）
REM      ② %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup      （当前用户）
REM
REM 或者直接双击运行，手动启动一次
REM ============================================================
title wry合金防护 v2
echo.
echo  ================================
echo   wry合金防护 v2 - 开机自启
echo  ================================
echo.
cd /d C:\Users\jianh\.qclaw\workspace\rdp-firewall
echo [+] 启动 guard...
start /b "" "C:\Program Files\QClaw\v0.2.32.610\resources\node\node.exe" rdp-guard.js
echo [+] 启动 web 面板...
start /b "" "C:\Program Files\QClaw\v0.2.32.610\resources\node\node.exe" wry-web.js
echo.
echo [OK] wry合金防护 v2 已启动！
echo     Web面板: http://localhost:19888
echo     强制开启密码: 147369
echo.
echo 按任意键退出...
pause >nul
