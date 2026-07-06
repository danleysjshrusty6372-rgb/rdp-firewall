@echo off
REM wry合金防护 v2 - 计划任务启动器
REM [FIX v2] 更新 node 路径为 v0.2.32.610
set USERPROFILE=C:\Users\jianh
"C:\Program Files\QClaw\v0.2.32.610\resources\node\node.exe" "C:\Users\jianh\.qclaw\workspace\rdp-firewall\rdp-guard.js"
exit /b %ERRORLEVEL%
