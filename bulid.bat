@echo off
REM 一键打包为单文件 exe（无控制台）
REM 先执行：pip install pyinstaller

echo [*] 使用 PyInstaller 打包...
pyinstaller --onefile --noconsole main.py -n SafeGen
echo [*] 完成：dist\SafeGen.exe
pause
