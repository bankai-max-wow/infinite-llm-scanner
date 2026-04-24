@echo off
echo [*] Installing Python requirements...
pip install -r requirements.txt
echo.
echo [*] Starting Infinite LLM Scanner...
echo [*] Options:
echo    --test          : Test mode (1 cycle)
echo    --zmap          : Use ZMap for port scanning
echo    --niansuh-only  : Only scan config files
echo    --gate-only     : Only test LLM gateways
echo.
python infinite_scanner.py %*
pause
