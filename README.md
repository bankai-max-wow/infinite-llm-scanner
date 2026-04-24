# Infinite LLM Gateway + Key Scanner

Automated scanner for finding LLM gateways and API keys.

## Features

- Scans for LLM gateways (LiteLLM, Ollama, vLLM)
- Extracts API keys from config files (Niansuh-style)
- Validates keys against real provider APIs
- Reports findings to Telegram
- ZMap integration for internet-wide port scanning
- Infinite loop mode for continuous scanning

## Quick Start

### Option 1: Run with Python (Recommended)
```bash
pip install -r requirements.txt
python infinite_scanner.py
```

### Option 2: Run EXE (No Python required)
```bash
# Double-click run_scanner.exe or use start.bat
start.bat
```

## Usage

```bash
# Full infinite scan (default mode)
python infinite_scanner.py

# Test mode (1 cycle only)
python infinite_scanner.py --test

# Use ZMap for port scanning
python infinite_scanner.py --zmap

# Only scan config files for keys
python infinite_scanner.py --niansuh-only

# Only test LLM gateways
python infinite_scanner.py --gate-only

# Custom batch size
python infinite_scanner.py --batch-size 5000

# ZMap with custom ports and bandwidth
python infinite_scanner.py --zmap --zmap-ports 3000,4000,8000 --zmap-bandwidth 10M
```

## Options

| Flag | Description |
|------|-------------|
| `--test` | Run single cycle (for testing) |
| `--zmap` | Use ZMap for port scanning |
| `--zmap-ports` | Ports for ZMap (default: 3000,4000,8000) |
| `--zmap-bandwidth` | ZMap rate limit (default: 10M) |
| `--niansuh-only` | Only extract keys from config files |
| `--gate-only` | Only test LLM gateways |
| `--batch-size` | IPs per cycle (default: 3000) |

## Telegram Reporting

Configure Telegram bot and group ID at top of `infinite_scanner.py`:
```python
TELEGRAM_BOT_TOKEN = 'YOUR_BOT_TOKEN'
TELEGRAM_CHAT_ID = 'YOUR_GROUP_ID'
```

## Output

Results saved to `scan_output/` folder:
- `found_working_keys.json` - Validated API keys
- `found_working_gates.json` - Working LLM gateways
- `seen_ips.json` - Scanned IPs (avoid re-scanning)
- `scan_log.jsonl` - Scan history

## Requirements

- Python 3.8+ (or Windows EXE bundle)
- aiohttp
- ZMap (optional, for internet port scanning)
  - Linux: `sudo apt install zmap`
  - macOS: `brew install zmap`
  - Source: https://github.com/zmap/zmap

## Legal Warning

This tool is for **authorized security testing only**. Unauthorized scanning of systems you don't own is illegal.
