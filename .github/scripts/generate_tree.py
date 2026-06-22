import json
import os
from collections import defaultdict

input_file = './falco-data/falco_events.json'
events = []

try:
    with open(input_file, 'r') as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))
except FileNotFoundError:
    print(f"No {input_file} found. Skipping summary.")
    exit(0)

# Maps for tree building and tracking
processes = {}
children_map = defaultdict(list)

# Tracking sets/dicts for specific rules
privesc_pids = set()
tty_pids = set()
sensitive_reads = defaultdict(set) 
env_reads = defaultdict(set)
staging_pids = set()
exfil_net_pids = set()

for event in events:
    rule_name = event.get('rule')
    fields = event.get('output_fields', {})
    pid = fields.get('proc.pid')
    ppid = fields.get('proc.ppid')
    cmdline = fields.get('proc.cmdline')
    filename = fields.get('fd.name')

    if not pid: continue

    # Always update to the latest cmdline (from execve)
    if cmdline:
        processes[pid] = cmdline
        
    if ppid and pid not in children_map[ppid]:
        children_map[ppid].append(pid)
        
    # Categorize alerts based on rule name
    if rule_name == 'Detect Privilege Escalation':
        privesc_pids.add(pid)
        
    if rule_name == 'Detect Sensitive File Read' and filename:
        sensitive_reads[pid].add(filename)
        
    if rule_name == 'Detect Interactive or Reverse Shell':
        tty_pids.add(pid)

    if rule_name == 'Detect Environment Variable Access' and filename:
        env_reads[pid].add(filename)

    if rule_name == 'Detect Data Staging and Encryption':
        staging_pids.add(pid)
        
    if rule_name == 'Detect Suspicious Network Exfiltration':
        exfil_net_pids.add(pid)

# Find root nodes
all_pids = set(processes.keys())
roots = set(children_map.keys()) - all_pids

summary = []

# --- 1. PRIVESC BANNER ---
if privesc_pids:
    summary.append("### 🚨 CRITICAL: Privilege Escalation Detected 🚨")
    summary.append("The following processes attempted to escalate privileges or modify critical permissions.\n")
    summary.append("| PID | Command |")
    summary.append("|---|---|")
    for esc_pid in privesc_pids:
        cmd = processes.get(esc_pid, "Unknown Command")
        summary.append(f"| {esc_pid} | `{cmd}` |")
    summary.append("\n---\n")

# --- 2. TTY / REVSHELL BANNER ---
if tty_pids:
    summary.append("### 💀 FATAL: Interactive Shell / TTY Spawned 💀")
    summary.append("CI/CD environments should be non-interactive. The following processes spawned an interactive shell or pseudo-terminal, indicating a likely reverse shell connection.\n")
    summary.append("| PID | Command |")
    summary.append("|---|---|")
    for shell_pid in tty_pids:
        cmd = processes.get(shell_pid, "Unknown Command")
        summary.append(f"| {shell_pid} | `{cmd}` |")
    summary.append("\n---\n")

# --- 3. ENV ACCESS BANNER  ---
if env_reads:
    summary.append("### ☢️ DANGER: Environment Variable Scraping ☢️")
    summary.append("The following processes accessed `/proc/*/environ`. Attackers use this to scrape memory for sensitive tokens or AWS/GitHub credentials injected into the CI/CD environment.\n")
    summary.append("| PID | Command | Target File |")
    summary.append("|---|---|---|")
    for env_pid, files in env_reads.items():
        cmd = processes.get(env_pid, "Unknown Command")
        file_list = ", ".join(f"`{f}`" for f in files)
        summary.append(f"| {env_pid} | `{cmd}` | {file_list} |")
    summary.append("\n---\n")

# --- 4. SENSITIVE FILE READS BANNER ---
if sensitive_reads:
    summary.append("### 🕵️ WARNING: Sensitive Files Accessed 🕵️")
    summary.append("The following processes accessed restricted files. Check the tree below to see if this data was subsequently staged or transmitted.\n")
    summary.append("| PID | Command | Files Accessed |")
    summary.append("|---|---|---|")
    for read_pid, files in sensitive_reads.items():
        cmd = processes.get(read_pid, "Unknown Command")
        file_list = ", ".join(f"`{f}`" for f in files)
        summary.append(f"| {read_pid} | `{cmd}` | {file_list} |")
    summary.append("\n---\n")

# --- 5. EXFILTRATION PIPELINE BANNER ---
if staging_pids or exfil_net_pids:
    summary.append("### 📡 CRITICAL: Data Exfiltration Pipeline Detected 📡")
    summary.append("Processes attempted to archive, encrypt, or transmit data over the network. This strongly indicates data theft staging.\n")
    summary.append("| PID | Behavior Type | Command |")
    summary.append("|---|---|---|")
    for s_pid in staging_pids:
        cmd = processes.get(s_pid, "Unknown Command")
        summary.append(f"| {s_pid} | `Data Staging/Encryption` | `{cmd}` |")
    for e_pid in exfil_net_pids:
        cmd = processes.get(e_pid, "Unknown Command")
        summary.append(f"| {e_pid} | `Network Transmission` | `{cmd}` |")
    summary.append("\n---\n")

# --- 6. PROCESS TREE ---
summary.extend(["### 🌳 CI/CD Process Execution Context\n", "```text"])

def build_tree(current_pid, depth, is_last):
    indent = "    " * depth
    prefix = "└── " if is_last else "├── "
    if depth == 0: prefix = ""
    
    # Apply context tags
    alert_tags = ""
    if current_pid in privesc_pids: alert_tags += "🚨[PRIVESC] "
    if current_pid in tty_pids: alert_tags += "💀[REVSHELL] "
    if current_pid in env_reads: alert_tags += "☢️[ENV_SCRAPING] "
    if current_pid in sensitive_reads: alert_tags += "📂[EXFIL] "
    if current_pid in staging_pids: alert_tags += "📦[STAGING] "
    if current_pid in exfil_net_pids: alert_tags += "📡[NETWORK_EXFIL] "
    
    cmd = processes.get(current_pid, f"Unknown Process (PID: {current_pid})")
    summary.append(f"{indent}{prefix}[{current_pid}] {alert_tags}{cmd}")
    
    children = children_map.get(current_pid, [])
    for i, child_pid in enumerate(children):
        build_tree(child_pid, depth + 1, i == (len(children) - 1))

for root_ppid in sorted(roots):
    for i, child_pid in enumerate(children_map[root_ppid]):
        build_tree(child_pid, 0, i == (len(children_map[root_ppid]) - 1))

summary.append("```\n")

# Write to GitHub Step Summary
summary_path = os.environ.get('GITHUB_STEP_SUMMARY')
if summary_path:
    with open(summary_path, 'a') as f:
        f.write('\n'.join(summary))
else:
    print('\n'.join(summary))