# Banstop

Banstop is an interactive terminal-based network traffic controller and bandwidth shaper for Linux. It allows network administrators and power users to throttle bandwidth, inject artificial latency, and introduce network jitter for any device on a local network—all without requiring administrative access to the gateway router, custom firmware, or physical access to target devices.

> [!IMPORTANT]
> **Linux-Exclusive.** Banstop depends on core Linux kernel capabilities (tc, HTB, netem) and standard utility binaries (arpspoof, arp-scan) that have no equivalents on Windows or macOS.

---

## How It Works

Banstop orchestrates a two-part network redirection and shaping sequence:

1. **ARP Interception**: It sends gratuitous, targeted ARP replies to redirect traffic from specified target hosts through the host running Banstop (a temporary Man-in-the-Middle configuration).
2. **QoS Traffic Control**: It leverages the Linux kernel's Traffic Control (tc) subsystem to attach Hierarchical Token Bucket (htb) and Network Emulator (netem) queue disciplines. Intercepted packets are shaped to matching limits before being forwarded back to the gateway.

```
Normal Path:
[Target Device] ───────────────────────────→ [Router] ──→ [Internet]

Intercepted & Shaped Path:
[Target Device] ──→ [Your Host (Banstop)] ──→ [Router] ──→ [Internet]
                       (Throttled/Lagged)
```

---

## Features

* **Multi-Target Live Monitor**: Rich-powered CLI dashboard displaying real-time target status (Active, Idle, Offline), current transfer rates (Mbps), total data transferred, and uptime.
* **Granular Network Control**:
  * **Bandwidth Throttling**: Cap download/upload speeds in Mbps.
  * **Latency Injection**: Introduce custom ping delays (ms).
  * **Network Jitter**: Emulate natural latency variation (jitter ms).
* **Operational Modes**:
  * **Blacklist Mode**: Specifically throttle selected devices while leaving the rest of the network untouched.
  * **Whitelist Mode**: Throttle all local hosts except safe exceptions that you select.
* **Dynamic Target Management (Live Session)**: Press R during live monitoring to access the **Manage Targets** menu without stopping the session:
  * **Scan & Add**: Rescan the network to discover newly connected devices and throttle them immediately.
  * **Manual Add**: Directly input an IP or MAC address to target.
  * **Dynamic Removal**: Select active targets to release from throttling; Banstop immediately repairs their ARP tables (restore_arp) and flushes their shaping filters.
* **Navigable Setup Wizard**: A state-machine configuration wizard with Back options to navigate between configuration screens.
* **Auto-Deduplication**: Intelligent scanner logic that filters duplicate arp-scan replies to present a clean host selection list.
* **Session Persistence**: Saves configurations locally (~/.config/banstop/config.json) to allow one-click session resumption.
* **Clean Teardown**: Intercepts terminal interrupts (Ctrl+C) and signals to restore all host routing tables, flush tc filters, and disable IPv4 forwarding.

---

## Requirements

* **OS**: Linux (tested on Arch Linux, Fedora, Debian, and Ubuntu)
* **System Utilities**:
  * arpspoof (from dsniff)
  * arp-scan
  * iproute2 (provides tc)
* **Python**: Version 3.8 or higher

### Install System Dependencies:

**Ubuntu / Debian / Linux Mint:**
```bash
sudo apt update && sudo apt install dsniff arp-scan iproute2
```

**Arch Linux / Manjaro / CachyOS:**
```bash
sudo pacman -S dsniff arp-scan iproute2
```

**Fedora / RHEL:**
```bash
sudo dnf install dsniff arp-scan iproute2
```

---

## Installation

Install Banstop via pipx (recommended) or pip:

```bash
# Using pipx (Recommended for isolated environments)
pipx install banstop

# Link command-line executable helper
sudo ln -s ~/.local/bin/banstop /usr/local/bin/banstop
```

---

## Usage

Start the interactive console client (requires root privileges for network socket manipulation and QoS configuration):

```bash
sudo banstop
```

### Configuration Wizard Flow:
1. **Interface Detection**: Automatically select or choose an active network interface.
2. **Gateway Discovery**: Automatically select or choose the router/gateway IP address.
3. **Session Check**: If a saved session configuration is found, choose whether to resume it or start a new scan.
4. **Target Selection**: Pick targets to blacklist or whitelisted hosts to protect.
5. **Shaping Type Selection**: Select Bandwidth throttling, Lag injection, or Both.
6. **Limit Configuration**: Choose a preset limit or type custom values.
7. **Session Review**: Review configuration and confirm to launch.

---

## Live Monitor Keyboard Shortcuts

While the live table dashboard is running, the following keyboard inputs are captured instantly (without needing to press Enter):

* `Ctrl + C`: Initiates a graceful shutdown sequence (restores target routing tables, flushes traffic shaping queues, and restores default IP forwarding configuration).
* `R` or `r`: Pauses rendering and opens the **Manage Targets** menu:
  * **Scan network for new devices**: Perform an active network scan and append selected new devices.
  * **Manually add target by IP or MAC**: Directly input targets to spoof.
  * **Remove target from list**: Choose throttled devices to release.

---

## Disclaimer

This tool is intended for network performance testing, system administration, and educational security research. It must only be run on networks you own or have explicit authorization to manage. Unauthorized ARP spoofing may violate local computer misuse legislation.
