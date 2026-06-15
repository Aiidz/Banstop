import re
import sys
import subprocess
import logging
import questionary
import ipaddress

from .console import (
    console,
    Table,
    box,
    qselect
    )

log = logging.getLogger("banstop")


def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def scan_devices(interface, router_ip, status_msg="Scanning network for active devices..."):
    """Scan all active devices on the local network using arp-scan."""
    with console.status(status_msg, spinner="dots"):
        result = run(f"arp-scan --localnet -I {interface}")

        devices = []
        seen_ips = set()
        seen_macs = set()
        for line in result.stdout.splitlines():
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([\w:]+)\s*(.*)", line)
            if match:
                ip, mac, vendor = match.groups()
                mac_lower = mac.lower()
                if ip == router_ip:
                    continue
                
                # Deduplicate: Only skip if both IP and MAC are already added.
                # If a MAC has a new IP (e.g. DHCP change) or an IP has a new MAC (e.g. device replacement),
                # we still want to see them. But if both are identical, it is a duplicate packet.
                if ip in seen_ips and mac_lower in seen_macs:
                    continue

                seen_ips.add(ip)
                seen_macs.add(mac_lower)
                vendor_clean = vendor.strip()

                if not vendor_clean or "locally administered" in vendor_clean.lower():
                    vendor_name = "Unknown"
                else:
                    vendor_name = vendor_clean
                
                devices.append({
                    "ip":     ip,
                    "mac":    mac_lower,
                    "vendor": vendor_name
                    })
        
        devices.sort(key=lambda dev:ipaddress.ip_address(dev["ip"]))
        
        if not devices:
            console.print(" [error]No devices found on the network.[/error]")
            sys.exit(1)
        else:
            console.print(f" [success]Found {len(devices)} devices detected on network[/success]")
        
        return devices


def display_devices(devices, last_ips=None, last_limit_mbps=None):
    table = Table(box=box.HORIZONTALS, title_style="bold", show_header=True)
    table.add_column("",            width=1, no_wrap=True)
    table.add_column("IP Address",  style="")
    table.add_column("MAC Address", style="")
    table.add_column("Device",      style="")

    
    last_ips = last_ips or []
    
    for dev in devices:
        is_last   = dev["ip"] in last_ips
        indicator = "→" if is_last else " "
        ip_cell   = f"[bold]{dev['ip']}[/bold]" if is_last else dev["ip"]

        vendor = dev.get("vendor", "unknown")

        if len(vendor) > 25:
            vendor = vendor[:25]
        
        
        table.add_row(indicator, ip_cell, dev["mac"], vendor)
    
    console.print(table)


def pick_shaping_type():
    """Prompt user to select shaping type: bandwidth, lag, or both."""
    choice = qselect(
        "Select shaping type:",
        choices=[
            questionary.Choice("Bandwidth — throttle speed",       value="bandwidth"),
            questionary.Choice("Lag — add artificial delay/ping",  value="lag"),
            questionary.Choice("Both — throttle speed AND lag",    value="both"),
            questionary.Choice("← Back",                            value="back"),
        ]
    )

    if choice is None:
        console.print(" [error]Cancelled by user.[/error]")
        sys.exit(0)

    return choice


LAG_PRESETS = [
    ("50ms delay  + 10ms jitter — mild lag",    50,  10),
    ("100ms delay + 30ms jitter — moderate lag", 100, 30),
    ("200ms delay + 50ms jitter — severe lag",   200, 50),
    ("500ms delay + 100ms jitter — extreme lag", 500, 100),
]


def pick_lag():
    """Prompt user to select a lag preset or enter custom latency/jitter."""
    choices = []
    for i, (label, latency, jitter) in enumerate(LAG_PRESETS):
        choices.append(questionary.Choice(label, value=i))

    choices.append(questionary.Choice("Custom", value="custom"))
    choices.append(questionary.Choice("← Back", value="back"))

    choice = qselect("Select lag level:", choices=choices)

    if choice is None:
        console.print(" [error]Cancelled by user.[/error]")
        sys.exit(0)

    if choice == "back":
        return "back"

    if isinstance(choice, int):
        _, latency_ms, jitter_ms = LAG_PRESETS[choice]
        return latency_ms, jitter_ms

    while True:
        try:
            console.print()
            console.print(
                "[dim]"
                "  • Enter delay in ms (recommended: 50 - 1000)\n"
                "  • Higher values = more lag\n"
                "[/dim]"
            )
            latency_ms = int(input("  Enter delay in ms: ").strip())
            if latency_ms <= 0:
                console.print("  [error]Delay must be greater than 0.[/error]")
                continue
            break
        except ValueError:
            console.print("  [error]Invalid input. Please enter a whole number.[/error]")
        except KeyboardInterrupt:
            console.print(" [error]Cancelled by user.[/error]")
            sys.exit(0)

    while True:
        try:
            console.print(
                "[dim]"
                "  • Enter jitter in ms (random variation, 0 for constant delay)\n"
                "  • Recommended: 10-50ms for realistic lag feel\n"
                "[/dim]"
            )
            jitter_ms = int(input("  Enter jitter in ms: ").strip())
            if jitter_ms < 0:
                console.print("  [error]Jitter cannot be negative.[/error]")
                continue
            break
        except ValueError:
            console.print("  [error]Invalid input. Please enter a whole number.[/error]")
        except KeyboardInterrupt:
            console.print(" [error]Cancelled by user.[/error]")
            sys.exit(0)

    return latency_ms, jitter_ms


def pick_limit(prompt_fn=None):
    """Prompt user to select a bandwidth limit."""

    choice = qselect(
        "Select bandwidth limit:",
        choices=[
            questionary.Choice("1 Mbps — Heavy buffering, no HD YouTube",  value="1"),
            questionary.Choice("2 Mbps — Stuck at 480p",                   value="2"),
            questionary.Choice("3 Mbps — Occasional buffering at 720p",    value="3"),
            questionary.Choice("Custom",                                    value="4"),
            questionary.Choice("← Back",                                    value="back")
            ]
        )

    if choice is None:
        console.print(" [error]Cancelled by user.[/error]")
        sys.exit(0)

    if choice == "back":
        return "back"

    presets = {"1": 1.0, "2": 2.0, "3": 3.0}

    if choice in presets:
        limit_value = presets[choice]
        return limit_value

    if choice == "4":
        while True:
            try:
                console.print()
                console.print(
                "[dim]"
                "  • Enter bandwidth limit in Mbps\n"
                "  • Use decimals (.) for values below 1 Mbps (e.g. 0.1, 0.10)\n"
                "  • Recommended range: 0.5 - 20 Mbps\n"
                "[/dim]"
                )

                val = float(input("  Enter limit in Mbps: ").strip())

                if val <= 0:
                    console.print("  [error]Limit must be greater than 0.0 Mbps.[/error]")
                    continue

                return val

            except ValueError:
                console.print("  [error]Invalid input. Please enter a valid decimal number.[/error]")
            except KeyboardInterrupt:
                console.print(" [error]Cancelled by user.[/error]")
                sys.exit(0)