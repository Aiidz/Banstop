import re
import sys
import select
import tty
import termios
import time
import subprocess
import logging
import threading
import ipaddress

from rich import box
from rich.panel import Panel
from .console import console, Live, Table, custom_style, qselect
import questionary
from .scanner import run as scan_run
from .scanner import scan_devices
from .shaping import setup_traffic_shaping, cleanup_traffic_shaping
from .spoof import arp_spoof_loop, restore_arp
from .config import save_config

log = logging.getLogger("banstop")


def run(cmd):
    """Executes a shell command and captures its standard output."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def format_bytes(b):
    """Converts raw byte counts into human-readable strings."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024 ** 2:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 ** 3:
        return f"{b / 1024 ** 2:.1f} MB"
    return f"{b / 1024 ** 3:.2f} GB"


def check_online(interface, ip_address):
    """
    Checks if a device is reachable via ARP — more reliable than ping
    since many devices block ICMP but always respond to ARP requests.
    Falls back to ARP cache check if arping is unavailable.
    """
    # Primary: arping via ARP request (works even on devices that block ICMP)
    try:
        result = subprocess.run(
            ["arping", "-c", "1", "-W", "1", "-I", interface, ip_address],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if result.returncode == 0:
            return True
    except FileNotFoundError:
        pass

    # Fallback: check OS ARP cache
    try:
        result = run(f"ip neigh show {ip_address}")
        output = result.stdout.strip()
        if output and "FAILED" not in output and "INCOMPLETE" not in output:
            return True
    except Exception:
        pass

    return False


def get_tc_stats_per_class(interface):
    """
    Parses tc output to extract traffic statistics per HTB class.

    Returns:
        dict: Mapping of class IDs (int) to total_bytes (int).
              Example: {10: 15420, 11: 5320}
    """
    result = run(f"tc -s class show dev {interface}")
    lines  = result.stdout.splitlines()

    stats            = {}
    current_class_id = None

    for line in lines:
        class_match = re.search(r"class htb 1:(\d+)", line)
        if class_match:
            current_class_id = int(class_match.group(1))
            continue

        if current_class_id is not None:
            sent_match = re.search(r"Sent\s+(\d+)\s+bytes", line)
            if sent_match:
                stats[current_class_id] = int(sent_match.group(1))
                current_class_id = None

    return stats


def verify_spoofing(interface, stop_event, status=None):
    """
    Verifies ARP spoofing is working by checking if traffic is flowing
    through tc classes. Waits up to 5 seconds for packets to appear.
    Returns (True, packet_count) if successful, (False, 0) if not.
    """
    if status:
        status.update("Verifying traffic interception (timeout 5s)...")
        time.sleep(5)
    for _ in range(5):
        if stop_event.is_set():
            return False, 0
        
        result = run(f"tc -s class show dev {interface}")
        lines = result.stdout.splitlines()
        
        total_pkts = 0
        for idx, line in enumerate(lines):
            if "class htb 1:" in line:
                if idx + 1 < len(lines):
                    m = re.search(r"Sent \d+ bytes (\d+) pkt", lines[idx + 1])
                    if m:
                        total_pkts += int(m.group(1))

        if total_pkts > 0:
            return True, total_pkts
            
        time.sleep(1)

    return False, 0


def rescan_devices(interface, router_ip):
    """Run arp-scan and return list of device dicts (new devices only)."""
    result = scan_run(f"arp-scan --localnet -I {interface}")
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
            if ip in seen_ips and mac_lower in seen_macs:
                continue
            seen_ips.add(ip)
            seen_macs.add(mac_lower)
            vendor_clean = vendor.strip()
            if not vendor_clean or "locally administered" in vendor_clean.lower():
                vendor_name = "Unknown"
            else:
                vendor_name = vendor_clean
            devices.append({"ip": ip, "mac": mac_lower, "vendor": vendor_name})
    return devices


def live_monitor(interface, targets, limit_mbps, stop_event,
                 shaping_type="bandwidth", latency_ms=0, jitter_ms=0,
                 router_ip=None, spoof_threads=None, operational_mode="blacklist",
                 target_events=None):
    """
    Orchestrates the live CLI dashboard.
    Uses a background thread for ARP probing to keep UI non-blocking.
    Uses threading.Lock to prevent race conditions on shared state.
    """
    if target_events is None:
        target_events = {}

    def format_limit():
        if shaping_type == "lag":
            if jitter_ms:
                return f"{latency_ms}/{jitter_ms}ms"
            return f"{latency_ms}/0ms"
        elif shaping_type == "both":
            jitter_part = f"/{jitter_ms}" if jitter_ms else "/0"
            return f"{limit_mbps} Mbps {latency_ms}{jitter_part}ms"
        else:
            return f"{limit_mbps} Mbps"

    limit_display = format_limit()
    states      = {}
    states_lock = threading.Lock()

    for i, tgt in enumerate(targets):
        ip = tgt["ip"] if isinstance(tgt, dict) else tgt
        states[ip] = {
            "class_id":   10 + i,
            "total_bytes": 0,
            "last_bytes":  0,
            "start_time":  time.time(),
            "is_online":   True,
            "needs_probe": False,
        }

    def background_prober():
        """
        Runs ARP probes asynchronously for IPs that need connectivity check.
        Uses Lock to safely update shared state.
        """
        while not stop_event.is_set():
            with states_lock:
                ips_to_probe = [
                    ip for ip, state in states.items()
                    if state["needs_probe"]
                ]

            for ip in ips_to_probe:
                if stop_event.is_set():
                    break
                is_online = check_online(interface, ip)
                with states_lock:
                    if ip in states:
                        states[ip]["is_online"]   = is_online
                        states[ip]["needs_probe"] = False

            stop_event.wait(2)

    threading.Thread(target=background_prober, daemon=True).start()

    def validate_ip(ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def validate_mac(mac):
        return bool(re.match(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$", mac))

    def handle_rescan_and_add():
        while True:
            console.print()
            console.print("[bold bright_cyan]=== Manage Targets ===[/bold bright_cyan]")
            choice = qselect(
                "Choose an option:",
                choices=[
                    questionary.Choice("Scan network for new devices", value="scan"),
                    questionary.Choice("Manually add target by IP or MAC", value="manual"),
                    questionary.Choice("Remove target from list", value="remove"),
                    questionary.Choice("Cancel / Return to monitor", value="cancel")
                ]
            )
            if not choice or choice == "cancel":
                return

            new_targets_to_add = []

            if choice == "scan":
                scanned = scan_devices(interface, router_ip, status_msg="Rescanning network for new devices...")
                
                current_ips = {t["ip"] for t in targets}
                current_macs = {t["mac"].lower() for t in targets if "mac" in t}
                
                new_devices = []
                for dev in scanned:
                    if dev["ip"] not in current_ips and dev["mac"].lower() not in current_macs:
                        new_devices.append(dev)
                        
                if not new_devices:
                    console.print(" [warning]No new devices detected on the network.[/warning]")
                    input("  Press Enter to return...")
                    continue
                    
                choices = [
                    questionary.Choice(f"{d['ip']:<15} · {d['mac']:<19} · {d['vendor'][:25]}", value=d)
                    for d in new_devices
                ]
                choices.append(questionary.Choice("← Back", value="back"))
                
                selected = questionary.checkbox(
                    "Select new devices to throttle:",
                    qmark="",
                    instruction="(Space to select, Enter to confirm)",
                    choices=choices,
                    style=custom_style,
                    pointer=">"
                ).ask(kbi_msg="")
                
                if selected is None or "back" in selected or (isinstance(selected, list) and "back" in [x if isinstance(x, str) else "" for x in selected]):
                    continue
                
                if selected:
                    new_targets_to_add.extend(selected)

            elif choice == "manual":
                val = input("  Enter IP or MAC address to add (or type 'back' to go back): ").strip()
                if not val or val.lower() == 'back':
                    continue
                    
                ip = None
                mac = ""
                vendor = "Manual Entry"
                
                if validate_ip(val):
                    ip = val
                    try:
                        scanned = scan_devices(interface, router_ip, status_msg=f"Resolving MAC for IP {ip}...")
                        for d in scanned:
                            if d["ip"] == ip:
                                mac = d["mac"]
                                vendor = d["vendor"]
                                break
                    except Exception:
                        pass
                elif validate_mac(val):
                    mac = val.lower()
                    try:
                        scanned = scan_devices(interface, router_ip, status_msg=f"Resolving IP for MAC {mac}...")
                        for d in scanned:
                            if d["mac"].lower() == mac:
                                ip = d["ip"]
                                vendor = d["vendor"]
                                break
                    except Exception:
                        pass
                        
                    if not ip:
                        ip = input(f"  Could not resolve IP for MAC {mac}. Enter IP address (or 'back' to go back): ").strip()
                        if ip.lower() == 'back':
                            continue
                        if not validate_ip(ip):
                            console.print(" [error]Invalid IP address.[/error]")
                            input("  Press Enter to return...")
                            continue
                else:
                    console.print(" [error]Invalid IP or MAC address format.[/error]")
                    input("  Press Enter to return...")
                    continue
                    
                current_ips = {t["ip"] for t in targets}
                if ip in current_ips:
                    console.print(f" [warning]Device {ip} is already in the targets list.[/warning]")
                    input("  Press Enter to return...")
                    continue
                    
                new_targets_to_add.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor
                })

            elif choice == "remove":
                if not targets:
                    console.print(" [warning]No targets are currently in the list.[/warning]")
                    input("  Press Enter to return...")
                    continue
                    
                choices = [
                    questionary.Choice(f"{t['ip']:<15} · {t.get('mac', ''):<19} · {t.get('vendor', '')[:25]}", value=t)
                    for t in targets
                ]
                choices.append(questionary.Choice("← Back", value="back"))
                
                selected_to_remove = questionary.checkbox(
                    "Select targets to remove from throttling:",
                    qmark="",
                    instruction="(Space to select, Enter to confirm)",
                    choices=choices,
                    style=custom_style,
                    pointer=">"
                ).ask(kbi_msg="")
                
                if selected_to_remove is None or "back" in selected_to_remove or (isinstance(selected_to_remove, list) and "back" in [x if isinstance(x, str) else "" for x in selected_to_remove]):
                    continue
                    
                if not selected_to_remove:
                    continue
                    
                for tgt in selected_to_remove:
                    ip = tgt["ip"]
                    if ip in target_events:
                        target_events[ip].set()
                        del target_events[ip]
                    
                    try:
                        restore_arp(interface, ip, router_ip)
                    except Exception as e:
                        log.warning(f"Failed to restore ARP for {ip}: {e}")
                        
                    if tgt in targets:
                        targets.remove(tgt)
                        
                    with states_lock:
                        if ip in states:
                            del states[ip]
                
                cleanup_traffic_shaping(interface)
                if targets:
                    setup_traffic_shaping(
                        interface, targets, limit_mbps=limit_mbps,
                        shaping_type=shaping_type, latency_ms=latency_ms, jitter_ms=jitter_ms
                    )
                
                try:
                    save_config(
                        interface, router_ip, operational_mode, targets,
                        limit_mbps=limit_mbps, shaping_type=shaping_type,
                        latency_ms=latency_ms, jitter_ms=jitter_ms
                    )
                except Exception:
                    pass
                    
                console.print(f" [success]Successfully removed {len(selected_to_remove)} device(s) and restored traffic.[/success]")
                time.sleep(1.5)
                continue

            if new_targets_to_add:
                for new_tgt in new_targets_to_add:
                    targets.append(new_tgt)
                    
                    new_ip = new_tgt["ip"]
                    new_event = threading.Event()
                    target_events[new_ip] = new_event
                    
                    t = threading.Thread(
                        target=arp_spoof_loop,
                        args=(interface, new_ip, router_ip, new_event),
                        daemon=True
                    )
                    t.start()
                    if spoof_threads is not None:
                        spoof_threads.append(t)
                        
                    with states_lock:
                        states[new_ip] = {
                            "class_id": 10 + len(targets) - 1,
                            "total_bytes": 0,
                            "last_bytes": 0,
                            "start_time": time.time(),
                            "is_online": True,
                            "needs_probe": False,
                        }
                        
                cleanup_traffic_shaping(interface)
                setup_traffic_shaping(
                    interface, targets, limit_mbps=limit_mbps,
                    shaping_type=shaping_type, latency_ms=latency_ms, jitter_ms=jitter_ms
                )
                
                try:
                    save_config(
                        interface, router_ip, operational_mode, targets,
                        limit_mbps=limit_mbps, shaping_type=shaping_type,
                        latency_ms=latency_ms, jitter_ms=jitter_ms
                    )
                except Exception:
                    pass
                    
                console.print(f" [success]Successfully added {len(new_targets_to_add)} device(s) and applied shaping.[/success]")
                time.sleep(1.5)

    prev_time = time.time()
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    try:
        tty.setcbreak(fd)
        with Live(console=console, refresh_per_second=2) as live:
            while not stop_event.is_set():
                now     = time.time()
                elapsed = now - prev_time

                tc_stats = get_tc_stats_per_class(interface)

                table = Table(
                    box=box.SIMPLE,
                    show_header=True,
                    expand=False,
                )
                table.add_column("STATUS",        justify="left")
                table.add_column("TARGET IP",     justify="left")
                table.add_column("LIMIT SPEED",   justify="right")
                table.add_column("CURRENT SPEED", justify="right")
                table.add_column("TOTAL DATA",    justify="right")
                table.add_column("SESSION TIME",  justify="center")

                with states_lock:
                    for tgt in targets:
                        ip    = tgt["ip"] if isinstance(tgt, dict) else tgt
                        state = states[ip]

                        current_bytes = tc_stats.get(state["class_id"], state["last_bytes"])
                        delta_bytes   = max(0, current_bytes - state["last_bytes"])

                        mbps = 0.0
                        if elapsed > 0:
                            mbps = (delta_bytes * 8) / (elapsed * 1_000_000)

                        # Traffic-first: if traffic flowing, device is definitely online
                        if mbps > 0.05:
                            state["needs_probe"] = False
                            state["is_online"]   = True
                            status_display       = "[bold green]ACTIVE[/bold green]"
                            speed_text           = f"[bold green]{mbps:.2f} Mbps[/bold green]"
                            text_style           = "white"
                        else:
                            # No traffic — delegate reachability check to background prober
                            state["needs_probe"] = True
                            if state["is_online"]:
                                status_display = "[dim white]IDLE[/dim white]"
                                speed_text     = "[dim white]0.00 Mbps[/dim white]"
                                text_style     = "dim white"
                            else:
                                status_display = "[bold magenta]PAUSED[/bold magenta]"
                                speed_text     = "[dim red][OFFLINE][/dim red]"
                                text_style     = "dim white"

                        state["total_bytes"] = current_bytes
                        state["last_bytes"]  = current_bytes

                        uptime     = int(now - state["start_time"])
                        m, s       = divmod(uptime, 60)
                        h, m       = divmod(m, 60)
                        uptime_str = f"{h:02d}:{m:02d}:{s:02d}"
                        total_str  = format_bytes(state["total_bytes"])

                        table.add_row(
                            status_display,
                            f"[{text_style}]{ip}[/{text_style}]",
                            f"[{text_style}]{limit_display}[/{text_style}]",
                            speed_text,
                            f"[{text_style}]{total_str}[/{text_style}]",
                            f"[{text_style}]{uptime_str}[/{text_style}]",
                        )

                prev_time = now

                live.update(Panel(
                    table,
                    subtitle="[dim white]Ctrl+C to terminate | R to rescan & add targets[/dim white]",
                    title_align="left",
                    subtitle_align="right",
                    padding=(0, 1),
                    expand=False,
                ))

                # Sleep in small increments to remain responsive to keypresses and stop_event
                for _ in range(5):
                    if stop_event.is_set():
                        break
                    if select.select([sys.stdin], [], [], 0)[0]:
                        key = sys.stdin.read(1)
                        if key.lower() == 'r':
                            # Flush buffer
                            while select.select([sys.stdin], [], [], 0)[0]:
                                sys.stdin.read(1)
                            
                            live.stop()
                            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                            try:
                                handle_rescan_and_add()
                            finally:
                                tty.setcbreak(fd)
                                live.start()
                                prev_time = time.time()  # reset timer baseline
                            break
                    time.sleep(0.1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)