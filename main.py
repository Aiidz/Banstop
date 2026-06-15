#!/usr/bin/env python3

import sys
import signal
import logging
import threading
import time

from core.console import console

from core import (
    check_os,
    check_root,
    check_dependencies,
    pick_interface,
    pick_router,
    scan_devices,
    display_devices,
    pick_limit,
    pick_shaping_type,
    pick_lag,
    enable_ip_forward,
    disable_ip_forward,
    setup_traffic_shaping,
    cleanup_traffic_shaping,
    arp_spoof_loop,
    restore_arp,
    verify_spoofing,
    live_monitor,
    save_config,
    load_config,
    prompt_use_saved_config,
    prompt_operational_mode,
    prompt_blacklist_selection,
    prompt_whitelist_selection,
    prompt_session_review,
    match_saved_config
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("banstop")

stop_event = threading.Event()

# Register signal handlers immediately so cleanup runs on any kill signal
def signal_handler(sig, frame):
    stop_event.set()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def prompt(text, valid_range=None):
    """Generic prompt with optional range validation."""
    while True:
        try:
            choice = input(text).strip()
            if valid_range is not None:
                idx = int(choice) - 1
                if 0 <= idx < valid_range:
                    return idx
                print(f"  [!] Enter a number between 1 and {valid_range}")
            else:
                return choice
        except ValueError:
            print("  [!] Invalid input.")
        except KeyboardInterrupt:
            print("\n  Cancelled.")
            sys.exit(0)


def banner():
    print()
    print(" ____                  _               ")
    print("| __ )  __ _ _ __  ___| |_ ___  _ __  ")
    print("|  _ \\ / _` | '_ \\/ __| __/ _ \\| '_ \\ ")
    print("| |_) | (_| | | | \\__ \\ || (_) | |_) |")
    print("|____/ \\__,_|_| |_|___/\\__\\___/| .__/ ")
    print("                                |_|    ")
    console.print("  [dim]enhanced bandwidth control[/dim]")
    print()    


def signal_handler(sig, frame):
    stop_event.set()


def main():
    check_os()
    check_root()
    check_dependencies()

    banner()

    interface      = None
    router_ip      = None
    limit_mbps     = None
    shaping_type   = "bandwidth"
    latency_ms     = 0
    jitter_ms      = 0
    used_saved     = False
    targets_to_throttle = []
    
    step = 1
    while True:
        if step == 1:
            interface = pick_interface()
            step = 2

        elif step == 2:
            router_ip = pick_router(interface)
            if router_ip == "back":
                step = 1
                continue
            step = 3

        elif step == 3:
            config  = load_config()
            devices = scan_devices(interface, router_ip)
            matched_dev = match_saved_config(config, devices)
            
            if matched_dev:
                last_ips = [d["ip"] for d in matched_dev]
                last_limit = config.get("limit_mbps")
            else:
                last_ips = []
                last_limit = None
                
            display_devices(devices, last_ips=last_ips, last_limit_mbps=last_limit)
            step = 4

        elif step == 4:
            if matched_dev and config.get("interface") == interface and config.get("router_ip") == router_ip:
                action = prompt_use_saved_config(config, matched_dev)

                while action == "rescan":
                    console.clear()
                    console.print()
                    devices = scan_devices(interface, router_ip, status_msg="Rescanning network, please wait...")
                    matched_dev = match_saved_config(config, devices)
                    if matched_dev:
                        last_ips_rescan = [d["ip"] for d in matched_dev]
                        display_devices(devices, last_ips=last_ips_rescan, last_limit_mbps=last_limit)
                        action = prompt_use_saved_config(config, matched_dev)
                    else:
                        display_devices(devices, last_ips=[], last_limit_mbps=None)
                        action = "new_scan"
                        break
                
                if action == "use_saved":
                    limit_mbps   = config.get("limit_mbps")
                    shaping_type = config.get("shaping_type", "bandwidth")
                    latency_ms   = config.get("latency_ms", 0)
                    jitter_ms    = config.get("jitter_ms", 0)
                    operational_mode = config.get("operational_mode", "blacklist")
                    targets_to_throttle = matched_dev
                    used_saved = True
                    step = 9
                elif action == "new_scan":
                    used_saved = False
                    step = 5
            else:
                console.print(" [dim]No previous session found on this network.[/dim]\n")
                used_saved = False
                step = 5

        elif step == 5:
            operational_mode = prompt_operational_mode()
            if operational_mode == "back":
                if matched_dev and config.get("interface") == interface and config.get("router_ip") == router_ip:
                    step = 4
                else:
                    step = 2
                continue
            step = 6

        elif step == 6:
            if operational_mode == "blacklist" or operational_mode is None:
                targets_to_throttle = prompt_blacklist_selection(devices, matched_dev)
                if targets_to_throttle == "back":
                    step = 5
                    continue
            elif operational_mode == "whitelist":
                safe_devices = prompt_whitelist_selection(devices, matched_dev)
                if safe_devices == "back":
                    step = 5
                    continue
                safe_ips = [d["ip"] for d in safe_devices]
                targets_to_throttle = [d for d in devices if d["ip"] not in safe_ips]
                
                if not targets_to_throttle:
                    console.print("  [warning]No targets to throttle. Everyone is whitelisted.[/warning]")
                    input("  Press Enter to change selection...")
                    continue
            step = 7

        elif step == 7:
            shaping_type = pick_shaping_type()
            if shaping_type == "back":
                step = 6
                continue
            step = 8

        elif step == 8:
            if shaping_type in ("lag", "both"):
                res = pick_lag()
                if res == "back":
                    step = 7
                    continue
                latency_ms, jitter_ms = res
            else:
                latency_ms, jitter_ms = 0, 0

            if shaping_type in ("bandwidth", "both"):
                limit_mbps = pick_limit(prompt)
                if limit_mbps == "back":
                    step = 7
                    continue
            else:
                limit_mbps = None
            step = 9

        elif step == 9:
            review_action = prompt_session_review(
                interface, router_ip, operational_mode, targets_to_throttle,
                limit_mbps=limit_mbps, shaping_type=shaping_type,
                latency_ms=latency_ms, jitter_ms=jitter_ms
            )
            if review_action == "back":
                if used_saved:
                    step = 4
                else:
                    step = 8
                continue
            elif review_action == "start":
                break

    spoof_threads = []
    success = False

    try:
        with console.status("Initializing network routing...", spinner="dots") as status:
            mode_display = operational_mode.capitalize() if operational_mode else "Blacklist"
            status.update(f"Saving {mode_display} config for {len(targets_to_throttle)} target(s) to config.json...")
        
            save_config(interface, router_ip, operational_mode, targets_to_throttle,
                        limit_mbps=limit_mbps, shaping_type=shaping_type,
                        latency_ms=latency_ms, jitter_ms=jitter_ms, status=status)
            time.sleep(0.8)
            
            status.update("System: Forcing net.ipv4.ip_forward=1...")
            enable_ip_forward()
            time.sleep(0.8)
            
            if shaping_type == "lag":
                shaping_desc = f"{latency_ms}ms delay"
                if jitter_ms:
                    shaping_desc += f" + {jitter_ms}ms jitter"
            elif shaping_type == "both":
                shaping_desc = f"{limit_mbps} Mbps + {latency_ms}ms delay"
                if jitter_ms:
                    shaping_desc += f" + {jitter_ms}ms jitter"
            else:
                shaping_desc = f"{limit_mbps} Mbps"

            status.update(f"QoS: Attaching {shaping_desc} rules to interface {interface}...")
            setup_traffic_shaping(interface, targets_to_throttle,
                                  limit_mbps=limit_mbps, shaping_type=shaping_type,
                                  latency_ms=latency_ms, jitter_ms=jitter_ms)
                
            time.sleep(0.8)
            
            status.update(f"ARP: Injecting MITM routes between {len(targets_to_throttle)} target(s) and gateway {router_ip}...")
            target_events = {}
            for tgt in targets_to_throttle:
                ip = tgt["ip"]
                # Use a specific event per target so we can terminate it individually
                evt = threading.Event()
                target_events[ip] = evt
                
                t = threading.Thread(
                    target=arp_spoof_loop,
                    args=(interface, ip, router_ip, evt),
                    daemon=True
                )
                t.start()
                spoof_threads.append(t)
            time.sleep(0.8)
            
            success, captured_pkts = verify_spoofing(interface, stop_event, status=status)
            
            if not success:
                stop_event.set()

        if success:
            console.print(f" [success]Spoofing successful! {captured_pkts} packets captured. Launching live monitor...[/success]")
            time.sleep(1.5)
            console.print()
            monitor_thread = threading.Thread(
                target=live_monitor,
                args=(interface, targets_to_throttle, limit_mbps, stop_event),
                kwargs={"shaping_type": shaping_type, "latency_ms": latency_ms, "jitter_ms": jitter_ms,
                        "router_ip": router_ip, "spoof_threads": spoof_threads,
                        "operational_mode": operational_mode,
                        "target_events": target_events},
                daemon=True
            )
            monitor_thread.start()
        else:
            console.print("  [error]Target device does not appear to be using the network. Stopping...[/error]")

        try:
            while not stop_event.is_set():
                stop_event.wait(0.1)
        except KeyboardInterrupt:
            stop_event.set()

        if success and 'monitor_thread' in locals():
            monitor_thread.join(timeout=2)

    finally:
        with console.status("Initiating teardown sequence...", spinner="dots") as status:

            status.update("Teardown: Signaling thread terminations...")
            if 'target_events' in locals():
                for ip, evt in target_events.items():
                    evt.set()

            status.update(f"Teardown: Terminating active ARP spoofing threads for {len(spoof_threads)} thread(s)...")
            for t in spoof_threads:
                t.join(timeout=5)
            time.sleep(0.6)

            status.update(f"ARP: Restoring ARP tables for {len(targets_to_throttle)} target(s)...")
            for tgt in targets_to_throttle:
                ip = tgt["ip"] if isinstance(tgt, dict) else tgt
                restore_arp(interface, ip, router_ip)
            time.sleep(0.6)

            status.update(f"QoS: Flushing HTB shaping rules from interface {interface}...")
            cleanup_traffic_shaping(interface)
            time.sleep(0.6)

            status.update("System: Restoring net.ipv4.ip_forward=0...")
            disable_ip_forward()
            time.sleep(0.6)

        console.print("\n [error]Session terminated.[/error]")
        console.print(" [success]Network restored and traffic shaping rules cleared.[/success]")


if __name__ == "__main__":
    main()