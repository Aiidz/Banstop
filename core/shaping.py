import subprocess
import logging

log = logging.getLogger("banstop")

SYSCTL_IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"


def run(cmd, check=True):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        log.error(f"Command failed: {cmd}\n{result.stderr.strip()}")
    return result


def enable_ip_forward():
    run(f"echo 1 > {SYSCTL_IP_FORWARD_PATH}")


def disable_ip_forward():
    run(f"echo 0 > {SYSCTL_IP_FORWARD_PATH}")


def setup_iptables(interface, targets):
    run(f"iptables -t nat -A POSTROUTING -o {interface} -j MASQUERADE", check=False)
    run(f"iptables -A FORWARD -i {interface} -o {interface} -j ACCEPT", check=False)
    run(f"iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT", check=False)
    for tgt in targets:
        ip = tgt["ip"] if isinstance(tgt, dict) else tgt
        run(f"iptables -A FORWARD -s {ip} -j ACCEPT", check=False)
        run(f"iptables -A FORWARD -d {ip} -j ACCEPT", check=False)


def setup_traffic_shaping(interface, targets, limit_mbps=None, shaping_type="bandwidth",
                          latency_ms=0, jitter_ms=0, status=None):
    if isinstance(targets, str):
        targets = [{"ip": targets}]

    setup_iptables(interface, targets)

    run(f"tc qdisc del dev {interface} root", check=False)
    run(f"tc qdisc add dev {interface} root handle 1: htb default 99")
    run(f"tc class add dev {interface} parent 1: classid 1:99 htb rate 1000mbit")
    run(f"tc qdisc add dev {interface} parent 1:99 handle 99: sfq perturb 10")

    for i, tgt in enumerate(targets):
        ip = tgt["ip"] if isinstance(tgt, dict) else tgt
        class_id = 10 + i
        handle_id = class_id * 10

        if shaping_type in ("bandwidth", "both"):
            limit_kbit = int(limit_mbps * 1000)
            burst = max(limit_kbit // 8 * 2, 1500)
            run(f"tc class add dev {interface} parent 1: classid 1:{class_id} htb rate {limit_kbit}kbit burst {burst}")
        else:
            run(f"tc class add dev {interface} parent 1: classid 1:{class_id} htb rate 1000mbit")

        if shaping_type in ("lag", "both"):
            jitter_arg = f" {jitter_ms}ms" if jitter_ms > 0 else ""
            run(f"tc qdisc add dev {interface} parent 1:{class_id} handle {handle_id}: netem delay {latency_ms}ms{jitter_arg}")
        else:
            run(f"tc qdisc add dev {interface} parent 1:{class_id} handle {handle_id}: sfq perturb 10")

        run(f"tc filter add dev {interface} parent 1: protocol ip prio {i*2+1} u32 match ip dst {ip}/32 flowid 1:{class_id}")
        run(f"tc filter add dev {interface} parent 1: protocol ip prio {i*2+2} u32 match ip src {ip}/32 flowid 1:{class_id}")


def cleanup_traffic_shaping(interface):
    run(f"tc qdisc del dev {interface} root", check=False)
    run(f"iptables -t nat -D POSTROUTING -o {interface} -j MASQUERADE", check=False)
    run(f"iptables -D FORWARD -i {interface} -o {interface} -j ACCEPT", check=False)
    run(f"iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT", check=False)
