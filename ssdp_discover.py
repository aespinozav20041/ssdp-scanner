import argparse
import json
from datetime import datetime
from scapy.all import Raw, send, sniff
from scapy.layers.inet import IP, UDP
import socket

"""
ssdp_discover.py
Discover devices announcing via SSDP (UPnP) on the local network and
do a small TCP connect probe on common camera ports (80, 554, 8000, 8080).
"""

MCAST_ADDR = "239.255.255.250"
MCAST_PORT = 1900
SSDP_PAYLOAD = "\r\n".join([
    "M-SEARCH * HTTP/1.1",
    f"HOST: {MCAST_ADDR}:{MCAST_PORT}",
    "MAN: \"ssdp:discover\"",
    "MX: 2",
    "ST: ssdp:all",
    "",
    ""
]).encode("utf-8")

COMMON_PORTS = [80, 554, 8000, 8080]  # HTTP RTSP

def send_ssdp(iface=None, timeout=2):
    """Send M-SEARCH and sniff replies for timeout seconds."""
    # Send m-search
    send(IP(dst=MCAST_ADDR)/UDP(dport=MCAST_PORT)/Raw(load=SSDP_PAYLOAD), iface=iface, verbose=0)
    # Sniff UDP responses 
    replies = sniff(filter="udp and src port 1900", timeout=timeout, iface=iface)
    results = []
    for p in replies:
        try:
            raw = bytes(p[Raw].load).decode('utf-8', errors='ignore')
        except Exception:
            raw = repr(p[Raw].load)
        src_ip = p[IP].src if IP in p else p.src
        results.append({'ip': src_ip, 'raw': raw})
    return results

def simple_port_check(ip, ports=COMMON_PORTS, timeout=1.0):
    """Try to connect TCP to ports; return list of open ports."""
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            open_ports.append(port)
        except Exception:
            pass
    return open_ports

def parse_ssdp_raw(raw):
    """Parse SSDP/HTTP-style response headers into a dict."""
    lines = raw.splitlines()
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().upper()] = v.strip()
    return headers

def main(args):
    out = {'generated_at': datetime.utcnow().isoformat() + 'Z', 'iface': args.iface, 'hosts': []}
    print(f"[+] Sending SSDP M-SEARCH on iface={args.iface}, waiting {args.timeout}s for replies...")
    replies = send_ssdp(iface=args.iface, timeout=args.timeout)
    seen = {}
    for r in replies:
        ip = r['ip']
        raw = r['raw']
        headers = parse_ssdp_raw(raw)
        # deduplicate by ip + USN 
        key = ip + '|' + headers.get('USN', '')
        if key in seen:
            continue
        seen[key] = True
        host = {'ip': ip, 'ssdp_raw': raw, 'ssdp_headers': headers}
        host['open_ports'] = simple_port_check(ip, ports=args.ports, timeout=args.port_timeout)
        host['location'] = headers.get('LOCATION')
        host['server'] = headers.get('SERVER')
        out['hosts'].append(host)

    print(f"[+] Collected {len(out['hosts'])} host(s).")
    # JSON output
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(out, f, indent=2)
        print(f"[+] Written results to {args.output}")
    else:
        print(json.dumps(out, indent=2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSDP discovery")
    parser.add_argument("-i", "--iface", help="Network interface to use (default: automatic)", default=None)
    parser.add_argument("-t", "--timeout", help="SSDP wait timeout seconds", type=int, default=5)
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=COMMON_PORTS,
                        help="Port list to probe (default: 80 554 8000 8080)")
    parser.add_argument("--port-timeout", type=float, default=0.8, help="TCP connect timeout per port")
    parser.add_argument("-o", "--output", help="Output JSON filename (optional)", default=None)
    args = parser.parse_args()
    main(args)
