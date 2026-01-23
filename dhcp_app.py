import argparse
import ipaddress
import json
import socket
import struct
import time


BOOTREQUEST = 1
BOOTREPLY = 2

DHCPDISCOVER = 1
DHCPREQUEST = 3
DHCPDECLINE = 4
DHCPRELEASE = 7

MAGIC_COOKIE = b"\x63\x82\x53\x63"


def _mac_to_str(mac_bytes):
    return ":".join(f"{b:02x}" for b in mac_bytes)


def parse_options(raw):
    options = {}
    idx = 0
    while idx < len(raw):
        code = raw[idx]
        idx += 1
        if code == 255:
            break
        if code == 0:
            continue
        if idx >= len(raw):
            break
        length = raw[idx]
        idx += 1
        value = raw[idx : idx + length]
        idx += length
        options[code] = value
    return options


def build_options(options):
    parts = []
    for code, value in options:
        if value is None:
            continue
        parts.append(struct.pack("BB", code, len(value)) + value)
    parts.append(b"\xff")
    return b"".join(parts)


class LeaseManager:
    def __init__(self, pool_start, pool_end, lease_time):
        self.pool_start = ipaddress.ip_address(pool_start)
        self.pool_end = ipaddress.ip_address(pool_end)
        self.lease_time = int(lease_time)
        self.leases = {}  # mac -> (ip, expiry)

    def _iter_pool(self):
        current = int(self.pool_start)
        end = int(self.pool_end)
        while current <= end:
            yield ipaddress.ip_address(current)
            current += 1

    def _is_available(self, ip_addr):
        now = time.time()
        for _, (lease_ip, expiry) in self.leases.items():
            if lease_ip == ip_addr and expiry > now:
                return False
        return True

    def allocate(self, mac, requested_ip=None):
        now = time.time()
        if mac in self.leases:
            ip_addr, expiry = self.leases[mac]
            if expiry > now:
                return ip_addr
        if requested_ip:
            try:
                ip_addr = ipaddress.ip_address(requested_ip)
                if self.pool_start <= ip_addr <= self.pool_end and self._is_available(ip_addr):
                    self.leases[mac] = (ip_addr, now + self.lease_time)
                    return ip_addr
            except ValueError:
                pass
        for ip_addr in self._iter_pool():
            if self._is_available(ip_addr):
                self.leases[mac] = (ip_addr, now + self.lease_time)
                return ip_addr
        return None


def build_reply(request, yiaddr, server_ip, options):
    op, htype, hlen, hops, xid, secs, flags = struct.unpack("!BBBBIHH", request[:12])
    ciaddr = request[12:16]
    chaddr = request[28:28 + 16]
    sname = b"\x00" * 64
    file_field = b"\x00" * 128
    pkt = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        BOOTREPLY,
        htype,
        hlen,
        hops,
        xid,
        secs,
        flags,
        ciaddr,
        socket.inet_aton(str(yiaddr)),
        socket.inet_aton(server_ip),
        b"\x00\x00\x00\x00",
        chaddr,
        sname,
        file_field,
    )
    return pkt + MAGIC_COOKIE + options


def load_config(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def get_local_ipv4s():
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_DGRAM):
            ips.add(info[4][0])
    except socket.gaierror:
        pass
    ips.add("127.0.0.1")
    return sorted(ips)


def main():
    parser = argparse.ArgumentParser(description="Simple DHCP server for IPMI access.")
    parser.add_argument("--config", default="config.json", help="Path to config file.")
    args = parser.parse_args()

    config = load_config(args.config)
    bind_ip = config["bind_ip"]
    server_ip = config["server_ip"]
    lease_time = int(config.get("lease_time_seconds", 3600))
    pool_start = config["pool_start"]
    pool_end = config["pool_end"]
    subnet_mask = socket.inet_aton(config["subnet_mask"])
    router = socket.inet_aton(config["router"])
    dns = socket.inet_aton(config["dns"])

    lease_manager = LeaseManager(pool_start, pool_end, lease_time)

    local_ips = get_local_ipv4s()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((bind_ip, 67))
    except OSError as exc:
        if getattr(exc, "winerror", None) == 10049:
            print(f"bind_ip {bind_ip} is not assigned to this host.")
            print("Update config.json to one of: " + ", ".join(local_ips))
            print("Or use 0.0.0.0 to bind all interfaces.")
        raise

    print(f"DHCP server listening on {bind_ip}:67")
    print(f"Pool {pool_start} - {pool_end}")

    while True:
        data, addr = sock.recvfrom(4096)
        if len(data) < 240 or data[236:240] != MAGIC_COOKIE:
            continue
        options = parse_options(data[240:])
        msg_type = options.get(53, b"\x00")
        if not msg_type:
            continue

        chaddr = data[28:44]
        hlen = data[2]
        mac = _mac_to_str(chaddr[:hlen])

        if msg_type == bytes([DHCPDISCOVER]):
            requested_ip = None
            yiaddr = lease_manager.allocate(mac, requested_ip)
            if not yiaddr:
                continue
            reply_options = build_options([
                (53, bytes([2])),
                (54, socket.inet_aton(server_ip)),
                (51, struct.pack("!I", lease_time)),
                (1, subnet_mask),
                (3, router),
                (6, dns),
            ])
            reply = build_reply(data, yiaddr, server_ip, reply_options)
            sock.sendto(reply, ("255.255.255.255", 68))
            print(f"OFFER {yiaddr} to {mac}")
            continue

        if msg_type == bytes([DHCPREQUEST]):
            requested = options.get(50)
            requested_ip = socket.inet_ntoa(requested) if requested else None
            yiaddr = lease_manager.allocate(mac, requested_ip)
            if not yiaddr:
                continue
            reply_options = build_options([
                (53, bytes([5])),
                (54, socket.inet_aton(server_ip)),
                (51, struct.pack("!I", lease_time)),
                (1, subnet_mask),
                (3, router),
                (6, dns),
            ])
            reply = build_reply(data, yiaddr, server_ip, reply_options)
            sock.sendto(reply, ("255.255.255.255", 68))
            print(f"ACK {yiaddr} to {mac}")
            continue

        if msg_type == bytes([DHCPDECLINE]) or msg_type == bytes([DHCPRELEASE]):
            print(f"Ignoring DHCP message type {msg_type[0]} from {mac}")


if __name__ == "__main__":
    main()
