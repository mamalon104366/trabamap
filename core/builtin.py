"""Motor integrado de TrabaMap: funciona sin Nmap instalado.

Cubre lo esencial con la biblioteca estándar de Python: descubrir equipos (ping + tabla ARP) y
revisar puertos TCP por conexión. No detecta versiones, sistema operativo, UDP ni ejecuta scripts:
para eso hace falta Nmap. Devuelve el mismo formato que el adaptador de Nmap.
"""
import ipaddress
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.scanner import ScanError

MAX_HOSTS = 1024
# Puertos TCP más habituales, por orden de frecuencia aproximada.
COMMON_PORTS = [
    80, 443, 22, 21, 23, 25, 53, 110, 111, 135, 139, 143, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
    8443, 8000, 8008, 8888, 81, 88, 389, 465, 515, 548, 554, 587, 631, 636, 873, 902, 1433, 1521, 1883, 2049,
    2222, 2375, 2376, 3000, 3001, 3283, 5000, 5060, 5173, 5357, 5432, 5555, 5800, 5938, 5984, 5985, 5986, 6379, 6443, 7000,
    7680, 8001, 8002, 8009, 8060, 8081, 8883, 9000, 9090, 9100, 9200, 10000, 11211, 27017, 32400, 49152, 62078, 20, 69, 113,
    119, 179, 199, 427, 444, 464, 500, 512, 513, 514, 543, 544, 593, 646, 990, 1025, 1026, 1027, 1080, 1110,
    1720, 1900, 2000, 2001, 2121, 2717, 3128, 3986, 4899, 5009, 5051, 5101, 5190, 5631, 5666, 6000, 6001, 6646, 7070, 8031,
    8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8181, 8200, 8300, 8500, 8834, 9001, 9080, 9443, 9999, 10001, 49153,
]
SERVICE_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 515: "printer", 548: "afp",
    554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1521: "oracle",
    1883: "mqtt", 2049: "nfs", 3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5555: "adb", 5900: "vnc", 5985: "winrm",
    6379: "redis", 7000: "airplay", 8008: "http", 8009: "castv2", 8060: "roku", 8080: "http-proxy", 8443: "https-alt", 9100: "jetdirect",
    9200: "elasticsearch", 27017: "mongodb", 32400: "plex", 62078: "iphone-sync",
}
UNSUPPORTED = {"udp": "UDP", "both": "TCP+UDP", "ack": "ACK", "window": "Window", "maimon": "Maimon", "fin": "FIN", "null": "Null", "xmas": "Xmas",
               "sctp": "SCTP", "sctp_cookie": "SCTP", "ip_proto": "protocolos IP", "idle": "idle"}
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _expand_targets(target: str) -> list[str]:
    addresses: list[str] = []
    for token in target.split():
        try:
            network = ipaddress.ip_network(token, strict=False)
            hosts = [str(ip) for ip in (network.hosts() if network.num_addresses > 2 else network)]
        except ValueError:
            try:
                hosts = [socket.gethostbyname(token)]
            except OSError as exc:
                raise ScanError(f"No se pudo resolver “{token}”. El motor integrado acepta IPs, rangos CIDR y nombres de equipo.") from exc
        addresses.extend(hosts)
        if len(addresses) > MAX_HOSTS:
            raise ScanError(f"El motor integrado revisa como máximo {MAX_HOSTS} direcciones por escaneo.")
    return list(dict.fromkeys(addresses))


def _ping(address: str) -> bool:
    args = ["ping", "-n", "1", "-w", "700", address] if sys.platform == "win32" else ["ping", "-c", "1", "-W", "1", address]
    try:
        done = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=4, creationflags=NO_WINDOW, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0 and "ttl" in done.stdout.lower()


def _arp_table() -> dict[str, str]:
    try:
        done = subprocess.run(["arp", "-a"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=6, creationflags=NO_WINDOW, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    table = {}
    for ip, mac in re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})\)?\s+(?:at\s+)?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", done.stdout):
        mac = ":".join(part.zfill(2) for part in re.split(r"[:-]", mac)).upper()
        if mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") and not mac.startswith("01:00:5E"):
            table[ip] = mac
    return table


def _probe(address: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        return "filtered"


def _ports_for(options: dict) -> list[int]:
    choice = options.get("ports", "common")
    if choice == "all":
        return list(range(1, 65536))
    if choice in ("fast", "top100"):
        return COMMON_PORTS[:100]
    if choice == "top":
        return COMMON_PORTS[: max(1, min(int(options.get("top_port_count", 100)), len(COMMON_PORTS)))]
    if choice == "custom":
        ports: set[int] = set()
        for part in str(options.get("custom_ports", "")).replace("T:", "").split(","):
            if not part or part.startswith(("U:", "S:")):
                continue
            low, _, high = part.partition("-")
            try:
                start, end = int(low or 1), int(high or low or 65535)
            except ValueError as exc:
                raise ScanError("Escribe puertos válidos, por ejemplo 22,80,443 o 1-1024.") from exc
            if not 1 <= start <= end <= 65535:
                raise ScanError("Los puertos deben estar entre 1 y 65.535.")
            ports.update(range(start, end + 1))
        return sorted(ports)
    return COMMON_PORTS


def run_builtin(target: str, options: dict, progress=None) -> dict:
    started = time.time()
    scan_type = options.get("scan_type", "connect")
    if scan_type in UNSUPPORTED:
        raise ScanError(f"El escaneo {UNSUPPORTED[scan_type]} necesita Nmap. El motor integrado hace descubrimiento y puertos TCP; instala Nmap desde nmap.org para el resto.")
    addresses = _expand_targets(target.strip())
    if not addresses:
        raise ScanError("Escribe un objetivo: una IP, un nombre de equipo o un rango como 192.168.1.0/24.")
    notify = progress or (lambda event: None)
    skipped = [label for key, label in (("service_detection", "versiones de servicios"), ("os_detection", "sistema operativo"), ("aggressive", "modo -A"), ("traceroute", "traza de ruta")) if options.get(key)]
    if options.get("scripts", "off") != "off" or "--script" in str(options.get("custom_args", "")):
        skipped.append("scripts NSE")

    alive: set[str] = set()
    discovery_only = scan_type in ("ping", "list")
    if scan_type == "list":
        alive = set(addresses)
    elif len(addresses) == 1 or options.get("skip_discovery"):
        alive = set(addresses)
    else:
        with ThreadPoolExecutor(max_workers=64) as pool:
            futures = {pool.submit(_ping, address): address for address in addresses}
            for count, future in enumerate(as_completed(futures), 1):
                if future.result():
                    alive.add(futures[future])
                if count % 16 == 0 or count == len(addresses):
                    notify({"message": f"Motor integrado: buscando equipos ({count} de {len(addresses)})", "percent": round(count * (100 if discovery_only else 30) / len(addresses))})
    arp = _arp_table()
    wanted = set(addresses)
    alive.update(ip for ip in arp if ip in wanted)  # equipos que ignoran el ping pero respondieron al ARP

    hosts = []
    ordered = sorted(alive, key=lambda ip: tuple(int(part) for part in ip.split(".")) if "." in ip else (0,))
    ports = [] if discovery_only else _ports_for(options)
    total = max(1, len(ordered) * max(1, len(ports)))
    done_count = 0
    timeout = 0.35 if len(ports) > 2000 else 0.8
    for address in ordered:
        results = []
        if ports:
            with ThreadPoolExecutor(max_workers=256 if len(ports) > 2000 else 96) as pool:
                futures = {pool.submit(_probe, address, port, timeout): port for port in ports}
                for future in as_completed(futures):
                    state = future.result()
                    done_count += 1
                    if state == "open" or len(ports) <= 64:
                        results.append({"port": futures[future], "protocol": "tcp", "state": state, "reason": {"open": "syn-ack", "closed": "conn-refused", "filtered": "no-response"}[state],
                                        "service": SERVICE_NAMES.get(futures[future], "desconocido"), "product": "", "version": "", "tunnel": "", "cpe": [], "scripts": []})
                    if done_count % 400 == 0:
                        notify({"message": f"Motor integrado: revisando puertos de {address}", "percent": min(99, 30 + round(done_count * 70 / total))})
        try:
            hostname = socket.gethostbyaddr(address)[0] if len(ordered) <= 64 else ""
        except OSError:
            hostname = ""
        if hostname == address:
            hostname = ""
        hosts.append({"address": address, "addresses": [], "mac": arp.get(address, ""), "mac_vendor": "", "hostnames": [hostname] if hostname else [], "hostname": hostname,
                      "status": "up", "uptime_seconds": None, "last_boot": "", "distance_hops": None, "ports": sorted(results, key=lambda item: item["port"]),
                      "other_ports": [], "os_matches": [], "scripts": [], "trace": []})

    note = "Analizado con el motor integrado de TrabaMap porque Nmap no está instalado: descubre equipos y revisa puertos TCP."
    if skipped:
        note += " Se omitió: " + ", ".join(skipped) + ". Instala Nmap para obtenerlo."
    return {"target": target, "hosts": hosts, "network_scripts": [], "runstats": {"up": len(hosts), "down": len(addresses) - len(hosts), "total": len(addresses)},
            "nmap_version": "", "engine": "integrado", "command": "", "nmap_command": "", "elapsed_seconds": round(time.time() - started, 2),
            "scan_type": scan_type, "fallback_note": note}
