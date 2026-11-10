"""Adaptador estructurado de Nmap. No usa shell y conserva el XML original para analizarlo."""
import os
import ipaddress
import re
import shlex
import shutil
import subprocess
import threading
import xml.etree.ElementTree as ET
from pathlib import Path

from core import policy


class ScanError(RuntimeError):
    pass


def _split_nmap_args(value: str) -> list[str]:
    # Keep Windows path separators while honoring quoted values; no shell is involved.
    lexer = shlex.shlex(value, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    lexer.escape = ""
    return list(lexer)


def find_nmap() -> str | None:
    override = os.environ.get("TRABAMAP_NMAP")
    if override and Path(override).is_file():
        return override
    found = shutil.which("nmap")
    if found:
        return found
    if os.name == "nt":
        for candidate in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"):
            if Path(candidate).is_file():
                return candidate
    return None


def nmap_version() -> str:
    binary = find_nmap()
    if not binary:
        return "No detectado"
    try:
        p = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=8, check=False)
        if p.returncode != 0 or not p.stdout:
            return "No disponible"
        match = re.search(r"\bversion\s+([0-9][\w.]*)", p.stdout.splitlines()[0], re.IGNORECASE)
        return match.group(1) if match else "No disponible"
    except (OSError, subprocess.TimeoutExpired):
        return "No disponible"


def _build_command(binary: str, target: str, options: dict) -> list[str]:
    # Arguments are passed as argv (never through a shell); XML stdout stays reserved for the app.
    args = [binary, "--reason", "-oX", "-", "--stats-every", "2s", "-v"]
    dns_mode = options.get("dns_mode", "off")
    if dns_mode == "off": args.append("-n")
    elif dns_mode == "force": args.append("-R")
    elif dns_mode != "resolve": raise ScanError("Selecciona una opción DNS válida.")
    scan_type = options.get("scan_type", "connect")
    scan_flags = {
        "ping": ["-sn"], "list": ["-sL"], "connect": ["-sT"], "syn": ["-sS"], "udp": ["-sU"], "idle": [],
        "both": ["-sS", "-sU"], "ack": ["-sA"], "window": ["-sW"], "maimon": ["-sM"], "fin": ["-sF"],
        "null": ["-sN"], "xmas": ["-sX"], "sctp": ["-sY"], "sctp_cookie": ["-sZ"], "ip_proto": ["-sO"],
    }
    if scan_type not in scan_flags:
        raise ScanError("Selecciona un tipo de escaneo Nmap válido.")
    args += scan_flags[scan_type]

    address_families = set()
    for item in target.split():
        try:
            address_families.add(ipaddress.ip_network(item, strict=False).version)
        except ValueError:
            continue
    if len(address_families) > 1:
        raise ScanError("Separa las direcciones IPv4 e IPv6 en escaneos distintos.")
    if options.get("ipv6") and address_families == {4}:
        raise ScanError("El modo IPv6 está activo, pero el objetivo indicado es IPv4.")
    if address_families == {6} or options.get("ipv6"):
        args += ["-6"]

    if scan_type == "idle":
        raise ScanError("La política de seguridad de TrabaMap no permite el escaneo idle: usa un equipo ajeno como intermediario.")

    ports = options.get("ports", "common")
    if scan_type not in ("ping", "list", "ip_proto"):
        if ports == "common": args += ["--top-ports", "1000"]
        elif ports == "top100": args += ["--top-ports", "100"]
        elif ports == "fast": args += ["-F"]
        elif ports == "top":
            count = int(options.get("top_port_count", 1000))
            if not 1 <= count <= 65535: raise ScanError("El número de puertos debe estar entre 1 y 65.535.")
            args += ["--top-ports", str(count)]
        elif ports == "all": args += ["-p-"]
        elif ports == "custom":
            value = str(options.get("custom_ports", ""))
            if not value or not re.fullmatch(r"[0-9,TUS:,-]+", value) or "--" in value:
                raise ScanError("Escribe puertos válidos, por ejemplo 22,80,443 o 1-1024.")
            args += ["-p", value]
        else:
            raise ScanError("Selecciona un rango de puertos válido.")

    if scan_type not in ("ping", "list") and options.get("skip_discovery", False): args += ["-Pn"]
    if options.get("aggressive"):
        if scan_type not in ("connect", "syn", "udp", "both", "sctp"):
            raise ScanError("El perfil -A requiere TCP Connect, SYN, UDP o SCTP INIT.")
        args += ["-A"]
    else:
        can_detect_services = scan_type in ("connect", "syn", "udp", "both", "sctp")
        can_detect_os = scan_type not in ("ping", "list", "ip_proto", "idle")
        if options.get("service_detection") and can_detect_services: args += ["-sV"]
        if options.get("version_intensity") is not None and options.get("service_detection") and can_detect_services:
            intensity = int(options["version_intensity"])
            if not 0 <= intensity <= 9: raise ScanError("La intensidad de detección debe estar entre 0 y 9.")
            args += ["--version-intensity", str(intensity)]
        if options.get("os_detection") and can_detect_os: args += ["-O"]
        if options.get("os_guess") and options.get("os_detection") and can_detect_os: args += ["--osscan-guess"]
        if options.get("os_scan_limit") and options.get("os_detection") and can_detect_os: args += ["--osscan-limit"]
        scripts = options.get("scripts", "off")
        if scripts != "off":
            if scripts == "default": args += ["-sC"]
            elif scripts == "vuln":
                # Se excluyen las comprobaciones que pueden tumbar o explotar el servicio revisado.
                args += ["--script", policy.SAFE_VULN_EXPRESSION]
            elif scripts in ("safe", "discovery"):
                args += ["--script", scripts]
            else: raise ScanError("Selecciona una categoría NSE permitida desde la interfaz.")
        if options.get("traceroute"): args += ["--traceroute"]
    timing = int(options.get("timing", 3))
    if not 0 <= timing <= 5: raise ScanError("El tiempo de escaneo debe estar entre 0 y 5.")
    args += [f"-T{timing}"]

    if options.get("sequential_ports") and scan_type not in ("ping", "list", "ip_proto"):
        args.append("-r")
    custom_args = str(options.get("custom_args", "")).strip()
    if len(custom_args) > 2000:
        raise ScanError("Los parámetros avanzados no pueden superar 2.000 caracteres.")
    if custom_args:
        try:
            extra = _split_nmap_args(custom_args)
        except ValueError as exc:
            raise ScanError(f"Revisa las comillas de los parámetros avanzados: {exc}") from exc
        try:
            policy.check_extra_args(extra)
        except policy.PolicyError as exc:
            raise ScanError(str(exc)) from exc
        if len(extra) > 128:
            raise ScanError("Usa como máximo 128 parámetros avanzados.")
        for token in extra:
            lowered = token.lower()
            extra_output = lowered.startswith(("-on", "-og", "-os"))
            if token in ("-h", "--help", "-V", "--version") or lowered == "--" or (lowered.startswith("-o") and not extra_output) or lowered == "--resume":
                raise ScanError(f"El parámetro {token} no está disponible porque TrabaMap necesita conservar el XML del escaneo.")
            if lowered in ("-sn", "-sl", "-st", "-ss", "-su", "-so", "-sa", "-sw", "-sm", "-sf", "-sn", "-sx", "-sy", "-sz", "-p", "-pn", "-6") or re.fullmatch(r"-t[0-5]", lowered):
                raise ScanError(f"Configura {token} con los controles del escaneo para evitar opciones duplicadas.")
        args += extra
    if target:
        args += ["--", *target.split()]
    return args


def _parse_xml(xml_text: str, target: str) -> dict:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScanError("Nmap devolvió un resultado XML incompleto o inválido.") from exc
    nmaprun = root if root.tag == "nmaprun" else root.find("./nmaprun")
    hosts = []
    def parse_script(node):
        details = []
        for elem in node.iter():
            if elem.tag == "elem" and elem.text and elem.text.strip():
                key = elem.get("key", "")
                details.append(f"{key}: {elem.text.strip()}" if key else elem.text.strip())
        output = node.get("output", "")
        evidence = " ".join([output, *details]).strip()
        positive = bool(re.search(r"\bVULNERABLE\b", evidence, re.IGNORECASE)) and not bool(re.search(r"\bNOT VULNERABLE\b", evidence, re.IGNORECASE))
        return {"id": node.get("id", ""), "output": output, "details": details, "possible_vulnerability": positive}
    for host in root.findall("host"):
        addresses = host.findall("address")
        address = next((a.get("addr") for a in addresses if a.get("addrtype") in ("ipv4", "ipv6")), target)
        mac_node = next((a for a in addresses if a.get("addrtype") == "mac"), None)
        mac = mac_node.get("addr", "") if mac_node is not None else ""
        mac_vendor = mac_node.get("vendor", "") if mac_node is not None else ""
        hostnames = [h.get("name", "") for h in host.findall("./hostnames/hostname") if h.get("name")]
        status = host.find("status")
        ports = []
        for port in host.findall("./ports/port"):
            state_node = port.find("state")
            if state_node is None: continue
            service = port.find("service")
            scripts = [parse_script(s) for s in port.findall("script")]
            ports.append({"port": int(port.get("portid", "0")), "protocol": port.get("protocol", "tcp"), "state": state_node.get("state", "unknown"), "reason": state_node.get("reason", ""), "service": service.get("name", "desconocido") if service is not None else "desconocido", "product": service.get("product", "") if service is not None else "", "version": service.get("version", "") if service is not None else "", "tunnel": service.get("tunnel", "") if service is not None else "", "cpe": [c.text for c in service.findall("cpe") if c.text] if service is not None else [], "scripts": scripts})
        extraports = [{"state": x.get("state", "unknown"), "count": int(x.get("count", "0"))} for x in host.findall("./ports/extraports")]
        os_matches = []
        for match in host.findall("./os/osmatch"):
            classes = []
            for item in match.findall("osclass"):
                classes.append({"type": item.get("type", ""), "vendor": item.get("vendor", ""), "family": item.get("osfamily", ""), "generation": item.get("osgen", ""), "accuracy": int(item.get("accuracy", "0")), "cpe": [c.text for c in item.findall("cpe") if c.text]})
            os_matches.append({"name": match.get("name", ""), "accuracy": int(match.get("accuracy", "0")), "classes": classes})
        host_scripts = [parse_script(s) for s in host.findall("./hostscript/script")]
        hops = [{"ttl": int(h.get("ttl", "0")), "address": h.get("ipaddr", ""), "rtt": h.get("rtt", ""), "hostname": h.get("host", "")} for h in host.findall("./trace/hop")]
        uptime = host.find("./uptime")
        distance = host.find("./distance")
        hosts.append({"address": address, "addresses": [{"type": a.get("addrtype", ""), "address": a.get("addr", ""), "vendor": a.get("vendor", "")} for a in addresses], "mac": mac, "mac_vendor": mac_vendor, "hostnames": hostnames, "hostname": hostnames[0] if hostnames else "", "status": status.get("state", "unknown") if status is not None else "unknown", "uptime_seconds": int(uptime.get("seconds", "0")) if uptime is not None else None, "last_boot": uptime.get("lastboot", "") if uptime is not None else "", "distance_hops": int(distance.get("value", "0")) if distance is not None else None, "ports": ports, "other_ports": extraports, "os_matches": os_matches, "scripts": host_scripts, "trace": hops})
    stats = root.find("./runstats/hosts")
    runstats = {"up": int(stats.get("up", "0")), "down": int(stats.get("down", "0")), "total": int(stats.get("total", "0"))} if stats is not None else {"up": len(hosts), "down": 0, "total": len(hosts)}
    network_scripts = [parse_script(s) for s in root.findall("./prescript/script") + root.findall("./postscript/script")]
    return {"target": target, "hosts": hosts, "network_scripts": network_scripts, "runstats": runstats, "nmap_version": nmaprun.get("version", "") if nmaprun is not None else "", "command": nmaprun.get("args", "") if nmaprun is not None else "", "elapsed_seconds": float(root.find("./runstats/finished").get("elapsed", "0")) if root.find("./runstats/finished") is not None else None}


PRIVILEGE_ERRORS = ("requires root privileges", "requires privileged", "root privileges", "npcap", "winpcap", "dnet: failed to open device", "only works if you are root", "operation not permitted", "failed to open device")
CONNECT_FALLBACK = {"syn": "connect", "both": "connect"}


def _needs_privileges(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(marker in lowered for marker in PRIVILEGE_ERRORS)


def _fallback_options(options: dict) -> dict | None:
    """Versión del mismo escaneo que funciona sin paquetes raw, o None si no existe equivalente."""
    scan_type = options.get("scan_type", "connect")
    raw_extras = options.get("os_detection") or options.get("aggressive") or options.get("traceroute")
    if scan_type not in CONNECT_FALLBACK and not (scan_type == "connect" and raw_extras):
        return None
    simpler = {**options, "scan_type": CONNECT_FALLBACK.get(scan_type, "connect"), "os_detection": False, "os_guess": False, "os_scan_limit": False, "traceroute": False}
    if options.get("aggressive"):
        # -A incluye detección de SO y traceroute; se conserva lo que sí funciona sin privilegios.
        simpler.update({"aggressive": False, "service_detection": True, "scripts": "default"})
    return simpler


def _execute(args: list[str], options: dict, progress=None) -> tuple[int, list[str], list[str]]:
    try:
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", bufsize=1)
        stdout_parts, stderr_parts = [], []
        def read_stdout():
            for line in process.stdout:
                stdout_parts.append(line)
        def read_stderr():
            for line in process.stderr:
                clean = line.strip()
                if clean:
                    stderr_parts.append(clean)
                    if progress:
                        match = re.search(r"About\s+(\d+(?:\.\d+)?)% done", clean, re.IGNORECASE)
                        progress({"message": clean[:240], "percent": round(float(match.group(1))) if match else None})
        out_thread = threading.Thread(target=read_stdout, daemon=True); err_thread = threading.Thread(target=read_stderr, daemon=True)
        out_thread.start(); err_thread.start()
        try: code = process.wait(timeout=int(options.get("timeout", 1800)))
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(); raise ScanError("El escaneo superó el límite de 30 minutos.")
        out_thread.join(); err_thread.join()
    except ScanError: raise
    except OSError as exc:
        raise ScanError(f"No se pudo ejecutar Nmap: {exc}") from exc
    return code, stdout_parts, stderr_parts


def run_scan(target: str, options: dict | str, progress=None) -> dict:
    binary = None if os.environ.get("TRABAMAP_FORCE_BUILTIN") else find_nmap()
    if isinstance(options, str):
        options = {"ports": "all" if options == "full" else "common", "scan_type": "connect", "service_detection": True, "timing": 3, "skip_discovery": False}
    target = target.strip()
    has_target_list = bool(re.search(r"(?:^|\s)(?:-iL|-iR|--inputfile|--randomtargets)(?:\s|$)", str(options.get("custom_args", "")), re.IGNORECASE))
    if not target and not has_target_list:
        raise ScanError("Escribe un objetivo o indica una lista Nmap con -iL en los parámetros avanzados.")
    if len(target) > 2048 or (target and (not re.fullmatch(r"[\w.%:/,!*-]+(?:\s+[\w.%:/,!*-]+)*", target) or target.startswith("-"))):
        raise ScanError("Escribe IPs, hostnames o redes válidos. Puedes indicar varios separados por espacios.")
    if not binary:
        # Sin Nmap: se validan igualmente las opciones y la política, y trabaja el motor integrado.
        _build_command("nmap", target, options)
        from core.builtin import run_builtin
        return run_builtin(target, options, progress)
    args = _build_command(binary, target, options)
    code, stdout_parts, stderr_parts = _execute(args, options, progress)
    fallback_note = ""
    if code != 0 and _needs_privileges("\n".join(stderr_parts)):
        # Sin Npcap o sin permisos de administrador los paquetes "raw" fallan: se repite con TCP Connect.
        simpler = _fallback_options(options)
        if simpler is not None:
            if progress:
                progress({"message": "Sin permisos para paquetes raw: repitiendo con TCP Connect…", "percent": None})
            options = simpler
            args = _build_command(binary, target, options)
            code, stdout_parts, stderr_parts = _execute(args, options, progress)
            fallback_note = "Este equipo no permitió paquetes raw (falta Npcap o permisos de administrador). TrabaMap repitió el análisis con TCP Connect, sin detección de sistema operativo ni traza de ruta."
    if code != 0:
        detail = stderr_parts[-1] if stderr_parts else "Nmap no pudo completar el escaneo."
        if _needs_privileges("\n".join(stderr_parts)):
            detail = "Este tipo de escaneo necesita Npcap y ejecutar TrabaMap como administrador. Prueba TCP Connect o el perfil Rápido."
        raise ScanError(detail)
    scan = _parse_xml("".join(stdout_parts), target)
    scan["scan_type"] = options.get("scan_type", "connect")
    scan["nmap_path"] = binary
    scan["nmap_command"] = shlex.join(args[1:])
    scan["raw_xml"] = "".join(stdout_parts)
    if fallback_note:
        scan["fallback_note"] = fallback_note
    return scan
