"""CLI y puente JSON de TrabaMap. Requiere Nmap instalado en el sistema."""
import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from core.scanner import run_scan, find_nmap, nmap_version, ScanError
from core.explainer import enrich
from core import policy

APP_NAME = "TrabaMap"
VERSION = "1.0.1"
REPORTS = Path(os.environ.get("TRABAMAP_REPORTS", Path(__file__).parent / "reports"))

def save_report(result: dict) -> str:
    REPORTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S-%f")
    safe = re.sub(r"[^a-zA-Z0-9.-]", "_", result["target"])[:60]
    name = f"{stamp}-{safe}.json"
    raw_xml = result.pop("raw_xml", "")
    if raw_xml:
        xml_name = name[:-5] + ".xml"
        (REPORTS / xml_name).write_text(raw_xml, encoding="utf-8")
        result["raw_xml_file"] = xml_name
    (REPORTS / name).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return name

def report_dir() -> Path:
    return Path(os.environ.get("TRABAMAP_REPORTS", REPORTS))

def run(target: str, options: dict, progress=None) -> dict:
    return enrich(run_scan(target, options, progress))

def main():
    parser = argparse.ArgumentParser(prog="tmap", description="Explora puertos de equipos propios o autorizados.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Escanear un equipo propio o autorizado")
    scan.add_argument("target")
    group = scan.add_mutually_exclusive_group()
    group.add_argument("--rapido", action="store_true", help="Revisa los 1000 puertos más comunes")
    group.add_argument("--completo", action="store_true", help="Revisa los 65535 puertos TCP")
    scan.add_argument("--guardar", action="store_true", help="Guarda un reporte JSON")
    sub.add_parser("help", help="Mostrar la ayuda")
    sub.add_parser("version"); sub.add_parser("about")
    internal = sub.add_parser("desktop-scan")
    internal.add_argument("target"); internal.add_argument("options_json")
    sub.add_parser("system-json")
    sub.add_parser("reports-json")
    sub.add_parser("export-xlsx-stdin", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.command == "help": parser.print_help(); return 0
        if args.command == "version": print(f"{APP_NAME} {VERSION} | Nmap {nmap_version()}"); return 0
        if args.command == "about": print("TrabaMap explica los puertos abiertos detectados por Nmap. Escanea solo sistemas propios o con autorización."); return 0
        if args.command == "system-json":
            import socket
            addresses = []
            try:
                for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                    address = info[4][0]
                    if not address.startswith("127.") and address not in addresses: addresses.append(address)
            except OSError: pass
            print(json.dumps({"hostname": socket.gethostname(), "addresses": addresses, "local_ip": addresses[0] if addresses else "127.0.0.1", "nmap": nmap_version(), "nmap_path": find_nmap(), "engine": "nmap" if find_nmap() and not os.environ.get("TRABAMAP_FORCE_BUILTIN") else "integrado", "policy": policy.describe()}, ensure_ascii=False)); return 0
        if args.command == "reports-json":
            folder = report_dir(); folder.mkdir(parents=True, exist_ok=True)
            rows = []
            for f in sorted(folder.glob("*.json"), reverse=True)[:100]:
                try:
                    d = json.loads(f.read_text(encoding="utf-8"))
                    open_ports = sorted({f"{p.get('port')}/{p.get('protocol', 'tcp')}" for h in d.get("hosts", []) for p in h.get("ports", []) if p.get("state") == "open"})
                    rows.append({"name": f.name, "target": d.get("target", ""), "date": d.get("created_at", ""), "summary": d.get("summary", {}), "open_ports": open_ports})
                except (OSError, ValueError): continue
            print(json.dumps(rows, ensure_ascii=False)); return 0
        if args.command == "export-xlsx-stdin":
            from core.xlsx_exporter import export_xlsx
            report = json.load(sys.stdin)
            filename = export_xlsx(report, report_dir())
            print(json.dumps({"name": filename}, ensure_ascii=False)); return 0
        if args.command == "desktop-scan":
            target = args.target
            options = json.loads(args.options_json)
            def progress(event):
                print(json.dumps({"event": "progress", **event}, ensure_ascii=False), flush=True)
            result = run(target, options, progress); result["created_at"] = datetime.now().astimezone().isoformat(timespec="milliseconds"); result["options"] = options
            if options.get("ephemeral"):
                result.pop("raw_xml", None)  # análisis auxiliar: no se guarda en el historial
            else:
                result["report_file"] = save_report(result)
            result.pop("raw_xml", None)
            print(json.dumps(result, ensure_ascii=False)); return 0
        options = {"ports": "all" if args.completo else "common", "scan_type": "connect", "service_detection": True, "timing": 3, "skip_discovery": False}
        result = run(args.target, options)
        if args.guardar: saved = save_report(result)
        result.pop("raw_xml", None)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.guardar: print(f"\nReporte guardado: {saved}")
        return 0
    except ScanError as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False) if args.command in ("desktop-scan", "reports-json") else f"Error: {exc}", file=sys.stderr)
        return 1
    except (ValueError, TypeError, OSError) as exc:
        print(json.dumps({"error": f"Configuración de escaneo inválida: {exc}"}, ensure_ascii=False), file=sys.stderr)
        return 1

if __name__ == "__main__": raise SystemExit(main())
