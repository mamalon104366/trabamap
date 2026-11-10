"""Crea informes de red legibles en Excel con la biblioteca estándar de Python."""
from __future__ import annotations

import json
import math
import re
import zipfile
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET

MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
ET.register_namespace("", MAIN_NS)
ET.register_namespace("r", REL_NS)


def _clean_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    text = str(value)
    text = re.sub(r"\bNmap\b", "el análisis", text, flags=re.IGNORECASE)
    text = re.sub(r"\bdescubrimiento\b", "respuesta", text, flags=re.IGNORECASE)
    return text[:32760]


def _column_name(index: int) -> str:
    result = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        result = chr(65 + remainder) + result
    return result


def _sheet(name: str, widths: list[float], *, freeze_rows: int = 0, autofilter: str = "") -> dict:
    return {"name": name, "widths": widths, "freeze_rows": freeze_rows, "autofilter": autofilter, "rows": [], "merges": [], "tab_color": "71549A"}


def _row(sheet: dict, values=None, *, styles=None, height: float | None = None) -> None:
    values = list(values or [])
    styles = list(styles or [0] * len(values))
    if len(styles) < len(values):
        styles.extend([0] * (len(values) - len(styles)))
    sheet["rows"].append({"values": values, "styles": styles, "height": height})


def _merge(sheet: dict, ref: str) -> None:
    sheet["merges"].append(ref)


def _cell(row_node, address: str, value, style: int = 0) -> None:
    if value is None or value == "":
        return
    attrs = {"r": address, "s": str(style)}
    if isinstance(value, bool):
        value = "Sí" if value else "No"
    if isinstance(value, (int, float)) and math.isfinite(value):
        cell = ET.SubElement(row_node, f"{{{MAIN_NS}}}c", {**attrs, "t": "n"})
        ET.SubElement(cell, f"{{{MAIN_NS}}}v").text = str(value)
        return
    cell = ET.SubElement(row_node, f"{{{MAIN_NS}}}c", {**attrs, "t": "inlineStr"})
    inline = ET.SubElement(cell, f"{{{MAIN_NS}}}is")
    ET.SubElement(inline, f"{{{MAIN_NS}}}t", {"{http://www.w3.org/XML/1998/namespace}space": "preserve"}).text = _clean_text(value)


def _worksheet(sheet: dict) -> bytes:
    rows = sheet["rows"]
    root = ET.Element(f"{{{MAIN_NS}}}worksheet")
    properties = ET.SubElement(root, f"{{{MAIN_NS}}}sheetPr")
    ET.SubElement(properties, f"{{{MAIN_NS}}}tabColor", {"rgb": f"FF{sheet.get('tab_color', '71549A')}"})
    maximum_columns = max(len(sheet["widths"]), max((len(row["values"]) for row in rows), default=1))
    maximum_columns = max(1, maximum_columns)
    end_ref = f"{_column_name(maximum_columns)}{max(1, len(rows))}"
    ET.SubElement(root, f"{{{MAIN_NS}}}dimension", {"ref": f"A1:{end_ref}"})
    views = ET.SubElement(root, f"{{{MAIN_NS}}}sheetViews")
    view = ET.SubElement(views, f"{{{MAIN_NS}}}sheetView", {"showGridLines": "0", "workbookViewId": "0"})
    freeze_rows = int(sheet.get("freeze_rows") or 0)
    if freeze_rows:
        split_cell = f"A{freeze_rows + 1}"
        ET.SubElement(view, f"{{{MAIN_NS}}}pane", {"ySplit": str(freeze_rows), "topLeftCell": split_cell, "activePane": "bottomLeft", "state": "frozen"})
        ET.SubElement(view, f"{{{MAIN_NS}}}selection", {"pane": "bottomLeft", "activeCell": split_cell, "sqref": split_cell})
    else:
        ET.SubElement(view, f"{{{MAIN_NS}}}selection", {"activeCell": "A1", "sqref": "A1"})
    ET.SubElement(root, f"{{{MAIN_NS}}}sheetFormatPr", {"defaultRowHeight": "21"})
    columns = ET.SubElement(root, f"{{{MAIN_NS}}}cols")
    for index, width in enumerate(sheet["widths"], 1):
        ET.SubElement(columns, f"{{{MAIN_NS}}}col", {"min": str(index), "max": str(index), "width": str(width), "customWidth": "1"})
    data = ET.SubElement(root, f"{{{MAIN_NS}}}sheetData")
    for row_number, row_data in enumerate(rows, 1):
        attrs = {"r": str(row_number)}
        if row_data.get("height"):
            attrs.update({"ht": str(row_data["height"]), "customHeight": "1"})
        row_node = ET.SubElement(data, f"{{{MAIN_NS}}}row", attrs)
        for column, value in enumerate(row_data["values"], 1):
            style = row_data["styles"][column - 1] if column - 1 < len(row_data["styles"]) else 0
            _cell(row_node, f"{_column_name(column)}{row_number}", value, style)
    if sheet.get("autofilter"):
        ET.SubElement(root, f"{{{MAIN_NS}}}autoFilter", {"ref": sheet["autofilter"]})
    if sheet["merges"]:
        merges = ET.SubElement(root, f"{{{MAIN_NS}}}mergeCells", {"count": str(len(sheet["merges"]))})
        for ref in sheet["merges"]:
            ET.SubElement(merges, f"{{{MAIN_NS}}}mergeCell", {"ref": ref})
    ET.SubElement(root, f"{{{MAIN_NS}}}pageMargins", {"left": "0.35", "right": "0.35", "top": "0.55", "bottom": "0.55", "header": "0.2", "footer": "0.2"})
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _no_prefix_xml(element, namespace: str) -> bytes:
    data = ET.tostring(element, encoding="utf-8", xml_declaration=True).decode("utf-8")
    prefix_match = re.search(rf"xmlns:(\w+)=[\"']{re.escape(namespace)}[\"']", data)
    if not prefix_match:
        return data.encode("utf-8")
    prefix = prefix_match.group(1)
    data = data.replace(f"xmlns:{prefix}=\"{namespace}\"", f"xmlns=\"{namespace}\"")
    data = data.replace(f"<{prefix}:", "<").replace(f"</{prefix}:", "</")
    return data.encode("utf-8")


def _format_time(report: dict) -> str:
    raw = report.get("created_at")
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        parsed = parsed.astimezone()
        months = ("enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre")
        hour = parsed.hour % 12 or 12
        meridian = "a. m." if parsed.hour < 12 else "p. m."
        return f"{parsed.day} de {months[parsed.month - 1]} de {parsed.year} a las {hour}:{parsed.minute:02d} {meridian}"
    except (ValueError, TypeError):
        return _format_time({"created_at": datetime.now().astimezone().isoformat()})


def _bytes_gb(value) -> str:
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return "No disponible"
    return f"{amount / (1024 ** 3):.1f} GB" if amount > 0 else "No disponible"


def _open_tcp(host: dict) -> list[dict]:
    return [port for port in host.get("ports") or [] if str(port.get("protocol", "tcp")).lower() == "tcp" and port.get("state") == "open"]


def _host_name(host: dict) -> str:
    local = host.get("local_inventory") or {}
    return str(host.get("hostname") or next(iter(host.get("hostnames") or []), "") or local.get("computer_name") or "Equipo sin nombre anunciado")


def _os(host: dict) -> tuple[str, str]:
    local = host.get("local_inventory") or {}
    if local.get("os_name"):
        version = " · ".join(str(value) for value in (local.get("os_version"), local.get("os_build")) if value)
        return " · ".join(value for value in (local["os_name"], version) if value), "Leído en este equipo"
    matches = host.get("os_matches") or []
    if not matches:
        return "Sin dato confirmado", "No se obtuvo una huella suficiente"
    match = matches[0]
    name = match.get("name") or "Familia probable"
    return name, f"{match.get('accuracy', '—')}% de coincidencia estimada"


def _device_type(host: dict) -> str:
    local = host.get("local_inventory") or {}
    if local:
        return "Computador propio"
    evidence = " ".join([str(host.get("mac_vendor") or ""), str(host.get("hostname") or ""), " ".join(str(port.get("service") or "") + " " + str(port.get("product") or "") for port in host.get("ports") or [])]).lower()
    if re.search(r"router|gateway|access point|mitrastar|mikrotik|ubiquiti|tp-link|netgear", evidence):
        return "Equipo de red posible"
    if re.search(r"windows|microsoft-ds|netbios|msrpc", evidence):
        return "Computador posible"
    if re.search(r"motorola|xiaomi|redmi|samsung|huawei|honor|tecno|infinix|oppo|vivo|realme", str(host.get("mac_vendor") or ""), re.I):
        return "Fabricante de interfaz móvil posible"
    return "Dispositivo de red"


def _styles_xml() -> bytes:
    ns = MAIN_NS
    root = ET.Element(f"{{{ns}}}styleSheet")
    fonts = ET.SubElement(root, f"{{{ns}}}fonts", {"count": "12"})
    font_values = [
        ("Aptos", "11", "FF292530", False), ("Aptos Display", "19", "FFFFFFFF", True),
        ("Aptos", "10", "FFD9D3E2", False), ("Aptos", "12", "FFFFFFFF", True),
        ("Aptos", "10", "FFFFFFFF", True), ("Aptos", "10", "FF503B70", True),
        ("Aptos", "9", "FF503B70", True), ("Aptos", "21", "FF201C27", True),
        ("Aptos", "10", "FF9E3544", True), ("Aptos", "10", "FF6A4A8B", True),
        ("Aptos", "10", "FF466C5B", True), ("Aptos", "10", "FF4B4653", False),
    ]
    for name, size, color, bold in font_values:
        node = ET.SubElement(fonts, f"{{{ns}}}font")
        ET.SubElement(node, f"{{{ns}}}sz", {"val": size})
        ET.SubElement(node, f"{{{ns}}}name", {"val": name})
        ET.SubElement(node, f"{{{ns}}}color", {"rgb": color})
        if bold:
            ET.SubElement(node, f"{{{ns}}}b")
    fills = ET.SubElement(root, f"{{{ns}}}fills", {"count": "9"})
    ET.SubElement(fills, f"{{{ns}}}fill").append(ET.Element(f"{{{ns}}}patternFill", {"patternType": "none"}))
    fill_colors = ["FF201C27", "FF503B70", "FFF0EBF6", "FFF7F6F9", "FFFCEDEF", "FFF3EDF8", "FFEAF3EE", "FFECE9EF"]
    for color in fill_colors:
        fill = ET.SubElement(fills, f"{{{ns}}}fill")
        pattern = ET.SubElement(fill, f"{{{ns}}}patternFill", {"patternType": "solid"})
        ET.SubElement(pattern, f"{{{ns}}}fgColor", {"rgb": color})
        ET.SubElement(pattern, f"{{{ns}}}bgColor", {"indexed": "64"})
    borders = ET.SubElement(root, f"{{{ns}}}borders", {"count": "3"})
    ET.SubElement(borders, f"{{{ns}}}border")
    bottom = ET.SubElement(borders, f"{{{ns}}}border")
    ET.SubElement(bottom, f"{{{ns}}}bottom", {"style": "thin"}).append(ET.Element(f"{{{ns}}}color", {"rgb": "FFE5E1EA"}))
    header_border = ET.SubElement(borders, f"{{{ns}}}border")
    ET.SubElement(header_border, f"{{{ns}}}bottom", {"style": "medium"}).append(ET.Element(f"{{{ns}}}color", {"rgb": "FF71549A"}))
    cell_style_xfs = ET.SubElement(root, f"{{{ns}}}cellStyleXfs", {"count": "1"})
    ET.SubElement(cell_style_xfs, f"{{{ns}}}xf", {"numFmtId": "0", "fontId": "0", "fillId": "0", "borderId": "0"})
    cell_xfs = ET.SubElement(root, f"{{{ns}}}cellXfs", {"count": "15"})
    xf_specs = [
        (0, 0, 0, ""), (1, 1, 0, "wrapText=1"), (2, 1, 0, "wrapText=1"),
        (3, 1, 0, "wrapText=1"), (4, 2, 2, "wrapText=1"), (0, 0, 1, "wrapText=1"),
        (5, 3, 1, "wrapText=1"), (6, 3, 0, "horizontal=\"center\" vertical=\"center\""),
        (7, 4, 0, "horizontal=\"center\" vertical=\"center\""), (11, 4, 1, "wrapText=1"),
        (5, 0, 1, "wrapText=1"), (8, 5, 1, "horizontal=\"center\" vertical=\"center\""),
        (9, 6, 1, "horizontal=\"center\" vertical=\"center\""), (10, 7, 1, "horizontal=\"center\" vertical=\"center\""),
        (11, 8, 1, "horizontal=\"center\" vertical=\"center\""),
    ]
    for font_id, fill_id, border_id, alignment in xf_specs:
        xf = ET.SubElement(cell_xfs, f"{{{ns}}}xf", {"numFmtId": "0", "fontId": str(font_id), "fillId": str(fill_id), "borderId": str(border_id), "xfId": "0", "applyFont": "1", "applyFill": "1", "applyBorder": "1"})
        if alignment:
            attr = {}
            if "horizontal" in alignment:
                h = re.search(r'horizontal="([^"]+)"', alignment)
                if h:
                    attr["horizontal"] = h.group(1)
            if "vertical" in alignment:
                v = re.search(r'vertical="([^"]+)"', alignment)
                if v:
                    attr["vertical"] = v.group(1)
            if "wrapText" in alignment:
                attr["wrapText"] = "1"
            ET.SubElement(xf, f"{{{ns}}}alignment", attr)
    cell_styles = ET.SubElement(root, f"{{{ns}}}cellStyles", {"count": "1"})
    ET.SubElement(cell_styles, f"{{{ns}}}cellStyle", {"name": "Normal", "xfId": "0", "builtinId": "0"})
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _build_sheets(report: dict) -> list[dict]:
    hosts = [host for host in report.get("hosts") or [] if host.get("status") == "up"]
    ports = [(host, port) for host in hosts for port in _open_tcp(host)]
    risk_rank = {"muy alto": 0, "alto": 1, "medio": 2, "bajo": 3, "informativo": 4}
    ports.sort(key=lambda item: (risk_rank.get(str(item[1].get("risk") or "").lower(), 5), int(item[1].get("port") or 0)))
    high_risk = sum(1 for _, port in ports if str(port.get("risk") or "").lower() in {"alto", "muy alto"})
    mac_count = sum(1 for host in hosts if host.get("mac"))
    date_text = _format_time(report)
    local_host = next((host for host in hosts if host.get("local_inventory")), None)

    summary = _sheet("Resumen", [18, 15, 18, 15, 18, 15, 18, 15])
    _row(summary, ["Informe de equipos y puertos"], styles=[1], height=39); _merge(summary, "A1:H1")
    _row(summary, [f"Generado el {date_text} · Evidencia explicada en lenguaje sencillo"], styles=[2], height=29); _merge(summary, "A2:H2")
    _row(summary, [], height=12)
    _row(summary, ["EQUIPOS QUE RESPONDIERON", "", "PUERTOS TCP ABIERTOS", "", "DIRECCIONES MAC VISIBLES", "", "PUERTOS PARA REVISAR", ""], styles=[7, 0, 7, 0, 7, 0, 7, 0], height=25)
    for ref in ("A4:B4", "C4:D4", "E4:F4", "G4:H4"):
        _merge(summary, ref)
    _row(summary, [len(hosts), "", len(ports), "", mac_count, "", high_risk, ""], styles=[8, 0, 8, 0, 8, 0, 8, 0], height=40)
    for ref in ("A5:B5", "C5:D5", "E5:F5", "G5:H5"):
        _merge(summary, ref)
    _row(summary, [], height=12)
    _row(summary, ["Qué significa este resultado"], styles=[3], height=28); _merge(summary, "A7:H7")
    details = [
        ("1 · Empieza por Puertos TCP", f"Se encontraron {len(ports)} puertos TCP abiertos. Cada fila explica el servicio que respondió, el uso habitual y una acción concreta."),
        ("2 · Revisa el nivel de atención", f"{high_risk} puerto(s) tienen una prioridad alta según la guía del proyecto. Un puerto abierto no demuestra por sí solo que exista una vulnerabilidad."),
        ("3 · Identifica los equipos", f"{mac_count} de {len(hosts)} equipos informaron una dirección MAC. El fabricante se calcula por el prefijo y puede ser distinto a la marca del teléfono."),
        ("4 · Mira Equipo local", "Este informe incluye componentes y puertos locales del computador." if local_host else "La ficha de componentes del computador aparecerá cuando el propio equipo forme parte del informe."),
    ]
    for index, (label, explanation) in enumerate(details):
        start = 8 + index * 2
        _row(summary, [label, "", explanation], styles=[6, 0, 9], height=25)
        _row(summary, [], height=22)
        _merge(summary, f"A{start}:B{start}")
        _merge(summary, f"C{start}:H{start + 1}")
    _row(summary, [], height=9)
    _row(summary, ["Datos móviles y privacidad"], styles=[3], height=28); _merge(summary, "A17:H17")
    _row(summary, ["Android: la ficha detallada requiere que el dispositivo ya esté conectado y autorizado por ADB. iPhone/iPad: el inventario de hardware y sistema requiere un MDM existente y que el equipo esté inscrito. Si esa fuente no entregó datos, aquí no se adivinan versiones, RAM, aplicaciones ni nombres de usuario."], styles=[5], height=48)
    _merge(summary, "A18:H18")

    devices = _sheet("Equipos", [25, 17, 21, 31, 29, 27, 29, 17, 25, 45], freeze_rows=4)
    _row(devices, ["Equipos que respondieron"], styles=[1], height=39); _merge(devices, "A1:J1")
    _row(devices, ["Una fila por equipo. Los datos probables se distinguen de los datos leídos directamente en el computador local."], styles=[2], height=29); _merge(devices, "A2:J2")
    _row(devices, [], height=12)
    device_headers = ["Nombre o descripción", "Dirección IP", "Dirección MAC", "Fabricante de la interfaz", "Sistema operativo", "Origen / confianza", "Tipo probable", "Puertos TCP abiertos", "Nombre anunciado", "Nota para interpretar"]
    _row(devices, device_headers, styles=[4] * len(device_headers), height=36)
    for host in hosts:
        os_name, confidence = _os(host)
        local = host.get("local_inventory") or {}
        manufacturer = host.get("mac_vendor") or "No identificado"
        note = "Información consultada en este computador." if local else "El fabricante corresponde al adaptador de red; no confirma el modelo del equipo." if host.get("mac_vendor") else "El equipo no informó fabricante ni nombre durante este análisis."
        device_type = _device_type(host)
        identity = host.get("identity") or {}
        if identity and not local:
            # Identificación de TrabaMap (mDNS, UPnP, puertos firma, TTL): se exporta con su evidencia.
            brand_model = " · ".join(str(value) for value in (identity.get("brand"), identity.get("model")) if value)
            device_type = " — ".join(value for value in (str(identity.get("type") or device_type), brand_model) if value)
            if identity.get("os") and os_name == "Sin dato confirmado":
                os_name = str(identity["os"])
            confidence = str(identity.get("confidence") or confidence)
            reasons = [str(reason) for reason in (identity.get("reasons") or [])[:3]]
            if reasons:
                note = " ".join(reasons)
        _row(devices, [_host_name(host), host.get("address", ""), host.get("mac") or "No informada", manufacturer, os_name, confidence, device_type, len(_open_tcp(host)), ", ".join(host.get("hostnames") or []) or "Sin nombre DNS", note], styles=[5, 5, 5, 5, 5, 5, 5, 5, 5, 5], height=34)
    if not hosts:
        _row(devices, ["No se registraron equipos que respondieran en este análisis."], styles=[9], height=32); _merge(devices, "A5:J5")
    devices["autofilter"] = f"A4:J{max(4, len(devices['rows']))}"

    port_sheet = _sheet("Puertos TCP", [25, 18, 14, 22, 35, 48, 17, 46, 46], freeze_rows=4)
    _row(port_sheet, ["Puertos TCP abiertos"], styles=[1], height=39); _merge(port_sheet, "A1:I1")
    _row(port_sheet, ["El puerto es la puerta de red; el servicio es lo que respondió. La aplicación exacta puede requerir datos locales del equipo."], styles=[2], height=29); _merge(port_sheet, "A2:I2")
    _row(port_sheet, [], height=12)
    port_headers = ["Equipo", "Dirección IP", "Puerto TCP", "Servicio detectado", "Producto o aplicación", "Qué significa", "Atención", "Qué conviene revisar", "Cómo se obtuvo el nombre"]
    _row(port_sheet, port_headers, styles=[4] * len(port_headers), height=36)
    for host, port in ports:
        listener = next((item for item in (host.get("local_inventory") or {}).get("tcp_listeners") or [] if int(item.get("port") or -1) == int(port.get("port") or -2)), None)
        app_name = f"{listener.get('application') or 'Proceso sin nombre'} · PID {listener.get('pid')}" if listener else " ".join(str(value) for value in (port.get("product"), port.get("version")) if value) or port.get("application") or port.get("service") or "Servicio sin identificar"
        evidence = "Proceso y PID consultados en este computador." if listener else "El servicio anunció este producto o versión; podría no ser el proceso exacto." if port.get("product") or port.get("version") else "El puerto sugiere este servicio; no confirma qué proceso lo ejecuta."
        description = _clean_text(port.get("description")) or "Un servicio respondió en este puerto."
        recommendation = _clean_text(port.get("recommendation")) or "Confirma si este servicio debe estar disponible."
        risk = str(port.get("risk") or "Sin valorar")
        risk_key = risk.lower()
        risk_style = 11 if risk_key in {"alto", "muy alto"} else 12 if risk_key == "medio" else 13 if risk_key == "bajo" else 14
        _row(port_sheet, [_host_name(host), host.get("address", ""), int(port.get("port") or 0), port.get("name") or port.get("service") or "Servicio sin nombre", app_name, description, risk, recommendation, evidence], styles=[5, 5, 5, 5, 5, 5, risk_style, 5, 5], height=42)
    if not ports:
        _row(port_sheet, ["No se registraron puertos TCP abiertos."], styles=[9], height=32); _merge(port_sheet, "A5:I5")
    port_sheet["autofilter"] = f"A4:I{max(4, len(port_sheet['rows']))}"

    sheets = [summary, devices, port_sheet]
    if local_host and local_host.get("local_inventory"):
        local = local_host["local_inventory"]
        local_sheet = _sheet("Equipo local", [25, 54, 27, 50], freeze_rows=14)
        _row(local_sheet, ["Componentes de este computador"], styles=[1], height=39); _merge(local_sheet, "A1:D1")
        _row(local_sheet, ["Datos consultados en el sistema operativo local; el usuario mostrado es la cuenta activa en este equipo."], styles=[2], height=29); _merge(local_sheet, "A2:D2")
        _row(local_sheet, [], height=12)
        _row(local_sheet, ["Dato", "Resultado", "Dato", "Resultado"], styles=[4] * 4, height=34)
        memory_modules = "\n".join("Módulo {}: {}{}{}".format(index + 1, _bytes_gb(item.get("capacity_bytes")), " · {} MHz".format(item.get("speed_mhz")) if item.get("speed_mhz") else "", " · {}".format(item.get("manufacturer")) if item.get("manufacturer") else "") for index, item in enumerate(local.get("memory_modules") or [])) or "No disponible"
        cpu = " / ".join("{}{}{}".format(item.get("name", ""), " · {} núcleos".format(item.get("cores")) if item.get("cores") else "", " · {} hilos".format(item.get("logical_processors")) if item.get("logical_processors") else "") for item in local.get("cpu") or []) or "No disponible"
        boards = " / ".join(" ".join(str(item.get(key) or "") for key in ("manufacturer", "product")).strip() for item in local.get("motherboard") or []) or "No disponible"
        graphics = " / ".join(item.get("name", "") for item in local.get("gpu") or [] if item.get("name")) or "No disponible"
        disks = " / ".join("{}{}".format(item.get("model") or "Unidad", " · {}".format(_bytes_gb(item.get("size_bytes"))) if item.get("size_bytes") else "") for item in local.get("storage") or []) or "No disponible"
        addresses = ", ".join(item.get("address", "") for item in local.get("local_addresses") or [] if item.get("address")) or "No disponible"
        local_values = [
            ["Nombre del equipo", local.get("computer_name") or _host_name(local_host), "Modelo del computador", local.get("computer_model") or "No informado"],
            ["Sistema operativo", local.get("os_name") or "No disponible", "Versión / compilación", " · ".join(str(value) for value in (local.get("os_version"), local.get("os_build")) if value) or "No disponible"],
            ["Usuario de Windows", local.get("user_name") or "No disponible", "Arquitectura", local.get("architecture") or "No disponible"],
            ["Memoria RAM instalada", _bytes_gb(local.get("ram_total_bytes")), "RAM disponible al consultar", _bytes_gb(local.get("ram_free_bytes"))],
            ["Procesador", cpu, "Placa base", boards],
            ["Gráficos", graphics, "Almacenamiento físico", disks],
            ["Módulos de RAM", memory_modules, "Direcciones locales", addresses],
        ]
        for index, values in enumerate(local_values):
            _row(local_sheet, values, styles=[10, 5, 10, 5], height=42 if index in (4, 5, 6) else 30)
        _row(local_sheet, [], height=9)
        _row(local_sheet, ["Puertos TCP locales en escucha"], styles=[3], height=28); _merge(local_sheet, "A13:D13")
        _row(local_sheet, ["Puerto TCP", "Dirección local", "Proceso", "PID"], styles=[4] * 4, height=34)
        listeners = local.get("tcp_listeners") or []
        for item in listeners:
            _row(local_sheet, [int(item.get("port") or 0), item.get("address") or "", item.get("application") or "Proceso sin identificar", item.get("pid") or ""], styles=[5] * 4, height=23)
        if listeners:
            local_sheet["autofilter"] = f"A14:D{max(14, len(local_sheet['rows']))}"
        else:
            _row(local_sheet, ["El sistema operativo no devolvió puertos TCP en escucha al consultar."], styles=[9], height=30); _merge(local_sheet, "A15:D15")
        sheets.append(local_sheet)

    adb_inventory = report.get("adb_inventory") or {}
    adb_devices = [device for device in adb_inventory.get("devices") or [] if device.get("authorized") and device.get("data_available", True)]
    adb_devices += [host["adb_inventory"] for host in hosts if (host.get("adb_inventory") or {}).get("authorized") and (host.get("adb_inventory") or {}).get("data_available", True) and all(item.get("serial") != host["adb_inventory"].get("serial") for item in adb_devices)]
    if adb_devices:
        adb_sheet = _sheet("Android ADB", [24, 18, 25, 28, 20, 23, 18, 18, 38, 24, 22], freeze_rows=4)
        _row(adb_sheet, ["Teléfonos Android autorizados"], styles=[1], height=39); _merge(adb_sheet, "A1:K1")
        _row(adb_sheet, ["Valores consultados directamente en equipos que ya aprobaron la depuración ADB."], styles=[2], height=29); _merge(adb_sheet, "A2:K2")
        _row(adb_sheet, [], height=12)
        headers = ["Nombre mostrado", "IP (si aplica)", "Fabricante", "Modelo", "Versión de Android", "Parche de seguridad", "RAM total", "RAM disponible", "Procesador / SoC", "Arquitectura", "Almacenamiento libre"]
        _row(adb_sheet, headers, styles=[4] * len(headers), height=37)
        for device in adb_devices:
            _row(adb_sheet, [device.get("device_name") or device.get("model") or "Android", device.get("address") or "USB / sin IP", device.get("manufacturer") or device.get("brand") or "No informado", device.get("model") or "No informado", device.get("android_version") or "No informada", device.get("security_patch") or "No informado", _bytes_gb(device.get("ram_total_bytes")), _bytes_gb(device.get("ram_available_bytes")), device.get("cpu_model") or "No informado", device.get("cpu_architecture") or "No informada", _bytes_gb(device.get("storage_available_bytes"))], styles=[5] * len(headers), height=38)
        adb_sheet["autofilter"] = f"A4:K{max(4, len(adb_sheet['rows']))}"
        sheets.append(adb_sheet)

    scripts_rows = []
    for host in hosts:
        for script in host.get("scripts") or []:
            scripts_rows.append([_host_name(host), host.get("address", ""), "Equipo", "", script.get("id", ""), "Sí · revisar" if script.get("possible_vulnerability") else "No marcado", _clean_text(script.get("output") or "\n".join(script.get("details") or []))])
        for port in host.get("ports") or []:
            for script in port.get("scripts") or []:
                scripts_rows.append([_host_name(host), host.get("address", ""), port.get("port", ""), port.get("protocol", ""), script.get("id", ""), "Sí · revisar" if script.get("possible_vulnerability") else "No marcado", _clean_text(script.get("output") or "\n".join(script.get("details") or []))])
    if scripts_rows:
        script_sheet = _sheet("Hallazgos", [24, 18, 14, 14, 29, 21, 90], freeze_rows=4)
        _row(script_sheet, ["Hallazgos de comprobaciones adicionales"], styles=[1], height=39); _merge(script_sheet, "A1:G1")
        _row(script_sheet, ["Resultados adicionales devueltos por los equipos y servicios consultados."], styles=[2], height=29); _merge(script_sheet, "A2:G2")
        _row(script_sheet, [], height=12)
        headers = ["Equipo", "Dirección IP", "Puerto", "Protocolo", "Comprobación", "Para revisar", "Evidencia recibida"]
        _row(script_sheet, headers, styles=[4] * len(headers), height=36)
        for values in scripts_rows:
            _row(script_sheet, values, styles=[5] * len(values), height=40)
        script_sheet["autofilter"] = f"A4:G{len(script_sheet['rows'])}"
        sheets.append(script_sheet)

    guide = _sheet("Guía", [28, 105], freeze_rows=4)
    _row(guide, ["Cómo leer este informe"], styles=[1], height=39); _merge(guide, "A1:B1")
    _row(guide, ["Definiciones breves para entender cada dato y saber qué puede confirmar."], styles=[2], height=29); _merge(guide, "A2:B2")
    _row(guide, [], height=12)
    _row(guide, ["Término", "Explicación"], styles=[4, 4], height=34)
    guide_rows = [
        ("Dirección IP", "Dirección que identifica al equipo dentro de la red. Puede cambiar con el tiempo."),
        ("Dirección MAC", "Identificador de una interfaz de red. Los teléfonos pueden usar una MAC privada aleatoria."),
        ("Fabricante de la interfaz", "Se estima por el prefijo de la MAC. No confirma el modelo ni la marca comercial del equipo."),
        ("Sistema operativo probable", "Una respuesta de red puede sugerir una familia. La versión exacta solo se muestra cuando una fuente autorizada la entrega."),
        ("Puerto TCP abierto", "Una aplicación acepta conexiones en ese puerto. Describe exposición de red; no significa automáticamente que exista una falla."),
        ("Aplicación o producto", "El servicio puede anunciar nombre o versión. En otro equipo esto no siempre identifica el proceso que lo ejecuta."),
        ("Nivel de atención", "Orientación inicial basada en el servicio habitual. Confirma si el puerto debe estar abierto y revisa el firewall y la configuración."),
        ("Android", "La versión, el modelo, el procesador y la memoria aparecen cuando el teléfono ya está conectado y autorizado mediante ADB por USB o depuración inalámbrica."),
        ("iPhone o iPad", "Los detalles del sistema y hardware requieren inscripción en un servidor MDM existente y configurado."),
        ("Cuenta de usuario", "El nombre se muestra para el computador local. En móviles solo aparece si la herramienta autorizada entrega ese dato."),
        ("Datos no disponibles", "‘No disponible’ significa que esa fuente no entregó el dato; no se reemplaza con una suposición."),
    ]
    for label, description in guide_rows:
        _row(guide, [label, description], styles=[10, 5], height=34)
    sheets.append(guide)
    return sheets


def export_xlsx(report: dict, reports_dir: Path) -> str:
    if not isinstance(report, dict) or not isinstance(report.get("hosts", []), list):
        raise ValueError("El resultado del análisis no tiene un formato válido.")
    sheets = _build_sheets(report)
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    filename = f"Trabamap_Informe_{stamp}.xlsx"
    file_path = reports_dir / filename

    content_types = ET.Element(f"{{{CT_NS}}}Types")
    ET.SubElement(content_types, f"{{{CT_NS}}}Default", {"Extension": "rels", "ContentType": "application/vnd.openxmlformats-package.relationships+xml"})
    ET.SubElement(content_types, f"{{{CT_NS}}}Default", {"Extension": "xml", "ContentType": "application/xml"})
    ET.SubElement(content_types, f"{{{CT_NS}}}Override", {"PartName": "/xl/workbook.xml", "ContentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"})
    ET.SubElement(content_types, f"{{{CT_NS}}}Override", {"PartName": "/xl/styles.xml", "ContentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"})
    for index in range(1, len(sheets) + 1):
        ET.SubElement(content_types, f"{{{CT_NS}}}Override", {"PartName": f"/xl/worksheets/sheet{index}.xml", "ContentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"})

    workbook = ET.Element(f"{{{MAIN_NS}}}workbook")
    sheet_list = ET.SubElement(workbook, f"{{{MAIN_NS}}}sheets")
    for index, sheet in enumerate(sheets, 1):
        ET.SubElement(sheet_list, f"{{{MAIN_NS}}}sheet", {"name": sheet["name"], "sheetId": str(index), f"{{{REL_NS}}}id": f"rId{index}"})
    ET.SubElement(workbook, f"{{{MAIN_NS}}}calcPr", {"calcMode": "auto", "fullCalcOnLoad": "1"})

    workbook_rels = ET.Element(f"{{{PKG_REL_NS}}}Relationships")
    for index in range(1, len(sheets) + 1):
        ET.SubElement(workbook_rels, f"{{{PKG_REL_NS}}}Relationship", {"Id": f"rId{index}", "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet", "Target": f"worksheets/sheet{index}.xml"})
    ET.SubElement(workbook_rels, f"{{{PKG_REL_NS}}}Relationship", {"Id": "rIdStyles", "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles", "Target": "styles.xml"})
    root_rels = ET.Element(f"{{{PKG_REL_NS}}}Relationships")
    ET.SubElement(root_rels, f"{{{PKG_REL_NS}}}Relationship", {"Id": "rId1", "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument", "Target": "xl/workbook.xml"})

    with zipfile.ZipFile(file_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _no_prefix_xml(content_types, CT_NS))
        archive.writestr("_rels/.rels", _no_prefix_xml(root_rels, PKG_REL_NS))
        archive.writestr("xl/workbook.xml", ET.tostring(workbook, encoding="utf-8", xml_declaration=True))
        archive.writestr("xl/_rels/workbook.xml.rels", _no_prefix_xml(workbook_rels, PKG_REL_NS))
        archive.writestr("xl/styles.xml", _styles_xml())
        for index, sheet in enumerate(sheets, 1):
            archive.writestr(f"xl/worksheets/sheet{index}.xml", _worksheet(sheet))
    return filename
