"""Explicaciones y valoración prudente: el puerto por sí solo no prueba una brecha."""
PORTS = {
    20: ("FTP datos", "Transferencia de archivos sin cifrado en configuraciones tradicionales.", "Alto", "Desactívalo si no lo necesitas. Prefiere SFTP o FTPS y restringe el acceso."),
    21: ("FTP", "Servicio de transferencia de archivos que puede exponer credenciales sin cifrado.", "Alto", "Cámbialo por SFTP/FTPS o limita el acceso por red y cuentas."),
    22: ("SSH", "Acceso remoto seguro a una consola; habitual en administración de servidores.", "Medio", "Usa llaves, desactiva contraseñas débiles y limita quién puede conectarse."),
    23: ("Telnet", "Acceso remoto antiguo que envía información sin cifrar.", "Muy alto", "Desactívalo y usa SSH."),
    25: ("SMTP", "Envío de correo electrónico entre servidores.", "Medio", "Comprueba que solo los remitentes autorizados puedan usarlo."),
    53: ("DNS", "Traduce nombres de dominio a direcciones de red.", "Medio", "Revisa que no permita recursión pública ni transferencias de zona abiertas."),
    80: ("HTTP", "Servidor web sin cifrado TLS.", "Medio", "Redirige a HTTPS y evita enviar credenciales por HTTP."),
    110: ("POP3", "Recepción de correo; el modo clásico no cifra la conexión.", "Alto", "Desactívalo o exige POP3S/TLS."),
    139: ("NetBIOS", "Compartición y descubrimiento de equipos en redes Windows antiguas.", "Alto", "Limítalo a la red local y desactívalo si no lo necesitas."),
    143: ("IMAP", "Acceso a buzones de correo; sin TLS puede exponer credenciales.", "Medio", "Exige IMAPS/TLS y autenticación robusta."),
    443: ("HTTPS", "Servidor web con conexión cifrada TLS.", "Bajo", "Mantén TLS y el software del servidor actualizados."),
    445: ("SMB", "Compartición de archivos e impresoras en Windows.", "Alto", "No lo expongas a Internet; limita SMB al segmento de confianza."),
    3306: ("MySQL", "Base de datos MySQL, normalmente destinada a conexiones internas.", "Alto", "Evita exponerla públicamente; restringe IPs y usa credenciales únicas."),
    3389: ("Escritorio remoto", "Acceso remoto gráfico a Windows (RDP).", "Alto", "Restringe por VPN/IP, activa MFA y evita exponer RDP a Internet."),
    5432: ("PostgreSQL", "Base de datos PostgreSQL, normalmente destinada a conexiones internas.", "Alto", "Limita IPs permitidas y evita exponer la base de datos públicamente."),
    5900: ("VNC", "Control remoto de escritorio; algunas configuraciones carecen de cifrado fuerte.", "Alto", "Desactívalo o úsalo solo tras una VPN con autenticación robusta."),
    8080: ("HTTP alternativo", "Servidor web o panel de administración en un puerto alternativo.", "Medio", "Identifica la aplicación y evita dejar paneles de administración expuestos."),
    8443: ("HTTPS alternativo", "Servidor web cifrado, a menudo usado por paneles de administración.", "Medio", "Averigua qué panel lo usa y limita el acceso."),
    # Infraestructura de red
    67: ("DHCP", "Reparte direcciones IP a los equipos de la red; normal en un router.", "Bajo", "Confirma que solo tu router ofrece DHCP."),
    69: ("TFTP", "Transferencia de archivos sin contraseña ni cifrado, usada por equipos de red.", "Alto", "Desactívalo si no actualizas firmware por TFTP."),
    88: ("Kerberos", "Autenticación de dominios Windows (Active Directory).", "Medio", "Es normal en un controlador de dominio; no lo expongas fuera de la red interna."),
    111: ("RPCbind", "Directorio de servicios RPC en Linux/Unix; acompaña a NFS.", "Alto", "Bloquéalo desde fuera y desactívalo si no usas NFS."),
    123: ("NTP", "Sincronización de la hora.", "Bajo", "Limita las consultas a tu red para evitar abusos de amplificación."),
    135: ("RPC de Windows", "Localizador de servicios de Windows; lo usan la administración remota y DCOM.", "Alto", "Mantenlo solo en la red local y con el firewall de Windows activo."),
    137: ("NetBIOS nombres", "Resolución de nombres de equipos Windows antiguos.", "Medio", "Desactiva NetBIOS sobre TCP/IP si no hay equipos antiguos."),
    138: ("NetBIOS datagramas", "Anuncios de equipos en redes Windows antiguas.", "Medio", "Desactiva NetBIOS sobre TCP/IP si no hay equipos antiguos."),
    161: ("SNMP", "Monitorización de equipos de red; las versiones 1 y 2c usan una clave en texto claro.", "Alto", "Usa SNMPv3 o cambia la comunidad 'public' y limita quién consulta."),
    389: ("LDAP", "Directorio de usuarios y equipos (Active Directory, OpenLDAP) sin cifrar.", "Alto", "Usa LDAPS (636) y no lo expongas fuera de la red interna."),
    500: ("IPsec IKE", "Negociación de túneles VPN IPsec.", "Bajo", "Normal en un servidor o router VPN; mantén el firmware actualizado."),
    514: ("Syslog / RSH", "Recepción de registros o shell remoto antiguo sin cifrar.", "Alto", "Confirma qué servicio es; desactiva rsh y limita syslog a equipos conocidos."),
    636: ("LDAPS", "Directorio de usuarios con conexión cifrada.", "Medio", "Limita el acceso a los equipos que lo necesitan."),
    1723: ("VPN PPTP", "VPN antigua con cifrado roto.", "Alto", "Sustitúyela por WireGuard, OpenVPN o IPsec."),
    1900: ("UPnP / SSDP", "Descubrimiento automático de dispositivos; permite abrir puertos en el router.", "Medio", "Desactiva UPnP en el router si no lo necesitas."),
    5353: ("mDNS / Bonjour", "Descubrimiento de equipos y servicios en la red local (Apple, Chromecast, impresoras).", "Bajo", "Es normal dentro de casa u oficina; no debe salir a Internet."),
    5355: ("LLMNR", "Resolución de nombres local de Windows.", "Medio", "Puede desactivarse por directiva si no se usa."),
    # Correo
    465: ("SMTPS", "Envío de correo con cifrado TLS.", "Bajo", "Exige autenticación y mantén el servidor actualizado."),
    587: ("SMTP envío", "Envío de correo autenticado desde clientes.", "Bajo", "Exige STARTTLS y autenticación."),
    993: ("IMAPS", "Acceso a buzones de correo con cifrado TLS.", "Bajo", "Mantén el servidor actualizado y usa contraseñas robustas."),
    995: ("POP3S", "Descarga de correo con cifrado TLS.", "Bajo", "Mantén el servidor actualizado y usa contraseñas robustas."),
    # Archivos e impresión
    515: ("LPD", "Cola de impresión clásica.", "Medio", "Normal en impresoras; limítala a la red local."),
    548: ("AFP", "Compartición de archivos de Apple (antigua).", "Medio", "Prefiere SMB y desactiva AFP si no hay Macs antiguos."),
    631: ("IPP / CUPS", "Impresión por red; habitual en impresoras, macOS y Linux.", "Medio", "Limítala a la red local y actualiza el firmware de la impresora."),
    873: ("rsync", "Sincronización de archivos; puede permitir acceso sin contraseña.", "Alto", "Exige autenticación o úsalo solo a través de SSH."),
    2049: ("NFS", "Carpetas compartidas de Linux/Unix.", "Alto", "Restringe las exportaciones a IPs concretas y no lo expongas a Internet."),
    9100: ("Impresión directa", "Puerto RAW/JetDirect: cualquier dato enviado se imprime.", "Medio", "Normal en impresoras; aíslala de redes de invitados."),
    # Acceso remoto
    512: ("rexec", "Ejecución remota antigua sin cifrar.", "Muy alto", "Desactívalo y usa SSH."),
    513: ("rlogin", "Inicio de sesión remoto antiguo sin cifrar.", "Muy alto", "Desactívalo y usa SSH."),
    902: ("VMware", "Consola y autenticación de VMware.", "Medio", "Limítalo a los equipos de administración."),
    2222: ("SSH alternativo", "SSH en un puerto no estándar.", "Medio", "Usa llaves y limita quién puede conectarse."),
    5555: ("ADB de Android", "Depuración de Android por red: da control total del dispositivo.", "Muy alto", "Desactiva la depuración inalámbrica cuando no la uses."),
    5800: ("VNC web", "Control remoto VNC desde el navegador.", "Alto", "Desactívalo o úsalo solo tras una VPN."),
    5938: ("TeamViewer", "Control remoto TeamViewer.", "Medio", "Activa doble factor y lista de equipos permitidos."),
    5985: ("WinRM", "Administración remota de Windows (PowerShell) por HTTP.", "Alto", "Limítalo a equipos de administración y prefiere HTTPS (5986)."),
    5986: ("WinRM HTTPS", "Administración remota de Windows cifrada.", "Medio", "Limítalo a equipos de administración."),
    # Bases de datos y cachés
    1433: ("SQL Server", "Base de datos Microsoft SQL Server.", "Alto", "Restringe IPs, desactiva la cuenta 'sa' y no la expongas a Internet."),
    1521: ("Oracle", "Base de datos Oracle.", "Alto", "Restringe IPs y protege el listener con contraseña."),
    5984: ("CouchDB", "Base de datos CouchDB con panel web.", "Alto", "Exige autenticación y limita el acceso."),
    6379: ("Redis", "Base de datos en memoria; por defecto no pide contraseña.", "Muy alto", "Actívale contraseña, enlázala a localhost y no la expongas."),
    9200: ("Elasticsearch", "Motor de búsqueda; sin seguridad activada expone todos los datos.", "Alto", "Activa la seguridad integrada y limita el acceso por red."),
    11211: ("Memcached", "Caché en memoria sin autenticación.", "Alto", "Enlázalo a localhost; expuesto se usa para ataques de amplificación."),
    27017: ("MongoDB", "Base de datos MongoDB.", "Alto", "Activa autenticación y enlázala a IPs internas."),
    # Desarrollo, contenedores y paneles
    2375: ("Docker sin TLS", "API de Docker sin cifrar: quien acceda controla la máquina.", "Muy alto", "Ciérralo; usa el socket local o TLS con certificados (2376)."),
    2376: ("Docker TLS", "API de Docker con TLS.", "Medio", "Comprueba que exige certificados de cliente."),
    3000: ("Aplicación web", "Puerto típico de servidores de desarrollo (Node, Grafana).", "Medio", "Identifica la aplicación; no dejes entornos de desarrollo accesibles."),
    5000: ("Aplicación web", "Puerto típico de Flask, registros Docker o UPnP.", "Medio", "Identifica la aplicación y confirma que debe estar accesible."),
    5173: ("Vite", "Servidor de desarrollo web.", "Bajo", "Es normal mientras desarrollas; ciérralo al terminar."),
    6443: ("Kubernetes API", "API de control de un clúster Kubernetes.", "Alto", "Limita el acceso por red y revisa la autenticación."),
    8000: ("HTTP alternativo", "Servidor web de desarrollo o panel.", "Medio", "Identifica la aplicación y evita paneles expuestos."),
    8081: ("HTTP alternativo", "Servidor web o panel de administración secundario.", "Medio", "Identifica la aplicación y evita paneles expuestos."),
    8888: ("HTTP alternativo", "A menudo Jupyter u otro panel de desarrollo.", "Medio", "Protégelo con contraseña o token y no lo expongas."),
    9000: ("Panel web", "Puerto típico de Portainer, SonarQube o PHP-FPM.", "Medio", "Identifica el servicio y limita el acceso."),
    9090: ("Panel web", "Puerto típico de Prometheus o Cockpit.", "Medio", "Identifica el servicio y exige autenticación."),
    10000: ("Webmin", "Panel web de administración de servidores.", "Alto", "Mantenlo actualizado y accesible solo por VPN."),
    # Hogar, multimedia y móviles
    554: ("RTSP", "Vídeo en directo de cámaras IP y grabadores.", "Alto", "Cambia la contraseña por defecto y no lo expongas a Internet."),
    1883: ("MQTT", "Mensajería de dispositivos IoT sin cifrar.", "Alto", "Exige usuario/contraseña y prefiere MQTT sobre TLS (8883)."),
    3283: ("Apple Remote Desktop", "Gestión remota de equipos Mac.", "Medio", "Limítalo a equipos de administración."),
    5060: ("SIP", "Telefonía IP sin cifrar.", "Medio", "Limita quién puede registrarse y usa contraseñas largas."),
    5357: ("WSD", "Descubrimiento de dispositivos de Windows (impresoras, escáneres).", "Bajo", "Normal en redes locales privadas."),
    7000: ("AirPlay", "Recepción de audio/vídeo AirPlay (Apple, televisores).", "Bajo", "Normal en casa; exige código si hay invitados."),
    7680: ("Optimización de entrega", "Windows comparte actualizaciones con otros equipos de la red.", "Bajo", "Normal en Windows 10/11; puede desactivarse en Configuración."),
    8008: ("Chromecast", "Control de Chromecast y dispositivos Google.", "Bajo", "Normal en casa; aísla la red de invitados."),
    8009: ("Chromecast / AJP", "Canal de control de Chromecast, o AJP en servidores Tomcat.", "Medio", "Si es un servidor Tomcat, desactiva AJP o protégelo."),
    8883: ("MQTT TLS", "Mensajería IoT cifrada.", "Bajo", "Mantén certificados y credenciales al día."),
    32400: ("Plex", "Servidor multimedia Plex.", "Medio", "Mantenlo actualizado y exige inicio de sesión."),
    62078: ("Sincronización de iPhone", "Servicio de sincronización Wi-Fi de iOS (lockdown).", "Bajo", "Normal en iPhone/iPad; solo responde a equipos emparejados."),
}
DEFAULT = ("Servicio de red", "Hay una aplicación escuchando en este puerto; Nmap no determina por sí solo si es vulnerable.", "Medio", "Identifica el proceso y confirma que debe estar accesible desde esta red.")

def explain(port: dict) -> dict:
    if any(script.get("possible_vulnerability") for script in port.get("scripts", [])):
        script_ids = ", ".join(s["id"] for s in port["scripts"] if s.get("possible_vulnerability"))
        explained = {**port, "name": port.get("service", "Servicio"), "description": f"NSE reportó una posible vulnerabilidad ({script_ids}). Revisa la salida del script antes de concluir.", "risk": "Alto", "recommendation": "Valida la evidencia de Nmap, confirma la versión afectada y aplica el parche del fabricante."}
        return _application_evidence(explained)
    name, description, risk, recommendation = PORTS.get(port["port"], DEFAULT)
    if port.get("state") != "open":
        explained = {**port, "name": port.get("service", "Puerto") or "Puerto", "description": f"Nmap marcó este puerto como {port.get('state', 'desconocido')}.", "risk": "Informativo", "recommendation": "Este estado no confirma un servicio abierto."}
        return _application_evidence(explained)
    service = port.get("service", "")
    if name == "Servicio de red" and service and service != "unknown": name = service.upper()
    return _application_evidence({**port, "name": name, "description": description, "risk": risk, "recommendation": recommendation})

def _application_evidence(port: dict) -> dict:
    """Describe cuánto se sabe de la aplicación sin confundir puerto y proceso."""
    product = str(port.get("product", "")).strip()
    version = str(port.get("version", "")).strip()
    service = str(port.get("service", "")).strip()
    if product:
        application = " ".join(part for part in (product, version) if part)
        source = "Producto/version reportado por la huella de servicio de Nmap (-sV); no identifica necesariamente el proceso exacto."
    elif service and service.lower() not in ("unknown", "desconocido"):
        application = service
        source = "Nombre de servicio reportado por Nmap; la aplicación o proceso exacto puede ser distinto o no estar identificado."
    elif int(port.get("port", 0)) in PORTS:
        application = PORTS[int(port["port"])][0]
        source = "Uso habitual de este puerto; es una pista, no una identificación de la aplicación instalada."
    else:
        application = "Aplicación exacta no identificada"
        source = "El número de puerto por sí solo no revela la aplicación que lo abrió."
    return {**port, "application": application, "application_source": source}

def enrich(scan: dict) -> dict:
    ranking = {"Muy alto": 0, "Alto": 1, "Medio": 2, "Bajo": 3, "Informativo": 4}
    for host in scan["hosts"]:
        host["ports"] = sorted((explain(p) for p in host["ports"]), key=lambda p: (0 if p["state"] == "open" else 1, ranking[p["risk"]], p["port"]))
    all_ports = [p for host in scan["hosts"] for p in host["ports"]]
    open_ports = [p for p in all_ports if p["state"] == "open"]
    severe = sum(p["risk"] in ("Muy alto", "Alto") for p in open_ports)
    extras = [x for host in scan["hosts"] for x in host.get("other_ports", [])]
    findings = sum(s.get("possible_vulnerability", False) for h in scan["hosts"] for s in h.get("scripts", []) + [s for p in h["ports"] for s in p.get("scripts", [])])
    scan["summary"] = {"hosts": scan.get("runstats", {}).get("up", len(scan["hosts"])), "open_ports": len(open_ports), "high_risk": severe, "nse_findings": findings, "filtered_ports": sum(int(x.get("count", 0)) for x in extras if "filtered" in x.get("state", "")), "closed_ports": sum(int(x.get("count", 0)) for x in extras if x.get("state") == "closed"), "status": "Revisar" if severe else ("Sin puertos abiertos" if not open_ports else "Correcto")}
    return scan
