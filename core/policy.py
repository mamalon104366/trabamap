"""Política de seguridad fija de TrabaMap.

Se aplica en el motor, no solo en la interfaz: aunque alguien modifique la ventana o escriba parámetros a mano,
estas opciones nunca llegan a Nmap. TrabaMap es una herramienta de diagnóstico y auditoría de redes propias;
no ofrece evasión, suplantación, fuerza bruta, denegación de servicio ni explotación.
"""
import re

# Opción (o prefijo) -> motivo que se muestra al usuario.
BLOCKED_FLAGS = {
    "-D": "los señuelos (-D) ocultan quién escanea",
    "-S": "falsificar la IP de origen (-S)",
    "-f": "fragmentar paquetes (-f) sirve para evadir filtros",
    "-g": "falsificar el puerto de origen (-g)",
    "-b": "el rebote FTP (-b) usa un servidor ajeno como intermediario",
    "-sI": "el escaneo idle (-sI) usa un equipo ajeno como intermediario",
    "-iR": "los objetivos aleatorios (-iR) escanean equipos sin autorización",
    "-iL": "las listas de objetivos en archivo (-iL) ocultan a quién se escanea; escribe los objetivos en el campo",
    "--mtu": "fragmentar paquetes (--mtu) sirve para evadir filtros",
    "--source-port": "falsificar el puerto de origen",
    "--spoof-mac": "falsificar la dirección MAC",
    "--data-length": "el relleno de paquetes sirve para evadir la detección",
    "--data": "inyectar datos arbitrarios en los paquetes",
    "--data-string": "inyectar datos arbitrarios en los paquetes",
    "--badsum": "enviar sumas de verificación falsas",
    "--ip-options": "manipular las opciones IP",
    "--ttl": "manipular el TTL de salida",
    "--proxies": "encadenar proxies oculta el origen del escaneo",
    "--randomtargets": "los objetivos aleatorios escanean equipos sin autorización",
    "--inputfile": "las listas de objetivos en archivo ocultan a quién se escanea",
    "--script-args-file": "los argumentos de scripts deben quedar visibles en el registro",
    "--datadir": "cambiar los datos internos de Nmap",
    "--script-updatedb": "modificar la base de scripts de Nmap",
}
# Categorías y scripts NSE que atacan en lugar de diagnosticar.
BLOCKED_SCRIPT_WORDS = ("brute", "dos", "exploit", "fuzzer", "slowloris", "flood", "backdoor-exec")
SAFE_VULN_EXPRESSION = "vuln and not (dos or exploit or brute or fuzzer)"


SHORT_WITH_VALUE = ("-D", "-S", "-g", "-b", "-sI", "-iR", "-iL")


class PolicyError(ValueError):
    pass


def _flag_name(token: str) -> str:
    return token.split("=", 1)[0]


def check_extra_args(tokens: list[str]) -> None:
    """Rechaza parámetros adicionales que la política no permite."""
    for index, token in enumerate(tokens):
        name = _flag_name(token)
        if name.startswith("--"):
            if name in BLOCKED_FLAGS:
                raise PolicyError(f"La política de seguridad de TrabaMap no permite {name}: {BLOCKED_FLAGS[name]}.")
        elif re.fullmatch(r"-f+", token):
            raise PolicyError(f"La política de seguridad de TrabaMap no permite {token}: {BLOCKED_FLAGS['-f']}.")
        else:
            # Las opciones cortas de Nmap admiten el valor pegado (-D10.0.0.1, -g53) y distinguen mayúsculas.
            for flag in SHORT_WITH_VALUE:
                if token.startswith(flag):
                    raise PolicyError(f"La política de seguridad de TrabaMap no permite {flag}: {BLOCKED_FLAGS[flag]}.")
        if name == "--script":
            value = token.split("=", 1)[1] if "=" in token else (tokens[index + 1] if index + 1 < len(tokens) else "")
            check_scripts(value)
        if name == "--script-args":
            value = token.split("=", 1)[1] if "=" in token else (tokens[index + 1] if index + 1 < len(tokens) else "")
            if re.search(r"\bunsafe\s*=\s*(1|true)", value, re.IGNORECASE):
                raise PolicyError("La política de seguridad de TrabaMap no permite unsafe=1: activa comprobaciones que pueden tumbar el equipo revisado.")


def check_scripts(expression: str) -> None:
    lowered = expression.lower()
    if lowered.strip() in ("all", "*"):
        raise PolicyError("La política de seguridad de TrabaMap no permite ejecutar todos los scripts a la vez: incluye fuerza bruta y denegación de servicio.")
    # "not dos" dentro de una expresión es una exclusión, no una petición.
    without_exclusions = re.sub(r"not\s*\([^)]*\)|not\s+[\w*-]+", " ", lowered)
    for word in BLOCKED_SCRIPT_WORDS:
        if re.search(rf"(^|[^a-z]){re.escape(word)}([^a-z]|$)", without_exclusions) or re.search(rf"[\w-]*-{re.escape(word)}\b", without_exclusions):
            raise PolicyError(f"La política de seguridad de TrabaMap no permite scripts de tipo “{word}”: atacan el servicio en lugar de diagnosticarlo.")


def describe() -> list[str]:
    """Reglas fijas, para mostrarlas en la interfaz y en la documentación."""
    return [
        "Sin evasión ni suplantación: no se permiten señuelos, IP/MAC/puerto de origen falsos, fragmentación ni proxies.",
        "Sin intermediarios ajenos: no hay escaneo idle (zombie) ni rebote FTP.",
        "Sin objetivos ocultos o al azar: no se aceptan listas en archivo ni -iR; todo objetivo queda escrito y registrado.",
        "Sin ataques: se bloquean los scripts de fuerza bruta, denegación de servicio, explotación y fuzzing, y el modo unsafe.",
        "Las comprobaciones de vulnerabilidades excluyen automáticamente las que pueden tumbar un servicio.",
        "Los parámetros van a Nmap como argumentos, nunca a través de una consola: no hay inyección de comandos.",
        "Cada escaneo queda en el registro local con fecha, objetivo, opciones y resultado.",
    ]
