# TrabaMap

TrabaMap es una aplicación de escritorio en español para explorar redes. Usa **Nmap como motor real** y añade una interfaz para configurar escaneos, entender puertos y servicios, revisar alertas orientativas, consultar el historial y guardar resultados locales.

TrabaMap usa el motor de Nmap; la interfaz añade descubrimiento de la red local, explicaciones en español, reportes e historial. No cambia la precisión de Nmap ni puede inferir datos que el equipo no revela.

## Requisitos

- Windows 10/11, macOS o Linux.
- Node.js 20+ y npm.
- Python 3.10+.
- Nmap instalado. En Windows se detectan las rutas habituales del instalador, incluida `C:\Program Files (x86)\Nmap\nmap.exe`.

## Iniciar la aplicación

```powershell
npm install
npm run desktop
```

`npm run desktop` inicia Vite y Electron juntos, elige un puerto local disponible y cierra el servidor al cerrar la app. Usa `npm run dev` solo para trabajar en la interfaz web; no hace falta ejecutarlo aparte para abrir TrabaMap.

## La interfaz

- **Barra lateral** con las secciones (Escáner, Dispositivos, Historial, Actividad, Guía), el estado del motor Nmap y la interfaz de red activa. Se contrae a un riel de iconos con el botón de la cabecera; la preferencia se recuerda.
- **Buscador** (`Ctrl+K`): salta a una sección, a un reporte, a un equipo descubierto o a cualquier concepto de la guía ("filtrado", "SYN", "-sV"…).
- **Comando explicado**: bajo los perfiles se muestra el comando Nmap que se va a ejecutar; "¿Qué hace cada parte?" traduce cada opción a español.
- **Guía**: cómo funciona un escaneo, perfiles, estados de puerto, niveles de riesgo, tipos de escaneo, opciones, glosario y límites.
- **Dispositivos** en lista o en **mapa de red** (router al centro, este equipo resaltado). Doble clic, `Enter` o el botón de información abren la ficha; el clic derecho ofrece el escaneo completo.
- El motor explica unos 85 puertos conocidos (web, correo, bases de datos, acceso remoto, impresión, IoT…) con riesgo orientativo y recomendación.

Para revisar el diseño sin Electron ni Nmap: `npm run dev` y abre `http://127.0.0.1:5173/?demo` (datos de ejemplo; no se incluyen en el paquete).

El logo vive como vector en `src/icons.jsx`. `py -3 scripts/create-brand-assets.py` regenera el icono `.ico` y las imágenes del instalador en `build/` (requiere Pillow).

## ¿Qué necesita quien recibe el .exe?

| Componente | ¿Va dentro del instalador? |
| --- | --- |
| Interfaz (Electron + React) | Sí |
| Motor Python de TrabaMap | Sí, compilado; no hay que instalar Python |
| Motor integrado (descubrir equipos, puertos TCP, identificación por mDNS/UPnP/DHCP) | Sí; funciona sin instalar nada más |
| Nmap y Npcap | **No.** Su licencia prohíbe redistribuirlos dentro de otro producto sin una licencia OEM de pago |

**Instalar Nmap desde la propia app:** si Nmap no está, la barra lateral muestra el botón **Instalar Nmap completo**. TrabaMap descarga el instalador oficial directamente de nmap.org, comprueba que tiene una firma digital válida de Nmap Software LLC (si no, lo borra) y lo abre; el usuario solo sigue el asistente de Nmap, que también instala Npcap. Al volver a la ventana, TrabaMap lo detecta solo. Así nadie tiene que buscar ni descargar nada a mano, y no se redistribuye ningún archivo de Nmap (`electron/nmap-setup.cjs`).

Sin Nmap la aplicación abre y trabaja con su **motor integrado**: descubre los equipos de la red, los identifica y revisa sus puertos TCP (16 de las 66 tarjetas del catálogo). Para versiones de servicios, sistema operativo por huella, UDP y scripts NSE hay que instalar Nmap desde [nmap.org](https://nmap.org/download.html); la barra lateral lo indica y enlaza la descarga oficial, y al volver a abrir TrabaMap lo detecta solo.

## Parámetros de seguridad

**Reglas fijas** (dentro del motor, `core/policy.py`; no se pueden apagar):

- Sin evasión ni suplantación: señuelos (`-D`), IP/MAC/puerto de origen falsos, fragmentación, relleno, proxies.
- Sin intermediarios ajenos: escaneo idle (`-sI`) ni rebote FTP (`-b`).
- Sin objetivos ocultos o al azar: ni `-iL` ni `-iR`.
- Sin ataques: scripts de fuerza bruta, denegación de servicio, explotación y fuzzing, ni `unsafe=1`. La categoría `vuln` se ejecuta como `vuln and not (dos or exploit or brute or fuzzer)`.
- Los parámetros van a Nmap como argumentos de proceso, nunca por una consola.

**Parámetros configurables** (sección Seguridad, `electron/security.cjs`; se evalúan en el proceso principal, no en la ventana):

| Parámetro | Valor inicial | Efecto |
| --- | --- | --- |
| Avisar fuera de la red local | Activado | Una IP pública o dominio detiene el escaneo hasta confirmar que hay autorización |
| Confirmar escaneos intrusivos | Activado | `vuln`, `auth`, `malware`, `http-enum`, `-A`… piden confirmación |
| Velocidad máxima T5 | Desactivada | El tope es T4 |
| Tamaño máximo de un escaneo | 1.024 direcciones | Un rango mayor se rechaza |

**Auditoría:** cada escaneo queda en el registro local con fecha, usuario de Windows, objetivo, opciones y confirmaciones aceptadas; los escaneos bloqueados y los cambios de configuración también.

## Android o iPhone con certeza: escucha DHCP

Un celular moderno usa MAC privada y casi no abre puertos, así que un escaneo activo no puede distinguirlo con seguridad. TrabaMap añade una **escucha pasiva de DHCP** (`electron/dhcp.cjs`): cuando un equipo entra al Wi-Fi envía por difusión un mensaje que delata su sistema. Android se presenta como `android-dhcp-14` (con la versión), Windows como `MSFT 5.0`, y iPhone/Mac piden una lista de parámetros exclusiva de Apple. Esas conclusiones son de confianza alta.

La escucha solo ve a los equipos que se conectan o renuevan su dirección mientras TrabaMap está abierto; para identificar uno al instante basta apagar y encender su Wi-Fi. No responde ni reparte direcciones. La primera vez Windows puede preguntar si TrabaMap puede comunicarse en redes privadas: hay que permitirlo.

## Tema y barra lateral

El botón de sol/luna (arriba a la derecha, o en el menú de usuario) cambia entre tema oscuro y claro; la elección se recuerda. Todos los colores salen de variables CSS al inicio y al final de `src/styles.css`.

## Catálogo Nmap: todo sin escribir

La sección **Catálogo Nmap** reúne 66 escaneos listos en ocho categorías (descubrir equipos, puertos, servicios y sistema, web y cifrado, Windows y archivos, revisión de seguridad, red e infraestructura, y todas las técnicas de sondeo). El uso es de dos pasos: se elige el objetivo de una lista ("Este equipo", "Toda mi red", "Mi router" o cualquier dispositivo ya encontrado) y se pulsa **Ejecutar** en una tarjeta. Cada tarjeta muestra el comando exacto que se va a lanzar, cuánto tarda y si necesita Npcap/administrador. La misma lista de objetivos está en el Escáner.

Las tarjetas se definen en `src/catalog.jsx`; añadir una es agregar una línea con sus opciones. El catálogo deja fuera a propósito la fuerza bruta de contraseñas, la denegación de servicio, la explotación y las opciones de evasión.

### Sistema operativo de cada equipo

La lista de Dispositivos muestra primero el sistema y permite filtrar por familia (Windows, Android, iOS, macOS, Linux…). Se decide así, de más a menos fiable:

1. Lectura directa (este equipo, Android por ADB) o lo que el equipo anuncia (versión de Android en UPnP, modelo Apple por mDNS, servicios exclusivos de iOS).
2. Puertos firma: 62078 abierto es iPhone/iPad; 135/445/3389 es Windows; 548 es macOS.
3. Huella `-O` de Nmap, **solo si el equipo tiene algún puerto abierto**; sin eso Nmap devuelve conjeturas y TrabaMap las descarta.
4. Descarte: TTL 128 → Windows; celular sin ninguna señal de Apple → Android (probable); TTL 64 sin más pistas → Linux o derivado. Estas conclusiones se marcan con confianza baja y explican su razonamiento.

## Identificación de dispositivos

Después del descubrimiento (`-sn`), TrabaMap hace una segunda pasada automática para saber **qué es** cada equipo:

| Fuente | Qué aporta | Ejemplo |
| --- | --- | --- |
| mDNS / Bonjour | Servicios y propiedades que el equipo anuncia | Chromecast y Google TV (modelo y nombre), Apple TV, Mac (`MacBookPro18,3`), impresoras (`ty=`), iPhone (`apple-mobdev2`) |
| UPnP / SSDP | La ficha que publica el propio dispositivo | Televisores (fabricante y modelo), routers, consolas, Sonos; versión de Android en la cabecera `SERVER` |
| Puertos firma (Nmap) | 28 puertos que delatan el tipo de equipo | 62078 iPhone/iPad, 8001/8002 Samsung TV, 3000/3001 LG webOS, 8060 Roku, 9100 impresora, 554 cámara, 135/445 Windows |
| NetBIOS (`nbstat`) | Nombre de equipos Windows | `LAPTOP-VENTAS` |
| TTL del ping | Familia del sistema | 128 Windows · 64 Linux/Android/iOS/macOS · 255 equipos de red |
| MAC | Fabricante (OUI) o aviso de MAC privada | Espressif → IoT; MAC aleatoria → celular probable |

El motor (`src/identify.js`) combina las pistas y devuelve tipo, marca, modelo, sistema operativo, un nivel de confianza (alta/media/baja) y la lista de evidencias, visible en la ficha del equipo ("Por qué lo sabemos") y en el Excel. La parte de red está en `electron/discovery.cjs` y solo consulta direcciones privadas de la red local; se puede probar suelta con `node electron/discovery.cjs <tu-ip> [ip ...]`.

Límites reales: los celulares usan MAC privada y casi no anuncian nada, así que suelen quedar como "teléfono o tableta" con confianza baja. Los componentes internos (RAM, procesador, discos) solo se leen de este computador o de un Android autorizado por ADB; de otros equipos no se pueden obtener sin credenciales o un agente instalado.

## Paquete de Windows

```powershell
npm install
npm run package:win
```

Genera en `artifacts/windows/`:

| Archivo | Para qué | Funciona con el Control inteligente de aplicaciones de Windows 11 |
| --- | --- | --- |
| `TrabaMap-1.0.1-win-x64.zip` | **Forma recomendada de compartir la app.** Se descomprime y se abre `TrabaMap.exe` | Sí (comprobado) |
| `TrabaMap-Instalador-1.0.1-x64.exe` | Instalador clásico con accesos directos | No: es un ejecutable sin firma |
| `TrabaMap-Portable-1.0.1-x64.exe` | Un solo archivo que se ejecuta sin instalar | No: es un ejecutable sin firma |

Por qué el .zip funciona donde los .exe no: Windows 11 puede traer activo el **Control inteligente de aplicaciones**, que bloquea cualquier ejecutable sin firma digital que no conozca. El .zip no contiene ninguno propio: usa el ejecutable de Electron tal como lo publica ese proyecto y el intérprete oficial de Python firmado por la Python Software Foundation (`scripts/build-python-runtime.ps1`), y el motor viaja como archivos `.py`. Los instaladores, en cambio, son ejecutables generados aquí y solo dejarían de bloquearse firmándolos con un certificado de firma de código. En equipos sin esa protección, los .exe muestran el aviso de SmartScreen ("Más información → Ejecutar de todas formas").

Consecuencia de no modificar el ejecutable: en el Explorador `TrabaMap.exe` muestra el icono de Electron; la ventana y la barra de tareas sí usan el icono de TrabaMap.

Quien recibe la app no necesita Node.js ni Python. Nmap no va incluido (ver "¿Qué necesita quien recibe el .exe?"). La versión portable guarda su historial en `TrabamapData` junto al ejecutable; las demás, en la carpeta de datos del usuario.

El primer arranque detecta la IP local, el router y el rango de red de la interfaz activa.

## Perfiles y opciones Nmap

- **Rápido:** puertos TCP comunes y detección de servicios.
- **Completo:** todos los puertos TCP.
- **Intensivo:** perfil Nmap `-A` con detección avanzada.
- **Descubrir:** abre el rango detectado y ejecuta `-sn` para listar equipos que respondieron, sin escanear puertos.
- La vista **Dispositivos** cuenta respuestas y muestra IP, nombre, fabricante/MAC cuando Nmap los entrega. Haz clic derecho en un equipo para abrir su ficha; **Escaneo TCP completo** revisa los 65.535 puertos TCP, detecta servicios/versiones y huella de SO, e intenta usar el script SMB `smb-os-discovery` para obtener nombre de equipo, dominio y SO de Windows/Samba cuando esté accesible. El análisis puede tardar y se puede cancelar.
- **Android con ADB:** si `adb` está instalado o se define `TRABAMAP_ADB`, TrabaMap consulta los teléfonos que ya están autorizados en ADB. Lee fabricante, modelo, versión/parche de Android, memoria, procesador y almacenamiento que el sistema expone. No empareja ni activa depuración automáticamente; para USB acepta la autorización en el teléfono y para Wi-Fi empareja la depuración inalámbrica desde Android. Los datos aparecen en la ficha del equipo y en la hoja **Android ADB** del Excel.
- **iPhone/iPad:** el sistema operativo y el inventario de hardware requieren un servidor MDM existente y que el dispositivo esté inscrito. TrabaMap no incluye un servidor MDM ni puede obtener esa información con un escaneo de red.
- Cuando escaneas este mismo equipo en Windows, TrabaMap usa consultas locales del sistema para mostrar Windows real, versión/compilación, usuario de la sesión, RAM, CPU, placa, gráficos, discos y puertos TCP en escucha asociados al nombre del proceso. En puertos abiertos de Nmap muestra el proceso local asociado cuando se puede identificar. En macOS/Linux muestra los datos básicos que el sistema operativo comparte con Electron; el mapeo local de procesos TCP aún está disponible solo en Windows.
- En opciones avanzadas: TCP Connect, SYN, UDP, TCP+UDP, ACK, Window, Maimon, FIN, NULL, Xmas, SCTP INIT/Cookie, idle, protocolos IP, descubrimiento y list scan; rangos de puertos; detección de servicios/SO; categorías y argumentos NSE; traceroute; DNS; IPv6; y temporización `-T0` a `-T5`.
- El campo **Otros parámetros Nmap** acepta opciones adicionales de Nmap como argumentos de proceso, sin invocar un shell. El objetivo y la salida XML que necesita la app permanecen administrados por TrabaMap; también permite guardar salidas normales, grepables o script-kiddie con `-oN`, `-oG` y `-oS`.
- El manual en español enlazado en la aplicación declara que describe Nmap 4.00. La referencia inglesa enlazada allí corresponde a la guía vigente.

Las opciones dependen de la plataforma y los permisos. Un equipo que no respondió no necesariamente está desconectado: puede estar dormido, filtrando sondas o aislado por el punto de acceso. Nmap no puede decir cuántas personas están conectadas. La identificación del dispositivo y el sistema operativo es una inferencia; depende de las huellas disponibles, y Android/iOS o una distribución concreta pueden quedar sin determinar. Los nombres de marca se estiman a partir del fabricante de la interfaz de red o del nombre anunciado; las MAC aleatorias pueden ocultar esa pista y no permiten confirmar el modelo. Los scripts NSE pueden enviar solicitudes al objetivo; usa solo sistemas propios o autorizados. La categoría `vuln` es opcional y no se activa por defecto.

En otros equipos de la red, la ficha presenta lo que Nmap recibió durante el análisis. No puede consultar de forma genérica su RAM, componentes internos ni usuario conectado. Para ese inventario remoto hace falta instalar un agente o habilitar administración autenticada y autorizada en cada equipo: por ejemplo WMI/WinRM en Windows, SSH o un agente en Linux/macOS, ADB emparejado en Android o MDM con el dispositivo inscrito en iOS. TrabaMap no instala agentes ni obtiene acceso a esos dispositivos automáticamente.

## Resultados y privacidad

- Resultados estructurados desde el XML original de Nmap, con direcciones MAC/fabricante, clases de dispositivo, candidatos de SO, uptime, distancia de red y CPE cuando están disponibles.
- Servicios, versiones, estado y motivo del puerto, sistema operativo probable, resultados NSE, trazado de red y estadísticas del análisis cuando están disponibles.
- Riesgo y recomendaciones explicados en español. La valoración es orientativa; un puerto abierto no demuestra una vulnerabilidad.
- En el historial, cada informe se divide en pestañas de resumen, dispositivos, puertos, scripts NSE y método/límites; el listado se puede filtrar por puertos abiertos o elementos para revisar.
- Exportación a Excel desde el escáner, la lista de dispositivos o el detalle del historial. El libro usa hojas claras para resumen, dispositivos y MAC/OUI, puertos abiertos con significado y recomendaciones, componentes del equipo local, Android autorizado por ADB y una guía de lectura. Los encabezados se mantienen visibles y las listas se pueden filtrar. Se guarda en `%APPDATA%\trabamap\reports` y se intenta abrir con la aplicación asociada a `.xlsx`.
- Historial y registro de actividad locales, con exportación del JSON de TrabaMap y del XML de Nmap.
- La interfaz detecta y muestra las IP e interfaces locales. Los reportes se guardan en `%APPDATA%\trabamap\reports` en Windows.
- Los datos no se envían a un servicio en la nube. La versión exacta de Android/iOS, los procesos internos de un móvil y la RAM/usuario de otro computador no aparecen automáticamente en un escaneo de red. La ficha y el Excel dejan esos datos como no confirmados si el equipo no los revela; el producto/versión de una aplicación remota solo se muestra si respondió a la detección de servicios de Nmap. El proceso y PID se muestran para el propio Windows cuando el inventario local los puede relacionar.

## CLI

```powershell
.\tmap.cmd scan localhost --rapido
.\tmap.cmd help
py -3 main.py scan localhost --rapido
py -3 main.py scan 192.168.1.10 --completo --guardar
py -3 main.py version
py -3 main.py about
```

En Windows, `tmap.cmd` es el lanzador local. Para escribir `tmap` desde cualquier carpeta, agrega la carpeta del proyecto al `PATH` de usuario.

La aplicación se ejecuta con Electron y React; el proceso principal de Electron usa un preload limitado y delega la ejecución y lectura de Nmap a Python.

## Solución de problemas

- Si escribiste `npm run devvc`, el comando correcto para abrir la app es `npm run desktop`.
- TrabaMap busca Nmap en el `PATH` y en las rutas habituales de Windows. Si lo instalaste en otra carpeta, define `NMAP_PATH` con la ruta completa de `nmap.exe` y vuelve a abrir la aplicación.
- La carpeta `nmap-master` se conserva como referencia, pero Vite la excluye de la observación para evitar recargas innecesarias.
