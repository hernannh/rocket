# Rocket

**Toolkit de Analisis de Logs para Blue Teams** — Convierte cualquier formato de log a CSV o JSON estructurado en segundos. Un unico binario estatico que parsea, filtra, correlaciona y enriquece logs de firewalls, SIEM, Windows EVTX, syslog y mas.

Rocket fue creado para analistas SOC, respondedores de incidentes e investigadores forenses que necesitan procesar logs rapido, en cualquier maquina, sin instalar dependencias.

---

## Por que Rocket?

- **Exportacion CSV & JSON** — Convierte cualquier formato de log a CSV estructurado (Excel, bases de datos) o JSON Lines (jq, Splunk, Elasticsearch). Selecciona campos especificos con `--fields` para reducir ruido. El valor central de Rocket.
- **Binario estatico unico** (4.5 MB) — Copialo a cualquier maquina via SCP y ejecutalo. Sin Python, sin Java, sin runtime. Funciona en estaciones de trabajo forense, servidores comprometidos, sistemas air-gapped.
- **8 formatos de logs** con auto-deteccion — keyvalue, json, syslog, cef, leef, apache, w3c, y Windows EVTX (parseo binario nativo). Lee archivos `.gz` comprimidos de forma transparente.
- **Filtrado avanzado** — Busqueda de texto, exclusion, regex, rangos de fecha, deduplicacion. Pipe desde stdin, salida a stdout. Combina filtros libremente.
- **I/O Streaming** — Maneja archivos de multiples GB sin cargarlos en memoria. 500K+ registros/segundo en syslog. Procesamiento concurrente con workers configurables.
- **Inteligencia de amenazas integrada** — Extraccion de IOCs, motor de reglas Sigma, resolucion GeoIP y constructor de timelines en una sola herramienta.

---

## Tabla de Contenidos

- [Instalacion](#instalacion)
- [Inicio Rapido](#inicio-rapido)
- [Formatos de Log Soportados](#formatos-de-log-soportados)
- [Comandos](#comandos)
  - [parse](#parse) — Convertir logs a CSV/JSON
  - [stats](#stats) — Triage rapido y analisis de campos
  - [ioc](#ioc) — Extraer Indicadores de Compromiso
  - [timeline](#timeline) — Linea temporal unificada
  - [sigma](#sigma) — Motor de reglas de deteccion Sigma
  - [geoip](#geoip) — Geolocalizacion de IPs con GeoLite2
  - [tail](#tail) — Monitoreo de logs en tiempo real
  - [merge](#merge) — Combinar multiples archivos CSV
  - [formats](#formats) — Listar formatos soportados
  - [version](#version) — Informacion del build
- [Filtros](#filtros)
- [Formatos de Salida](#formatos-de-salida)
- [Casos de Uso](#casos-de-uso)
- [Rendimiento](#rendimiento)
- [Configuracion de Base de Datos GeoIP](#configuracion-de-base-de-datos-geoip)
- [Reglas Sigma](#reglas-sigma)
- [Plataformas Soportadas](#plataformas-soportadas)

---

## Instalacion

Descarga el binario para tu plataforma desde la pagina de [Releases](https://github.com/socketsar/rocket/releases).

### Linux (amd64)

```bash
chmod +x rocket-linux-amd64
sudo mv rocket-linux-amd64 /usr/local/bin/rocket
```

### macOS

```bash
chmod +x rocket-darwin-arm64
sudo mv rocket-darwin-arm64 /usr/local/bin/rocket
```

### Windows

Descarga `rocket-windows-amd64.exe` y agregalo al PATH, o ejecutalo directamente.

### Verificar instalacion

```bash
rocket version
```

---

## Inicio Rapido

```bash
# Parsear un archivo de log (auto-detecta el formato)
rocket parse access.log

# Parsear un directorio recursivamente y unificar resultados
rocket parse /var/log/ -r --merge -o ./output/

# Triage rapido — top IPs, eventos, usuarios
rocket stats Security.evtx --fields event_id,Event.EventData.TargetUserName --top 15

# Extraer IOCs (IPs, dominios, hashes, URLs)
rocket ioc firewall.log --top 20

# Construir una linea temporal desde multiples fuentes
rocket timeline Security.evtx syslog firewall.log -o timeline.csv

# Aplicar reglas de deteccion Sigma
rocket sigma Security.evtx --rules ./sigma-rules/

# Resolver GeoIP de IPs atacantes
rocket geoip firewall.log --db ./geodb/ --top 20

# Monitorear un archivo de log en tiempo real
rocket tail /var/log/syslog -f --filter "fail" --format syslog
```

---

## Formatos de Log Soportados

| Formato | Descripcion | Auto-deteccion | Ejemplos |
|---|---|---|---|
| **keyvalue** | Pares Key=value | Si | FortiGate, FortiAnalyzer, Palo Alto, logs de aplicaciones |
| **json** | JSON Lines / NDJSON | Si | Elasticsearch, CloudWatch, Docker, logs estructurados |
| **syslog** | BSD, RFC 5424, RFC 3339 | Si | Linux syslog, rsyslog, systemd-journal, dispositivos de red |
| **cef** | ArcSight Common Event Format | Si | ArcSight, FortiSIEM, CrowdStrike, cualquier fuente CEF |
| **leef** | IBM QRadar LEEF 1.0/2.0 | Si | QRadar, productos de seguridad IBM |
| **apache** | Combined y Common Log Format | Si | Apache, Nginx (con formato common log), HAProxy |
| **w3c** | W3C Extended Log Format | Si | IIS, Microsoft TMG, algunos proveedores CDN |
| **evtx** | Windows Event Log (binario) | Por extension | Security.evtx, System.evtx, Application.evtx |

### Auto-deteccion de formato

Rocket muestrea las primeras 20 lineas de cada archivo y las evalua contra todos los parsers registrados. Se selecciona el parser con mayor puntaje de confianza. Para archivos EVTX, la deteccion se basa en la extension `.evtx`.

Podes forzar un formato especifico con `--format` / `-f`:

```bash
rocket parse mixed.log --format syslog
rocket parse data.txt -f keyvalue
```

---

## Comandos

### parse

Convierte uno o mas archivos de log a formato CSV o JSON.

```
rocket parse <input> [flags]
```

**Flags:**

| Flag | Corto | Descripcion |
|---|---|---|
| `--output` | `-o` | Directorio de salida (default: mismo que el input) |
| `--format` | `-f` | Formato de log: auto, keyvalue, json, syslog, cef, leef, apache, w3c, evtx (default: auto) |
| `--output-format` | | Formato de salida: csv, json (default: csv) |
| `--filter` | | Conservar solo lineas que contengan este texto (case-insensitive) |
| `--exclude` | | Excluir lineas que contengan este texto (case-insensitive) |
| `--regex` | | Conservar solo lineas que coincidan con este patron regex |
| `--fields` | | Lista de campos separados por coma para incluir en la salida |
| `--date-range` | | Filtro por rango de fechas: YYYY-MM-DD:YYYY-MM-DD |
| `--dedup` | | Eliminar registros duplicados |
| `--dedup-fields` | | Campos a usar para deduplicacion (default: linea completa) |
| `--recursive` | `-r` | Escanear subdirectorios recursivamente |
| `--merge` | | Unificar todas las salidas en un solo archivo |
| `--workers` | `-w` | Numero de workers concurrentes (default: 4) |
| `--stdout` | | Escribir la salida a stdout en lugar de archivos |

**Ejemplos:**

```bash
# Conversion basica
rocket parse access.log
rocket parse /var/log/app/ -r -o ./output/

# Filtro y seleccion de campos
rocket parse firewall.log --filter "blocked" --fields srcip,dstip,action,attack
rocket parse syslog --exclude "CRON" --fields timestamp,program,message

# Filtrado por regex
rocket parse firewall.log --regex 'CVE-\d{4}-\d+'
rocket parse auth.log --regex 'Failed password.*from \d+\.\d+'

# Rango de fechas
rocket parse /var/log/ -r --date-range 2026-03-01:2026-03-31

# Salida JSON con pipe a jq
rocket parse firewall.log --output-format json --stdout | jq '.srcip'

# Deduplicacion
rocket parse firewall.log --dedup --dedup-fields srcip,attack

# Windows Event Logs
rocket parse Security.evtx -o ./output/
rocket parse C:\Windows\System32\winevt\Logs\ -r --merge

# Multiples archivos de entrada
rocket parse server1.log server2.log server3.log -o ./merged/ --merge

# Leer desde stdin (pipe)
cat /var/log/syslog | rocket parse -f syslog --fields program,message -
ssh servidor-forense "cat /var/log/auth.log" | rocket parse -f syslog --filter "Failed" -

# Archivos comprimidos (.gz)
rocket parse /var/log/syslog.2.gz /var/log/syslog.3.gz -o ./output/

# Procesamiento batch de alto rendimiento
rocket parse /evidence/logs/ -r --workers 8 --merge -o ./case-output/
```

**Tipos de entrada soportados:**
- Archivo unico: `rocket parse access.log`
- Multiples archivos: `rocket parse file1.log file2.log file3.log`
- Directorio: `rocket parse /var/log/`
- Directorio (recursivo): `rocket parse /var/log/ -r`
- Patron glob: `rocket parse "*.log"`
- Comprimido gzip: `rocket parse syslog.2.gz`
- Stdin: `cat file | rocket parse -f syslog -`

---

### stats

Triage rapido — analiza archivos de log y muestra los valores mas frecuentes por campo sin generar archivos de salida.

```
rocket stats <input> [flags]
```

**Flags:**

| Flag | Corto | Descripcion |
|---|---|---|
| `--format` | `-f` | Formato de log (default: auto) |
| `--fields` | | Campos a analizar separados por coma (default: todos) |
| `--top` | | Cantidad de valores top por campo (default: 10) |
| `--recursive` | `-r` | Escanear subdirectorios |

**Ejemplos:**

```bash
# Vista general de todos los campos
rocket stats access.log

# Enfocarse en campos especificos
rocket stats firewall.log --fields srcip,attack,severity,srccountry --top 15

# Triage de Windows Event Log
rocket stats Security.evtx --fields event_id,Event.EventData.TargetUserName,Event.EventData.LogonType

# Analisis de servicios en syslog
rocket stats /var/log/syslog -r --format syslog --fields program,hostname --top 20
```

**Ejemplo de salida:**

```
=== Summary ===
Total records: 613
Unique fields: 4

--- attack (19 unique values) ---
       186  Mirai.Botnet
       134  ZGrab.Scanner
        75  Nmap.Script.Scanner
        33  Apache.HTTP.Server.cgi-bin.Path.Traversal
        32  WordPress.REST.API.Username.Enumeration.Information.Disclosure
  ... and 14 more

--- srcip (351 unique values) ---
        18  45.205.1.20
        15  172.233.29.203
        15  20.43.23.11
  ... and 346 more
```

---

### ioc

Extrae Indicadores de Compromiso (IOCs) de archivos de log.

```
rocket ioc <input> [flags]
```

**Tipos de IOC soportados:**

| Tipo | Descripcion | Ejemplo |
|---|---|---|
| `ipv4` | Direcciones IPv4 (solo publicas) | `45.205.1.20` |
| `ipv6` | Direcciones IPv6 | `2001:db8::1` |
| `domain` | Nombres de dominio | `evil.example.com` |
| `url` | URLs HTTP/HTTPS | `https://malware.site/payload` |
| `email` | Direcciones de correo electronico | `attacker@evil.com` |
| `md5` | Hashes MD5 (32 caracteres hex) | `d41d8cd98f00b204e9800998ecf8427e` |
| `sha1` | Hashes SHA1 (40 caracteres hex) | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| `sha256` | Hashes SHA256 (64 caracteres hex) | `e3b0c44298fc1c149afbf4c8996fb924...` |

Los rangos de IP privados/reservados (10.x, 172.16.x, 192.168.x, 127.x) se excluyen automaticamente.

**Flags:**

| Flag | Corto | Descripcion |
|---|---|---|
| `--format` | `-f` | Formato de log (default: auto) |
| `--types` | | Tipos de IOC a extraer separados por coma (default: todos) |
| `--output-format` | | Salida: text, json (default: text) |
| `--top` | | Cantidad de IOCs top por tipo (default: 20) |
| `--recursive` | `-r` | Escanear subdirectorios |

**Ejemplos:**

```bash
# Extraer todos los IOCs
rocket ioc firewall.log

# Solo IPs y dominios
rocket ioc access.log --types ipv4,domain --top 30

# Salida JSON para integracion con otras herramientas
rocket ioc /var/log/ -r --output-format json > iocs.json

# Desde archivos EVTX
rocket ioc Security.evtx --types ipv4,domain

# Desde stdin
cat syslog | rocket ioc - -f syslog --types ipv4
```

---

### timeline

Construye una linea temporal cronologica unificada desde multiples fuentes de log. Esencial para la reconstruccion de incidentes.

```
rocket timeline <input> [inputs...] [flags]
```

Cada evento se enriquece con:
- `timeline_ts` — Timestamp normalizado para ordenamiento
- `source` — Ruta del archivo original

**Flags:**

| Flag | Corto | Descripcion |
|---|---|---|
| `--output` | `-o` | Ruta del archivo de salida (default: timeline.csv) |
| `--format` | `-f` | Formato de log (default: auto por archivo) |
| `--output-format` | | Salida: csv, json (default: csv) |
| `--fields` | | Campos a incluir separados por coma |
| `--filter` | | Conservar solo lineas que contengan este texto |
| `--exclude` | | Excluir lineas que contengan este texto |
| `--recursive` | `-r` | Escanear subdirectorios |

**Ejemplos:**

```bash
# Combinar logs de Windows + Linux + Firewall
rocket timeline Security.evtx syslog firewall.log -o timeline.csv

# Timeline en JSON para ingesta en Elastic/Splunk
rocket timeline /evidence/ -r --output-format json -o timeline.json

# Timeline filtrado
rocket timeline Security.evtx auth.log --filter "failed" --fields timeline_ts,source,message

# Enfocarse en una ventana de tiempo especifica
rocket timeline /evidence/ -r -o timeline.csv
# Luego filtrar el CSV por fecha segun se necesite
```

**Ejemplo de salida:**

```
[+] Building timeline from 3 file(s)...
[+] Processing Security.evtx...
[+] Processing syslog...
[+] Processing firewall.log...
[+] Sorting 33245 events chronologically...
[+] Timeline: 33245 events -> timeline.csv
[+] Time range: 2026-03-13 00:00:00 to 2026-03-30 21:12:30
```

---

### sigma

Aplica reglas de deteccion Sigma contra registros de log parseados. Sigma es el estandar abierto para reglas de deteccion SIEM utilizado por la comunidad de ciberseguridad.

```
rocket sigma <input> [flags]
```

**Flags:**

| Flag | Corto | Descripcion |
|---|---|---|
| `--rules` | | Ruta al directorio de reglas Sigma o archivo .yml individual **(requerido)** |
| `--format` | `-f` | Formato de log (default: auto) |
| `--output-format` | | Salida: text, json (default: text) |
| `--output` | `-o` | Archivo de salida (default: stdout) |
| `--recursive` | `-r` | Escanear subdirectorios |

**Funcionalidades Sigma soportadas:**

| Funcionalidad | Soporte |
|---|---|
| Coincidencia de campos (exacta) | Si |
| Modificadores de campo: `contains`, `startswith`, `endswith` | Si |
| Coincidencia con comodines (`*`) | Si |
| Condiciones: `and`, `or`, `not` | Si |
| Condiciones: `1 of them`, `all of them` | Si |
| Condiciones: `1 of selection_*`, `all of selection_*` | Si |
| Listas de palabras clave (buscar en todos los campos) | Si |
| Parentesis en condiciones | Si |

**Ejemplos:**

```bash
# Escanear con un directorio de reglas
rocket sigma Security.evtx --rules ./sigma-rules/

# Regla individual
rocket sigma firewall.log --rules mirai_detection.yml

# Salida JSON para procesamiento adicional
rocket sigma /var/log/ -r --rules ./rules/ --output-format json -o detections.json

# Combinar con syslog
rocket sigma auth.log --rules brute_force.yml --format syslog
```

**Ejemplo de regla Sigma:**

```yaml
title: Deteccion de Botnet Mirai
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
level: critical
description: Detecta actividad de botnet Mirai en logs IPS
logsource:
    category: ids
    product: fortigate
detection:
    selection:
        attack|contains: Mirai
    condition: selection
```

**Ejemplo de regla Sigma para Windows:**

```yaml
title: Inicio de Sesion por Escritorio Remoto Detectado
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: stable
level: medium
description: Detecta eventos de logon RDP (LogonType 10)
logsource:
    product: windows
    service: security
detection:
    selection:
        event_id: '4624'
        Event.EventData.LogonType: '10'
    condition: selection
```

Podes usar reglas del repositorio comunitario [SigmaHQ](https://github.com/SigmaHQ/sigma).

---

### geoip

Resuelve datos de geolocalizacion (pais, ASN, organizacion) para direcciones IP encontradas en archivos de log.

```
rocket geoip <input> [flags]
```

**Flags:**

| Flag | Corto | Descripcion |
|---|---|---|
| `--db` | | Ruta al archivo mmdb o directorio con archivos mmdb **(requerido)** |
| `--format` | `-f` | Formato de log (default: auto) |
| `--fields` | | Campos donde buscar IPs (default: todos) |
| `--top` | | Cantidad de IPs top a mostrar (default: 20) |
| `--recursive` | `-r` | Escanear subdirectorios |

**Ejemplos:**

```bash
# Geolocalizacion basica
rocket geoip firewall.log --db ./GeoLite2-Country.mmdb

# Multiples bases de datos (directorio)
rocket geoip firewall.log --db ./geodb/ --top 30

# Enfocarse en campos de IP especificos
rocket geoip firewall.log --db ./geodb/ --fields srcip,dstip

# Archivos EVTX
rocket geoip Security.evtx --db ./geodb/
```

**Ejemplo de salida:**

```
=== GeoIP Resolution (160 unique public IPs) ===

COUNT     IP                  CC   COUNTRY                 ASN       ORGANIZATION
--------  ------------------  ---  ----------------------  --------  ------------
43        172.93.48.52        US   United States           29802     HIVELOCITY, Inc.
22        87.251.64.141       US   United States           200730    ISAEV Igor
18        45.205.1.20         US   United States           215925    Vpsvault.host Ltd
15        20.43.23.11         CA   Canada                  8075      Microsoft Corporation
15        172.233.29.203      BR   Brazil                  63949     Akamai Connected Cloud

=== Events by Country ===

       402  Argentina
       220  United States
        84  Vietnam
        62  The Netherlands
```

Ver [Configuracion de Base de Datos GeoIP](#configuracion-de-base-de-datos-geoip) para instrucciones de descarga.

---

### tail

Monitorea un archivo de log en tiempo real con parseo estructurado, filtrado y formato. Como `tail -f` pero con inteligencia.

```
rocket tail <file> [flags]
```

**Flags:**

| Flag | Corto | Descripcion |
|---|---|---|
| `--follow` | `-f` | Seguir el archivo por nuevas lineas (como tail -f) |
| `--format` | | Formato de log (default: auto) |
| `--filter` | | Conservar solo lineas que contengan este texto |
| `--exclude` | | Excluir lineas que contengan este texto |
| `--regex` | | Conservar solo lineas que coincidan con este regex |
| `--fields` | | Campos a mostrar separados por coma |
| `--output-format` | | Salida: text, json, csv (default: text) |

**Ejemplos:**

```bash
# Monitoreo en tiempo real
rocket tail /var/log/syslog -f --format syslog

# Filtrar por fallas
rocket tail /var/log/auth.log -f --filter "fail" --format syslog

# Mostrar campos especificos
rocket tail /var/log/syslog -f --fields timestamp,program,message --format syslog

# Salida JSON para piping
rocket tail firewall.log -f --output-format json --fields srcip,action

# Excluir ruido
rocket tail /var/log/syslog -f --exclude "CRON" --format syslog

# Coincidencia con regex
rocket tail access.log -f --regex "5\d{2}" --fields timestamp,status,request_uri
```

**Ejemplo de salida (modo texto):**

```
timestamp=2026-03-30T16:40:39.066646-03:00 | program=update-cloudflare-ips.sh | message=[*] Verificando sintaxis de Nginx...
timestamp=2026-03-30T16:40:39.307969-03:00 | program=systemd | message=nginx.service: Unit cannot be reloaded because it is inactive.
```

---

### merge

Combina multiples archivos CSV en un unico CSV unificado. Maneja archivos con conjuntos de columnas diferentes creando una union de todos los headers.

```
rocket merge <file1.csv> <file2.csv> [files...] [flags]
```

**Flags:**

| Flag | Corto | Descripcion |
|---|---|---|
| `--output` | `-o` | Ruta del archivo de salida (default: merged_logs.csv) |

**Ejemplos:**

```bash
rocket merge output1.csv output2.csv -o merged.csv
rocket merge *.csv -o all_logs.csv
```

---

### formats

Lista todos los formatos de log soportados.

```bash
rocket formats
```

**Salida:**

```
FORMAT    DESCRIPTION
------    -----------
keyvalue  Key=value pairs (e.g., user=admin action=login status="ok")
json      JSON lines / NDJSON (one JSON object per line)
syslog    Syslog (BSD, RFC 5424, and RFC 3339/rsyslog formats)
cef       ArcSight Common Event Format (CEF)
leef      IBM QRadar Log Event Extended Format (LEEF 1.0/2.0)
apache    Apache access logs (Combined and Common Log Format)
w3c       W3C Extended Log File Format (IIS, proxies)
evtx      Windows Event Log (.evtx) — Security, System, Application
```

---

### version

Muestra informacion del build.

```bash
rocket version
```

```
rocket v1.0.0
  commit:  a1b2c3d
  built:   2026-03-30T20:00:00Z
  go:      go1.22.0
  os/arch: linux/amd64
```

---

## Filtros

Rocket provee multiples mecanismos de filtrado que se pueden combinar:

| Filtro | Flag | Descripcion |
|---|---|---|
| Texto (incluir) | `--filter "ERROR"` | Coincidencia de subcadena (case-insensitive) |
| Texto (excluir) | `--exclude "CRON"` | Exclusion de subcadena (case-insensitive) |
| Regex | `--regex 'CVE-\d{4}-\d+'` | Coincidencia con patron regex completo |
| Rango de fechas | `--date-range 2026-03-01:2026-03-31` | Rango de fechas ISO (inclusivo) |
| Dedup | `--dedup` | Eliminar lineas duplicadas exactas |
| Dedup por campos | `--dedup --dedup-fields srcip,attack` | Dedup por combinacion de campos especificos |
| Seleccion de campos | `--fields srcip,attack,severity` | Solo incluir estas columnas en la salida |

**Los filtros se pueden combinar:**

```bash
rocket parse firewall.log \
  --filter "blocked" \
  --exclude "scanner" \
  --regex 'srcip=45\.' \
  --date-range 2026-03-01:2026-03-31 \
  --dedup --dedup-fields srcip,attack \
  --fields srcip,attack,severity,srccountry
```

---

## Formatos de Salida

### CSV (default)

CSV estandar con headers. Compatible con Excel, Google Sheets, LibreOffice, pandas, bases de datos.

```bash
rocket parse firewall.log -o ./output/
```

### JSON Lines (NDJSON)

Un objeto JSON por linea. Compatible con `jq`, Splunk, Elasticsearch, Logstash, scripts personalizados.

```bash
rocket parse firewall.log --output-format json -o ./output/
```

### Pipe a jq

```bash
rocket parse firewall.log --output-format json --stdout | jq 'select(.severity == "critical")'
rocket parse firewall.log --output-format json --stdout | jq -r '.srcip' | sort -u
rocket parse Security.evtx --output-format json --stdout | jq 'select(.event_id == "4625")'
```

### Pipe a otras herramientas

```bash
# Contar IPs unicas
rocket parse firewall.log --fields srcip --stdout | tail -n +2 | sort -u | wc -l

# Alimentar a grep
rocket parse firewall.log --output-format json --stdout | grep "Mirai"

# Importar a SQLite
rocket parse firewall.log -o output.csv
sqlite3 analysis.db ".import --csv output.csv logs"
```

---

## Casos de Uso

### Respuesta a Incidentes

```bash
# 1. Recolectar evidencia de multiples fuentes
scp target:/var/log/syslog* ./evidence/
scp target:/var/log/auth.log* ./evidence/
# Copiar EVTX desde Windows (via WinSCP, imagen forense, etc.)

# 2. Construir una linea temporal unificada
rocket timeline ./evidence/ -r -o timeline.csv

# 3. Triage rapido
rocket stats ./evidence/ -r --fields program,hostname,event_id

# 4. Extraer IOCs
rocket ioc ./evidence/ -r --output-format json > iocs.json

# 5. Aplicar reglas de deteccion Sigma
rocket sigma ./evidence/ -r --rules ./sigma-rules/ --output-format json > detections.json

# 6. Resolucion GeoIP de IPs atacantes
rocket geoip ./evidence/ -r --db ./geodb/ --top 50
```

### Threat Hunting

```bash
# Encontrar movimiento lateral (sesiones RDP)
rocket parse Security.evtx --output-format json --stdout | \
  jq 'select(.event_id == "4624") | select(.["Event.EventData.LogonType"] == "10")'

# Buscar ataques de path traversal
rocket parse firewall.log --regex '\.\./|%2e%2e' --fields srcip,url,attack

# Encontrar patrones de fuerza bruta
rocket parse auth.log -f syslog --filter "Failed password" --fields timestamp,message

# Extraer todas las CVEs siendo explotadas
rocket parse firewall.log --regex 'CVE-\d{4}-\d+' --fields srcip,attack,cve --output-format json --stdout | \
  jq -r '.cve' | sort | uniq -c | sort -rn
```

### Operaciones Diarias del SOC

```bash
# Triage matutino — que paso durante la noche
rocket stats /var/log/fortigate.log --fields attack,severity,srcip --top 10

# Monitoreo en tiempo real durante un incidente
rocket tail /var/log/syslog -f --filter "fail" --format syslog --fields timestamp,program,message

# Procesar exportacion de FortiAnalyzer
rocket parse ./forti-export/ -r --merge -o ./daily-report/ --workers 8

# Filtrar falsos positivos conocidos
rocket parse firewall.log --exclude "scanner" --exclude "monitor" --fields srcip,attack,severity
```

### Analisis Forense

```bash
# Procesar Windows Event Logs desde imagen de disco
rocket parse /mnt/evidence/Windows/System32/winevt/Logs/ -r -o ./case-42/

# Enfocarse en eventos de seguridad relevantes
rocket parse Security.evtx --output-format json --stdout | \
  jq 'select(.event_id == "4688")' | \  # Creacion de procesos
  jq 'select(.["Event.EventData.NewProcessName"] | test("powershell|cmd|wscript"))'

# Descomprimir y procesar logs rotados
rocket parse /mnt/evidence/var/log/syslog* /mnt/evidence/var/log/auth.log* -o ./case-42/
```

---

## Rendimiento

Benchmarks con archivos de log reales:

| Fuente | Tamano | Registros | Tiempo | Throughput |
|---|---|---|---|---|
| FortiAnalyzer (3 archivos) | 5.5 MB | 5,914 | 0.21s | 28,162 registros/s |
| Linux syslog (5 archivos, 3 .gz) | 2.9 MB | 61,215 | 0.12s | 510,125 registros/s |
| Windows EVTX (3 archivos) | 51 MB | 113,030 | 5.3s | 21,325 registros/s |
| Timeline (EVTX + syslog + FW) | Mixto | 33,245 | 2.1s | 15,831 registros/s |

- El procesamiento concurrente escala con los nucleos de CPU disponibles (configurable con `--workers`)
- Los archivos gzip se descomprimen al vuelo sin overhead de disco
- El uso de memoria se mantiene constante independientemente del tamano del archivo (streaming I/O)

---

## Configuracion de Base de Datos GeoIP

Rocket utiliza bases de datos MaxMind GeoLite2 en formato MMDB. Son gratuitas y se actualizan regularmente.

### Descargar bases de datos

```bash
mkdir -p geodb
wget -O geodb/GeoLite2-Country.mmdb \
  "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
wget -O geodb/GeoLite2-ASN.mmdb \
  "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"
wget -O geodb/GeoLite2-City.mmdb \
  "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
```

### Uso

```bash
# Apuntar a directorio (auto-detecta tipos de base de datos)
rocket geoip firewall.log --db ./geodb/

# Apuntar a archivo individual
rocket geoip firewall.log --db ./geodb/GeoLite2-Country.mmdb
```

El flag `--db` acepta:
- Un directorio con archivos `.mmdb` (auto-detecta Country, ASN, City por nombre de archivo)
- Un archivo `.mmdb` individual

---

## Reglas Sigma

### Que es Sigma?

[Sigma](https://github.com/SigmaHQ/sigma) es un estandar abierto para escribir reglas de deteccion que se pueden compartir entre sistemas SIEM. Rocket incluye un motor Sigma integrado que evalua reglas directamente contra los registros de log parseados.

### Usar reglas de la comunidad

```bash
# Clonar el repositorio SigmaHQ
git clone https://github.com/SigmaHQ/sigma.git

# Escanear logs de Windows contra reglas de Windows
rocket sigma Security.evtx --rules ./sigma/rules/windows/

# Escanear logs web contra reglas web
rocket sigma access.log --rules ./sigma/rules/web/
```

### Escribir reglas personalizadas

Crea un archivo `.yml` siguiendo la especificacion Sigma:

```yaml
title: Deteccion de Fuerza Bruta SSH
id: uuid-unico-aqui
status: stable
level: high
description: Detecta multiples intentos fallidos de login SSH
logsource:
    product: linux
    service: auth
detection:
    selection:
        program: sshd
        message|contains: "Failed password"
    condition: selection
```

```bash
rocket sigma /var/log/auth.log --rules brute_force_ssh.yml -f syslog
```

---

## Plataformas Soportadas

| Plataforma | Arquitectura | Binario |
|---|---|---|
| Linux | amd64 | `rocket-linux-amd64` |
| Linux | arm64 | `rocket-linux-arm64` |
| Windows | amd64 | `rocket-windows-amd64.exe` |
| macOS | amd64 (Intel) | `rocket-darwin-amd64` |
| macOS | arm64 (Apple Silicon) | `rocket-darwin-arm64` |

Todos los binarios son:
- Enlazados estaticamente (sin dependencias de librerias compartidas)
- Compilados con `CGO_ENABLED=0` (Go puro)
- Sin simbolos de depuracion (`-s -w`)
- Listos para ejecutar en cualquier maquina sin instalacion

---

## Licencia

Licenciado bajo [Apache License 2.0](LICENSE). Eres libre de usar, modificar y distribuir este software. Se requiere atribucion al autor original.

---

Desarrollado por [Sockets.AR](https://socketsar.com) - Soluciones IT & Ciberseguridad
