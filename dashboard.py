#!/usr/bin/env python3
"""
dashboard.py - Panel web para Pi-hole o AdGuard Home + Unbound
Autor: nexo (Dark)
v4.5 - Verificaciones efectivas, instantáneas y plazo total de lectura HTTP.
v4.4 - Solo lectura por defecto, autenticación privada y conexiones limitadas.
v4.3 - Identidad visual compartida con el TUI y acento según el motor activo.
v4.2 - Sigue al motor activo: lee ENGINE de /etc/nexo-dns.conf y saca los
       datos de gravity.db o de AdGuardHome.yaml + querylog.json.
v4.1 - Alineado con nexo-dns.sh y endurecido para uso en red.

Uso:
    sudo python3 dashboard.py [--port 8080] [--host 0.0.0.0] [--auth usuario:password]
"""
import http.server
import subprocess
import re
import os
import sys
import argparse
import base64
import hmac
import html as html_lib
import io
import ipaddress
import json
import secrets
import urllib.parse
import socket
import threading
import stat
import time
from datetime import datetime, timedelta, timezone

# --- Utilidades de sistema ---
SUDO = [] if getattr(os, "geteuid", lambda: 1)() == 0 else ["sudo", "-n"]

NEXO_CONF = "/etc/nexo-dns.conf"
UNBOUND_CONF = "/etc/unbound/unbound.conf.d/pi-hole.conf"
AGH_DIR = "/opt/AdGuardHome"
AGH_YAML = AGH_DIR + "/AdGuardHome.yaml"
AGH_LOG = AGH_DIR + "/data/querylog.json"
AGH_TAIL_BYTES = 4 * 1024 * 1024


def conf_value(key):
    """Lee una clave de /etc/nexo-dns.conf, que escribe nexo-dns.sh."""
    try:
        with open(NEXO_CONF) as f:
            for line in f:
                if line.startswith(key + "="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


def engine():
    """Que filtro manda: 'pihole' o 'adguard'. Lo normal es que lo diga el
    fichero de config; si no esta (instalacion vieja), se deduce de lo que
    haya instalado."""
    e = conf_value("ENGINE")
    if e in ("pihole", "adguard"):
        return e
    return "adguard" if os.path.isfile(AGH_YAML) else "pihole"


def engine_label():
    return "AdGuard Home" if engine() == "adguard" else "Pi-hole FTL"


def engine_svc():
    return "AdGuardHome" if engine() == "adguard" else "pihole-FTL"


def agh_dns_options():
    """Lee el bloque dns que escribe AdGuard. Otra sintaxis queda sin verificar."""
    options = {}
    in_dns, in_clients, seen_dns = False, False, False
    indent, key = None, None
    try:
        with open(AGH_YAML, encoding="utf-8") as f:
            for line in f:
                line = re.split(r"(^|\s+)#", line, maxsplit=1)[0].rstrip()
                if not line or line in ("---", "..."):
                    continue
                if not line[0].isspace():
                    section = re.fullmatch(r"([A-Za-z_]\w*):(?:\s+(.*))?", line)
                    if section is None:
                        if line.startswith("- ") and not in_dns:
                            continue
                        return None
                    in_dns = section[1] == "dns"
                    in_clients = section[1] == "clients"
                    if in_clients and section[2] not in (None, "{}", "null", "~"):
                        return None
                    if in_dns:
                        if seen_dns or section[2]:
                            return None
                        seen_dns = True
                    continue
                if in_clients:
                    upstream = re.fullmatch(r'''\s+(?:-\s+)?["']?upstreams["']?\s*:\s*(.*)''', line)
                    if upstream and not re.fullmatch(r"\[\s*\]|null|~", upstream[1]):
                        return None
                if not in_dns:
                    continue
                value = line.lstrip(" ")
                depth = len(line) - len(value)
                if indent is None:
                    indent = depth
                if not depth or depth < indent or value.startswith("\t"):
                    return None
                if depth == indent and not value.startswith("- "):
                    entry = re.fullmatch(r"([A-Za-z_]\w*):(?:\s+(.*))?", value)
                    if entry is None or entry[1] in options:
                        return None
                    key = entry[1]
                    options[key] = [entry[2] or ""]
                elif key is not None:
                    options[key].append(value)
                else:
                    return None
    except (OSError, UnicodeError):
        return None
    return options if seen_dns else None


def verify_upstream(uport):
    if engine() != "adguard":
        # El entorno del daemon puede prevalecer sobre el TOML y la CLI local.
        pid = run(SUDO + ["systemctl", "show", "-p", "MainPID", "--value", "pihole-FTL"])
        if pid.isascii() and pid.isdigit() and int(pid) > 0:
            try:
                with open("/proc/{}/environ".format(pid), "rb") as source:
                    if any(entry.startswith(b"FTLCONF_dns_upstreams=") for entry in source.read().split(b"\0")):
                        return None
            except OSError:
                return None
        raw = run(SUDO + ["pihole-FTL", "--config", "dns.upstreams"])
        target = "127.0.0.1#{}".format(uport)
        try:
            values = json.loads(raw)
        except ValueError:
            # Algunas versiones imprimen el array sin comillas. Solo se usa
            # la salida completa de la CLI, nunca una búsqueda en el TOML.
            item = r"[A-Za-z0-9._:#%/+-]+"
            plain = re.fullmatch(r"\[\s*(" + item + r"(?:\s*,\s*" + item + r")*)\s*\]", raw)
            if plain is None:
                return None
            values = [value.strip() for value in plain[1].split(",")]
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            return None
        return values == [target]

    options = agh_dns_options()
    if options is None or "upstream_dns" not in options:
        return None
    file_setting = options.get("upstream_dns_file", [""])
    if file_setting not in ([""], ['""'], ["''"], ["null"], ["~"]):
        # AdGuard da prioridad al archivo. Su contenido puede cambiar por separado.
        return None
    fallback = options.get("fallback_dns", [""])
    if len(fallback) > 1:
        return False
    if fallback[0] not in ("", "null", "~"):
        inline_list = re.fullmatch(r"\[(.*)\]", fallback[0])
        if inline_list is None:
            return None
        if inline_list[1].strip():
            return False
    values = options["upstream_dns"]
    target = "127.0.0.1:{}".format(uport)
    if not values[0] and all(value.startswith("- ") for value in values[1:]):
        return values[1:] in (["- " + target], ['- "{}"'.format(target)], ["- '{}'".format(target)])
    if re.fullmatch(r"\[\s*\]", values[0]):
        return False
    return None

def run(cmd):
    """Ejecuta una orden sin pasarla por un intérprete de shell."""
    try:
        out = subprocess.run(
            cmd, shell=False, capture_output=True, text=True, timeout=10,
            check=False,
        )
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return ""

def service_active(name):
    return run(SUDO + ["systemctl", "is-active", name]).strip() == "active"

def unbound_port():
    """Puerto de Unbound. Lo escribe nexo-dns.sh; si no esta, se lee de la
    propia config, y como ultimo recurso 5335."""
    try:
        with open(NEXO_CONF) as f:
            for line in f:
                if line.startswith("UNBOUND_PORT="):
                    p = line.split("=", 1)[1].strip()
                    if p.isdigit():
                        return p
    except Exception:
        pass
    try:
        with open(UNBOUND_CONF, encoding="utf-8") as f:
            config = f.read()
    except OSError:
        config = ""
    m = re.search(r'^\s*port:\s*(\d+)', config, re.M)
    return m.group(1) if m else "5335"

def pihole_port():
    try:
        with open(NEXO_CONF) as f:
            for line in f:
                if line.startswith("PIHOLE_PORT="):
                    p = line.split("=", 1)[1].strip()
                    if p.isdigit():
                        return p
    except Exception:
        pass
    return "53"

def dns_reply(name, server, port, *flags):
    cmd = ["dig", "-r", "+noall", "+comments", "+answer", "+time=2",
           "+tries=1", "-q", name, "-t", "A", "@{}".format(server), *flags]
    if port:
        cmd.extend(["-p", str(port)])
    output = run(cmd)
    status = re.search(r"^;; ->>HEADER<<- opcode: QUERY, status: ([A-Z]+),", output, re.M)
    flags_line = re.search(r"^;; flags: ([^;]+);", output, re.M)
    address = ""
    if status and status[1] == "NOERROR":
        for answer in re.finditer(r"^\S+\s+\d+\s+IN\s+A\s+([\d.]+)\s*$", output, re.M):
            try:
                ip = ipaddress.IPv4Address(answer[1])
                if ip.is_global and not ip.is_multicast:
                    address = answer[1]
                    break
            except ValueError:
                pass
    return status[1] if status else None, flags_line[1].split() if flags_line else [], address


def dig_test(server, port=""):
    return dns_reply("google.com", server, port)[2]


def verify_dnssec(uport):
    status, flags, address = dns_reply("cloudflare.com", "127.0.0.1", uport,
                                       "+dnssec", "+adflag", "+nocdflag")
    if status is None:
        return None
    if status != "NOERROR" or "ad" not in flags or not address:
        return False
    status, _, _ = dns_reply("dnssec-failed.org", "127.0.0.1", uport,
                             "+dnssec", "+nocdflag")
    if status is None:
        return None
    if status != "SERVFAIL":
        return False
    # Sin validación el nombre debe resolver, o SERVFAIL podría ser un fallo de red.
    _, _, unchecked = dns_reply("dnssec-failed.org", "127.0.0.1", uport,
                                "+dnssec", "+cdflag")
    return True if unchecked else None

def count_gravity():
    """Dominios bloqueados. Pi-hole los tiene en gravity; AdGuard hay que
    contarlos en los ficheros de filtros que se descarga."""
    if engine() == "adguard":
        total = 0
        try:
            d = os.path.join(AGH_DIR, "data", "filters")
            for name in os.listdir(d):
                if not name.endswith(".txt"):
                    continue
                with open(os.path.join(d, name), encoding="utf-8",
                          errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line and line[0] not in "!#":
                            total += 1
        except OSError:
            return "0"
        return str(total)
    return run(SUDO + [
        "pihole-FTL", "sqlite3", "/etc/pihole/gravity.db",
        "SELECT COUNT(*) FROM gravity;",
    ]).strip() or "0"

def list_adlists():
    if engine() == "adguard":
        names, urls = [], []
        try:
            with open(AGH_YAML, encoding="utf-8") as f:
                inblk = False
                for line in f:
                    s = line.rstrip("\n")
                    if re.match(r'^[A-Za-z_][A-Za-z0-9_]*:', s):
                        inblk = s.startswith("filters:")
                        continue
                    if not inblk:
                        continue
                    m = re.match(r'^\s+name:\s*(.+)$', s)
                    if m:
                        names.append(m.group(1).strip())
                    m = re.match(r'^\s+url:\s*(.+)$', s)
                    if m:
                        urls.append(m.group(1).strip())
        except OSError:
            return []
        return ["{}|{}".format(n, u) for n, u in zip(names, urls)]
    try:
        sql = "SELECT COALESCE(comment, 'sin nombre') || '|' || COALESCE(address, '?') FROM adlist;"
        raw = run(SUDO + [
            "pihole-FTL", "sqlite3", "/etc/pihole/gravity.db", sql,
        ]).strip()
        return [r for r in raw.splitlines() if r]
    except Exception:
        return []

def listening_sockets():
    output = run(SUDO + ["ss", "-H", "-lntup"])
    sockets = []
    for line in output.splitlines():
        fields = line.split(None, 6)
        if len(fields) >= 6 and fields[0] in ("tcp", "udp"):
            host, _, port = fields[4].rpartition(":")
            process = fields[6] if len(fields) == 7 else ""
            sockets.append((fields[0], host.strip("[]").split("%", 1)[0], port, process))
    return sockets


def verify_unbound_listening(uport, sockets):
    # checkconf también carga los includes. ss contrasta lo que realmente abrió el proceso.
    interfaces = run(SUDO + ["unbound-checkconf", "-o", "interface"]).split()
    automatic = run(SUDO + ["unbound-checkconf", "-o", "interface-automatic"])
    if automatic == "yes" or any(
            not is_loopback_host(interface.split("@", 1)[0]) for interface in interfaces):
        return False
    protocols = set()
    unidentified = False
    for protocol, host, port, process in sockets:
        if re.search(r'\("unbound",pid=\d+,', process):
            if not is_loopback_host(host):
                return False
            if port == uport:
                protocols.add(protocol)
        elif port == uport and not process:
            unidentified = True
    if automatic == "no" and protocols == {"tcp", "udp"} and not unidentified:
        return True
    return None


def agh_client_count():
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=1)
    ips = set()
    found, incomplete = False, False
    for path in (AGH_LOG, AGH_LOG + ".1"):
        try:
            with open(path, "rb") as source:
                end = source.seek(0, os.SEEK_END)
                offset = max(0, end - AGH_TAIL_BYTES)
                source.seek(max(0, offset - 1))
                tail = source.read(end - offset + bool(offset))
        except FileNotFoundError:
            continue
        except OSError:
            return "?"
        found = True
        if offset:
            # Descarta solo la primera línea si quedó cortada por el seek.
            _, _, tail = tail.partition(b"\n")
        covers_cutoff = False
        for line in tail.splitlines():
            try:
                item = json.loads(line)
                stamp = item["T"]
                if not isinstance(stamp, str):
                    continue
                # AdGuard escribe RFC 3339 con hasta 9 decimales. Python 3.8
                # requiere una fracción de 3 o 6 dígitos y no reconoce Z.
                stamp = re.sub(r"\.(\d+)", lambda m: "." + m[1].ljust(6, "0")[:6], stamp)
                when = datetime.fromisoformat(stamp[:-1] + "+00:00" if stamp.endswith("Z") else stamp)
                if when.tzinfo is None:
                    continue
                if when < cutoff:
                    covers_cutoff = True
                elif when <= now:
                    ip = item["IP"]
                    if isinstance(ip, str):
                        ips.add(ipaddress.ip_address(ip))
            except (KeyError, TypeError, ValueError, RecursionError):
                continue
        incomplete |= bool(offset) and not covers_cutoff
    if not found:
        return "?"
    return "{}{}".format(len(ips), "+" if incomplete else "")

def clients_24h():
    """Cuantos clientes usan de verdad este DNS. Si son muy pocos, casi seguro
    el router sigue repartiendo su propio DNS y esto esta de adorno."""
    if engine() == "adguard":
        return agh_client_count()
    sql = ("SELECT COUNT(DISTINCT client) FROM query_storage "
           "WHERE timestamp > strftime('%s','now','-1 day');")
    n = run(SUDO + [
        "pihole-FTL", "sqlite3", "/etc/pihole/pihole-FTL.db", sql,
    ]).strip()
    return n if n.isdigit() else "?"

def verify():
    uport = unbound_port()
    pport = pihole_port()
    # root.hints puede venir del paquete dns-root-data o descargarse aparte
    hints_ok = any(
        os.path.isfile(p) and os.path.getsize(p) > 0
        for p in ("/usr/share/dns/root.hints",
                  "/var/lib/unbound/root.hints",
                  "/etc/unbound/root.hints")
    )
    sockets = listening_sockets()
    listening_ports = {port for protocol, _, port, _ in sockets if protocol == "tcp"}
    filtro = "AdGuard" if engine() == "adguard" else "Pi-hole"
    return {
        "Puerto {} ({})".format(pport, filtro): pport in listening_ports,
        "Puerto {} (Unbound)".format(uport): uport in listening_ports,
        "Unbound solo en localhost": verify_unbound_listening(uport, sockets),
        "Upstream = Unbound": verify_upstream(uport),
        "DNSSEC rechaza firmas rotas": verify_dnssec(uport),
        "Root hints": hints_ok,
    }

def restart():
    for service in ("unbound", engine_svc()):
        try:
            result = subprocess.run(SUDO + ["systemctl", "restart", service],
                                    shell=False, capture_output=True, timeout=15,
                                    check=False)
        except (OSError, subprocess.SubprocessError):
            return False
        if result.returncode:
            return False
    return True

# --- Recoleccion de datos ---
def collect():
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "engine": engine(),
        "engine_label": engine_label(),
        "pihole": service_active(engine_svc()),
        "unbound": service_active("unbound"),
        "dns_pihole": dig_test("127.0.0.1", pihole_port()),
        "dns_unbound": dig_test("127.0.0.1", unbound_port()),
        "gravity": count_gravity(),
        "clients": clients_24h(),
        "adlists": list_adlists(),
        "verify": verify(),
    }

# --- HTML / CSS ---
CSS = """
:root{
  --bg:#0d1117; --panel:#161b22; --panel2:#21262d; --line:#30363d;
  --green:#22c55e; --red:#ef4444; --yellow:#facc15; --text:#f1f5f9; --muted:#94a3b8;
  --cyan:#22d3ee; --indigo:#6366f1; --coral:#f43f5e; --adguard:#67b279;
  --accent:var(--coral); --accent-soft:rgba(244,63,94,.2);
}
body.engine-adguard{--accent:var(--adguard);--accent-soft:rgba(103,178,121,.22)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:2rem}
.wrap{max-width:1000px;margin:0 auto}
.logo-box{display:flex;flex-direction:column;align-items:center;margin-bottom:1.5rem}
.logo-box img{width:160px;height:160px;border-radius:24px;box-shadow:0 0 44px rgba(34,211,238,.16)}
.logo-box .tag{margin-top:.6rem;font-size:.85rem;color:var(--muted);letter-spacing:.05em}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:2rem;border-bottom:1px solid var(--line);padding-bottom:1rem}
h1{font-size:1.6rem;font-weight:700;text-decoration:underline;text-decoration-color:var(--accent);text-underline-offset:.35rem}
.badge{font-size:.8rem;padding:.3rem .7rem;border-radius:999px;background:var(--panel2);color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem;margin-bottom:2rem}
.card{background:linear-gradient(145deg,var(--panel),#111827);border:1px solid var(--line);border-top-color:var(--accent);border-radius:12px;padding:1.2rem;box-shadow:0 10px 26px rgba(0,0,0,.14)}
.card .label{font-size:.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.card .value{font-size:1.5rem;font-weight:700;margin-top:.4rem}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:.5rem}
.ok{background:var(--green)} .bad{background:var(--red)} .warn{background:var(--yellow)}
section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem}
section h2{font-size:1.1rem;margin-bottom:1rem;color:var(--cyan)}
.check{display:flex;align-items:center;justify-content:space-between;padding:.5rem 0;border-bottom:1px solid var(--line)}
.check:last-child{border-bottom:none}
.list-item{padding:.5rem 0;border-bottom:1px solid var(--line);font-size:.9rem}
.list-item:last-child{border-bottom:none}
.btn{display:inline-block;background:var(--accent);color:#071018;padding:.6rem 1.2rem;border-radius:8px;font-weight:700;border:1px solid transparent;cursor:pointer;text-decoration:none;box-shadow:0 0 0 3px var(--accent-soft)}
.btn:hover{filter:brightness(1.08)}
.btn:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}
.hint{font-size:.85rem;color:var(--muted);margin-top:.6rem;line-height:1.5}
footer{text-align:center;color:var(--muted);font-size:.8rem;margin-top:2rem}
"""

def render_html(data, age=0):
    pihole_dot = "ok" if data["pihole"] else "bad"
    unbound_dot = "ok" if data["unbound"] else "bad"
    checks = "".join(
        '<div class="check"><span>{}</span><span><span class="dot {}"></span>{}</span></div>'.format(
            html_lib.escape(str(k)), "warn" if v is None else "ok" if v else "bad",
            "Sin verificar" if v is None else "Correcto" if v else "Error")
        for k, v in data["verify"].items()
    )
    lists = "".join(
        '<div class="list-item">- {}</div>'.format(html_lib.escape(str(c)))
        for c in data["adlists"]
    ) or '<div class="list-item">Sin listas</div>'

    pihole_status = "Activo" if data["pihole"] else "Caido"
    unbound_status = "Activo" if data["unbound"] else "Caido"

    # Pocos clientes casi siempre significa que el router no reparte esta IP
    try:
        few = int(data["clients"]) <= 2
    except (ValueError, TypeError):
        few = False
    clients_dot = "warn" if few or not str(data["clients"]).isdigit() else "ok"
    hint = ('<div class="hint">Muy pocos clientes para una red domestica. '
            'Revisa el DHCP de tu router: debe repartir la IP de esta maquina '
            'como UNICO servidor DNS. Un secundario publico salta el filtrado.</div>') if few else ""

    engine_key = "adguard" if data.get("engine") == "adguard" else "pihole"
    html = (
        '<!DOCTYPE html>'
        '<html lang="es"><head><meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>nexo-dns</title>'
        '<link rel="icon" href="/logo.svg">'
        '<style>{}</style>'
        '<meta http-equiv="refresh" content="15"></head>'
        '<body class="engine-{}"><div class="wrap">'
        '<div class="logo-box">'
        '  <img src="/logo.svg" alt="nexo-dns logo">'
        '  <div class="tag">DNS privado, filtrado y recursivo</div>'
        '</div>'
        '<header><h1>nexo-dns</h1><span class="badge">Instantánea: {} · hace {} s</span></header>'
        '<div class="grid">'
        '  <div class="card"><div class="label">{}</div><div class="value"><span class="dot {}"></span>{}</div></div>'
        '  <div class="card"><div class="label">Unbound</div><div class="value"><span class="dot {}"></span>{}</div></div>'
        '  <div class="card"><div class="label">Dominios bloqueados</div><div class="value">{}</div></div>'
        '  <div class="card"><div class="label">Clientes (24 h)</div><div class="value"><span class="dot {}"></span>{}</div></div>'
        '</div>'
        '{}'
        '<section><h2>Verificacion</h2>{}</section>'
        '<section><h2>Listas de bloqueo ({})</h2>{}</section>'
        '<section><h2>Acciones</h2>'
        '  <form method="post" action="/restart">'
        '  <input type="hidden" name="csrf_token" value="{}">'
        '  <button class="btn" type="submit">Reiniciar servicios</button></form>'
        '</section>'
        '<footer>nexo-dns by nexo (Dark)</footer>'
        '</div></body></html>'
    ).format(
        CSS, engine_key, html_lib.escape(str(data["timestamp"])), age,
        html_lib.escape(str(data.get("engine_label", "Pi-hole FTL"))),
        pihole_dot, pihole_status,
        unbound_dot, unbound_status,
        html_lib.escape(str(data["gravity"])),
        clients_dot, html_lib.escape(str(data["clients"])),
        hint,
        checks,
        len(data["adlists"]), lists,
        html_lib.escape(CSRF_TOKEN, quote=True),
    )
    if not ALLOW_RESTART:
        html = re.sub(r'<section><h2>Acciones</h2>.*?</section>',
                      '<section><h2>Acceso</h2><p>Panel de solo lectura. Administra los servicios desde el TUI.</p></section>',
                      html, flags=re.S)
    return html

# --- Autenticacion basica ---
AUTH_USER = None
AUTH_PASS = None
ALLOW_RESTART = False
CSRF_TOKEN = secrets.token_urlsafe(32)

def check_auth(headers):
    if AUTH_USER is None or AUTH_PASS is None:
        return True
    auth = headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth[6:]).decode()
        user, _, pwd = decoded.partition(":")
        # compare_digest y no ==: el operador normal corta en cuanto encuentra
        # un byte distinto, y ese tiempo distinto se mide. Con --host 0.0.0.0
        # el panel queda expuesto y la contrasena se puede sacar a base de
        # cronometrar respuestas, caracter a caracter.
        # Los dos compare_digest se evaluan siempre —sin cortocircuito— para no
        # filtrar por tiempo si lo que falla es el usuario o la contrasena.
        ok_user = hmac.compare_digest(user.encode(), AUTH_USER.encode())
        ok_pass = hmac.compare_digest(pwd.encode(), AUTH_PASS.encode())
        return ok_user & ok_pass
    except Exception:
        return False

def csrf_valid(body):
    """Valida el token de acciones que cambian el sistema."""
    try:
        tokens = urllib.parse.parse_qs(body, strict_parsing=True)["csrf_token"]
        if len(tokens) != 1:
            return False
        token = tokens[0]
    except (KeyError, ValueError, IndexError):
        return False
    return hmac.compare_digest(token.encode(), CSRF_TOKEN.encode())

def same_origin(headers):
    """Rechaza peticiones POST enviadas desde otro sitio web."""
    origin = headers.get("Origin")
    if not origin:
        return True
    try:
        parsed = urllib.parse.urlsplit(origin)
        return (parsed.scheme in ("http", "https") and not parsed.username
                and parsed.netloc == headers.get("Host", ""))
    except ValueError:
        return False

def is_loopback_host(host):
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_host_authority(value):
    if not re.fullmatch(r"(?:[A-Za-z0-9_.-]+|\[[A-Za-z0-9:.%_-]+\])(?::[0-9]+)?", value):
        return None
    try:
        authority = urllib.parse.urlsplit("//" + value)
        if authority.hostname and authority.port != 0:
            return authority.hostname.lower(), authority.port
    except ValueError:
        pass
    return None


# --- Servidor HTTP ---
class DeadlineReader(io.RawIOBase):
    """Aplica el mismo plazo a cada lectura del socket, incluso dentro del búfer."""

    def __init__(self, connection, timeout):
        super().__init__()
        self.connection = connection
        self.deadline = time.monotonic() + timeout

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("Plazo de lectura agotado")
        previous = self.connection.gettimeout()
        try:
            self.connection.settimeout(remaining)
            return self.connection.recv_into(buffer)
        finally:
            self.connection.settimeout(previous)


class BoundedHTTPServer(http.server.ThreadingHTTPServer):
    """Panel privado: acota conexiones y tiempo de lectura; no servidor público."""
    daemon_threads = True
    request_queue_size = 16
    read_timeout = 5
    snapshot_ttl = 10

    def __init__(self, address, handler, max_connections=16):
        self.slots = threading.BoundedSemaphore(max_connections)
        self._snapshot_lock = threading.Lock()
        self._snapshot = None
        self.allowed_hosts = {address[0].lower()}
        if is_loopback_host(address[0]):
            self.allowed_hosts.update({"localhost", "127.0.0.1", "::1"})
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(self.read_timeout)
        return connection, address

    def get_snapshot(self):
        with self._snapshot_lock:
            now = time.monotonic()
            if self._snapshot is None or now - self._snapshot[1] >= self.snapshot_ttl:
                data = collect()
                self._snapshot = now, time.monotonic(), data
            started, _, data = self._snapshot
            return data, int(time.monotonic() - started)

    def restart_services(self):
        with self._snapshot_lock:
            self._snapshot = None
            return restart()

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def read_auth_file(path):
    """Credenciales fuera de argv; fichero regular, privado y del usuario actual."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, encoding="utf-8") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("El archivo de autenticación debe tener permisos 600")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise ValueError("El archivo debe pertenecer al usuario que ejecuta el panel")
        value = source.read(4097).rstrip("\r\n")
        if len(value) > 4096 or "\n" in value or ":" not in value:
            raise ValueError("Formato de autenticación no válido")
        user, password = value.split(":", 1)
        if not user or not password:
            raise ValueError("Usuario y contraseña no pueden estar vacíos")
        return user, password


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "nexo-dns"
    sys_version = ""

    def setup(self):
        super().setup()
        self.rfile.close()
        self.rfile = io.BufferedReader(DeadlineReader(self.connection, self.server.read_timeout))

    def trusted_host(self):
        # Evita DNS rebinding: Origin no basta si el Host también es del atacante.
        values = self.headers.get_all("Host", [])
        if len(values) != 1:
            return False
        authority = parse_host_authority(values[0])
        if authority is None:
            return False
        host, port = authority
        return (port in (None, self.server.server_port) and host in self.server.allowed_hosts
                or port is not None and values[0].lower() in self.server.allowed_hosts)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", (
            "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        ))
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        super().end_headers()

    def _deny(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="nexo-dns", charset="UTF-8"')
        self.end_headers()

    def do_GET(self):
        if not self.trusted_host():
            self.send_error(403, "Host no autorizado")
            return
        if not check_auth(self.headers):
            self._deny()
            return

        if self.path == "/logo.svg":
            try:
                path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "logo.svg")
                with open(path, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "image/svg+xml")
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                self.send_response(404)
                self.end_headers()
            return
        if self.path == "/restart":
            # Reiniciar es una accion con efecto: solo por POST, nunca por GET.
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        if self.path != "/":
            self.send_error(404)
            return
        data, age = self.server.get_snapshot()
        html = render_html(data, age)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def do_POST(self):
        if not self.trusted_host():
            self.send_error(403, "Host no autorizado")
            return
        if not check_auth(self.headers):
            self._deny()
            return
        if self.path == "/restart":
            if not ALLOW_RESTART:
                self.send_error(403, "Panel de solo lectura")
                return
            lengths = self.headers.get_all("Content-Length", [])
            if "Transfer-Encoding" in self.headers or len(lengths) != 1:
                self.send_error(400, "Solicitud no valida")
                return
            try:
                length = int(lengths[0])
            except ValueError:
                length = 0
            if length <= 0 or length > 4096:
                self.send_error(400, "Solicitud no valida")
                return
            if not same_origin(self.headers):
                self.send_error(403, "Solicitud rechazada")
                return
            raw_body = self.rfile.read(length)
            if len(raw_body) != length:
                self.send_error(400, "Solicitud no valida")
                return
            try:
                body = raw_body.decode("utf-8")
            except UnicodeDecodeError:
                self.send_error(400, "Solicitud no valida")
                return
            if not csrf_valid(body):
                self.send_error(403, "Solicitud rechazada")
                return
            if not self.server.restart_services():
                self.send_error(503, "No se pudo reiniciar; revisa los servicios desde el TUI")
                return
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        self.send_response(405)
        self.end_headers()

    def log_message(self, *a):
        pass

def main():
    ap = argparse.ArgumentParser(description="nexo-dns - panel web")
    ap.add_argument("--host", default="127.0.0.1", help="Host (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8080, help="Puerto (default: 8080)")
    ap.add_argument("--auth", help="Autenticacion basica: usuario:password")
    ap.add_argument("--auth-file", help="Archivo privado (600) con usuario:contraseña")
    ap.add_argument("--allowed-host", action="append", default=[],
                    help="Nombre DNS o IP autorizado en Host, con puerto opcional; repetible")
    ap.add_argument("--allow-restart", action="store_true", help="Habilita reinicios (por defecto: solo lectura)")
    ap.add_argument(
        "--allow-unauthenticated", action="store_true",
        help="Permite escuchar fuera de localhost sin autenticacion (peligroso)",
    )
    args = ap.parse_args()

    global AUTH_USER, AUTH_PASS, ALLOW_RESTART
    ALLOW_RESTART = args.allow_restart
    if not 1 <= args.port <= 65535:
        ap.error("Puerto fuera de rango")
    if args.host in ("0.0.0.0", "::") and not args.allowed_host:
        ap.error("Una escucha global exige --allowed-host con la IP o nombre usado para acceder")
    allowed_hosts = set()
    for value in args.allowed_host:
        authority = parse_host_authority(value)
        if authority:
            host, port = authority
            allowed_hosts.add(host if port is None else value.lower())
        else:
            try:
                ipaddress.IPv6Address(value)
            except ValueError:
                ap.error("--allowed-host requiere un nombre DNS o IP; usa [IPv6]:puerto si añades puerto")
            allowed_hosts.add(value.lower())
    if args.auth and args.auth_file:
        ap.error("Usa --auth o --auth-file, no ambos")
    if args.auth_file:
        try:
            AUTH_USER, AUTH_PASS = read_auth_file(args.auth_file)
        except (OSError, ValueError):
            ap.error("Archivo de autenticación inválido: debe ser privado, propio y contener usuario:contraseña")
    if args.auth:
        if ":" not in args.auth:
            print("Error: --auth debe ser usuario:password")
            sys.exit(1)
        AUTH_USER, AUTH_PASS = args.auth.split(":", 1)
        if not AUTH_USER or not AUTH_PASS:
            ap.error("Usuario y contraseña no pueden estar vacíos")
        print("Autenticacion basica habilitada para el usuario: {}".format(AUTH_USER))
    if AUTH_USER is None and not is_loopback_host(args.host) and not args.allow_unauthenticated:
        print("Error: el panel no se expondra a la red sin autenticacion.")
        print("       Usa --auth-file /ruta/privada/auth o, bajo tu responsabilidad,")
        print("       --allow-unauthenticated.")
        sys.exit(2)

    if not is_loopback_host(args.host):
        print("AVISO: Basic Auth no cifra el trafico. Usa Tailscale o un proxy HTTPS.")

    with BoundedHTTPServer((args.host, args.port), Handler) as httpd:
        httpd.allowed_hosts.update(allowed_hosts)
        print("Dashboard en http://{}:{}".format(args.host, args.port))
        if args.host == "0.0.0.0":
            print("  Accede desde: http://<IP-del-servidor>:{}".format(args.port))
        print("Ctrl+C para detener")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nDetenido.")

if __name__ == "__main__":
    main()
