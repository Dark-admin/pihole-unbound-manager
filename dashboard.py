#!/usr/bin/env python3
"""
dashboard.py - Panel web para Pi-hole + Unbound
Autor: nexo (Dark)
v4.0 - Alineado con nexo-dns.sh y endurecido para uso en red.

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
import ipaddress
import secrets
import urllib.parse
from datetime import datetime

# --- Utilidades de sistema ---
SUDO = [] if getattr(os, "geteuid", lambda: 1)() == 0 else ["sudo", "-n"]

NEXO_CONF = "/etc/nexo-dns.conf"
UNBOUND_CONF = "/etc/unbound/unbound.conf.d/pi-hole.conf"

def run(cmd):
    """Ejecuta una orden sin pasarla por un intérprete de shell."""
    try:
        out = subprocess.run(
            cmd, shell=False, capture_output=True, text=True, timeout=10,
            check=False,
        )
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
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

def dig_test(server, port=""):
    cmd = ["dig", "+short", "+time=2", "google.com", "@{}".format(server)]
    if port:
        cmd.extend(["-p", str(port)])
    out = run(cmd).splitlines()
    out = out[0] if out else ""
    # dig +short escribe ";; communications error" por stdout, no por stderr
    if out and not out.startswith(";;") and "." in out:
        return out
    return ""

def count_gravity():
    return run(SUDO + [
        "pihole-FTL", "sqlite3", "/etc/pihole/gravity.db",
        "SELECT COUNT(*) FROM gravity;",
    ]).strip() or "0"

def list_adlists():
    try:
        sql = "SELECT COALESCE(comment, 'sin nombre') || '|' || COALESCE(address, '?') FROM adlist;"
        raw = run(SUDO + [
            "pihole-FTL", "sqlite3", "/etc/pihole/gravity.db", sql,
        ]).strip()
        return [r for r in raw.splitlines() if r]
    except Exception:
        return []

def port_open(port):
    """Verifica si un puerto esta escuchando."""
    try:
        output = run(SUDO + ["ss", "-tlnp"])
        return re.search(r':{}\s'.format(re.escape(str(port))), output) is not None
    except Exception:
        return False

def clients_24h():
    """Cuantos clientes usan de verdad este DNS. Si son muy pocos, casi seguro
    el router sigue repartiendo su propio DNS y esto esta de adorno."""
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
    # Prueba real de DNSSEC: una firma rota TIENE que ser rechazada
    servfail = "SERVFAIL" in run([
        "dig", "dnssec-failed.org", "@127.0.0.1", "-p", str(uport), "+time=3",
    ])
    # Unbound debe escuchar solo en localhost, no ser un recursivo abierto
    try:
        with open(UNBOUND_CONF, encoding="utf-8") as f:
            localhost_only = any(
                re.match(r"^\s*interface:\s*127\.0\.0\.1\s*$", line)
                for line in f
            )
    except OSError:
        localhost_only = False

    # En pihole.toml v6 el valor va en la linea SIGUIENTE a "upstreams = [",
    # asi que un grep simple nunca lo encuentra. Se usa la API de Pi-hole, y
    # solo se cae al fichero (con -A3) si no hay CLI v6.
    upstream_raw = run(SUDO + ["pihole-FTL", "--config", "dns.upstreams"])
    if not upstream_raw:
        try:
            with open("/etc/pihole/pihole.toml", encoding="utf-8") as f:
                upstream_raw = f.read()
        except OSError:
            upstream_raw = ""
    upstream_ok = "127.0.0.1#{}".format(uport) in upstream_raw

    return {
        "Puerto {} (Pi-hole)".format(pport): port_open(pport),
        "Puerto {} (Unbound)".format(uport): port_open(uport),
        "Unbound solo en localhost": localhost_only,
        "Upstream = Unbound": upstream_ok,
        "DNSSEC rechaza firmas rotas": servfail,
        "Root hints": hints_ok,
    }

def restart():
    run(SUDO + ["systemctl", "restart", "unbound"])
    run(SUDO + ["systemctl", "restart", "pihole-FTL"])

# --- Recoleccion de datos ---
def collect():
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pihole": service_active("pihole-FTL"),
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
  --green:#3fb950; --red:#f85149; --yellow:#d29922; --text:#e6edf3; --muted:#8b949e;
  --accent:#58a6ff; --orange:#ff7b00;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:2rem}
.wrap{max-width:1000px;margin:0 auto}
.logo-box{display:flex;flex-direction:column;align-items:center;margin-bottom:1.5rem}
.logo-box img{width:160px;height:160px;border-radius:24px;box-shadow:0 0 40px rgba(255,123,0,.25)}
.logo-box .tag{margin-top:.6rem;font-size:.85rem;color:var(--muted);letter-spacing:.05em}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:2rem;border-bottom:1px solid var(--line);padding-bottom:1rem}
h1{font-size:1.6rem;font-weight:700}
.badge{font-size:.8rem;padding:.3rem .7rem;border-radius:999px;background:var(--panel2);color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem;margin-bottom:2rem}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:1.2rem}
.card .label{font-size:.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.card .value{font-size:1.5rem;font-weight:700;margin-top:.4rem}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:.5rem}
.ok{background:var(--green)} .bad{background:var(--red)} .warn{background:var(--yellow)}
section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem}
section h2{font-size:1.1rem;margin-bottom:1rem;color:var(--accent)}
.check{display:flex;align-items:center;justify-content:space-between;padding:.5rem 0;border-bottom:1px solid var(--line)}
.check:last-child{border-bottom:none}
.list-item{padding:.5rem 0;border-bottom:1px solid var(--line);font-size:.9rem}
.list-item:last-child{border-bottom:none}
.btn{display:inline-block;background:var(--orange);color:#000;padding:.6rem 1.2rem;border-radius:8px;font-weight:600;border:none;cursor:pointer;text-decoration:none}
.btn:hover{opacity:.85}
.hint{font-size:.85rem;color:var(--muted);margin-top:.6rem;line-height:1.5}
footer{text-align:center;color:var(--muted);font-size:.8rem;margin-top:2rem}
"""

def render_html(data):
    pihole_dot = "ok" if data["pihole"] else "bad"
    unbound_dot = "ok" if data["unbound"] else "bad"
    checks = "".join(
        '<div class="check"><span>{}</span><span class="dot {}"></span></div>'.format(
            html_lib.escape(str(k)), "ok" if v else "bad")
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
    clients_dot = "warn" if few else "ok"
    hint = ('<div class="hint">Muy pocos clientes para una red domestica. '
            'Revisa el DHCP de tu router: debe repartir la IP de esta maquina '
            'como UNICO servidor DNS. Un secundario publico salta el filtrado.</div>') if few else ""

    html = (
        '<!DOCTYPE html>'
        '<html lang="es"><head><meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>nexo-dns</title>'
        '<link rel="icon" href="/logo.svg">'
        '<style>{}</style>'
        '<meta http-equiv="refresh" content="15"></head>'
        '<body><div class="wrap">'
        '<div class="logo-box">'
        '  <img src="/logo.svg" alt="nexo-dns logo">'
        '  <div class="tag">DNS privado, filtrado y recursivo</div>'
        '</div>'
        '<header><h1>nexo-dns</h1><span class="badge">Actualizado: {}</span></header>'
        '<div class="grid">'
        '  <div class="card"><div class="label">Pi-hole FTL</div><div class="value"><span class="dot {}"></span>{}</div></div>'
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
        CSS, data["timestamp"],
        pihole_dot, pihole_status,
        unbound_dot, unbound_status,
        data["gravity"],
        clients_dot, data["clients"],
        hint,
        checks,
        len(data["adlists"]), lists,
        html_lib.escape(CSRF_TOKEN, quote=True),
    )
    return html

# --- Autenticacion basica ---
AUTH_USER = None
AUTH_PASS = None
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
        ok_user = hmac.compare_digest(user, AUTH_USER)
        ok_pass = hmac.compare_digest(pwd, AUTH_PASS)
        return ok_user & ok_pass
    except Exception:
        return False

def csrf_valid(body):
    """Valida el token de acciones que cambian el sistema."""
    try:
        token = urllib.parse.parse_qs(body, strict_parsing=True)["csrf_token"][0]
    except (KeyError, ValueError, IndexError):
        return False
    return hmac.compare_digest(token, CSRF_TOKEN)

def same_origin(headers):
    """Rechaza peticiones POST enviadas desde otro sitio web."""
    origin = headers.get("Origin")
    if not origin:
        return True
    try:
        return urllib.parse.urlsplit(origin).netloc == headers.get("Host", "")
    except ValueError:
        return False

def is_loopback_host(host):
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False

# --- Servidor HTTP ---
class Handler(http.server.BaseHTTPRequestHandler):
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
        self.send_header("WWW-Authenticate", 'Basic realm="nexo-dns"')
        self.end_headers()

    def do_GET(self):
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
        data = collect()
        html = render_html(data)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def do_POST(self):
        if not check_auth(self.headers):
            self._deny()
            return
        if self.path == "/restart":
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > 4096:
                self.send_error(400, "Solicitud no valida")
                return
            try:
                body = self.rfile.read(length).decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                self.send_error(400, "Solicitud no valida")
                return
            if not same_origin(self.headers) or not csrf_valid(body):
                self.send_error(403, "Solicitud rechazada")
                return
            restart()
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
    ap.add_argument(
        "--allow-unauthenticated", action="store_true",
        help="Permite escuchar fuera de localhost sin autenticacion (peligroso)",
    )
    args = ap.parse_args()

    global AUTH_USER, AUTH_PASS
    if args.auth:
        if ":" not in args.auth:
            print("Error: --auth debe ser usuario:password")
            sys.exit(1)
        AUTH_USER, AUTH_PASS = args.auth.split(":", 1)
        print("Autenticacion basica habilitada para el usuario: {}".format(AUTH_USER))
    elif not is_loopback_host(args.host) and not args.allow_unauthenticated:
        print("Error: el panel no se expondra a la red sin autenticacion.")
        print("       Usa --auth usuario:password o, bajo tu responsabilidad,")
        print("       --allow-unauthenticated.")
        sys.exit(2)

    if not is_loopback_host(args.host):
        print("AVISO: Basic Auth no cifra el trafico. Usa Tailscale o un proxy HTTPS.")

    http.server.ThreadingHTTPServer.allow_reuse_address = True
    with http.server.ThreadingHTTPServer((args.host, args.port), Handler) as httpd:
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
