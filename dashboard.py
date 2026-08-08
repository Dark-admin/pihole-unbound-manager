#!/usr/bin/env python3
"""
dashboard.py - Panel web para Pi-hole + Unbound
Autor: nexo (Dark)
v3.0 - Alineado con nexo-dns.sh: lee el puerto real de Unbound y verifica
       cosas que significan algo (antes comprobaba un "fix" que ya no existe).

Uso:
    sudo python3 dashboard.py [--port 8080] [--host 0.0.0.0] [--auth usuario:password]
"""
import http.server
import socketserver
import subprocess
import re
import os
import sys
import argparse
import base64
import hmac
from datetime import datetime

# --- Utilidades de sistema ---
SUDO = "" if os.geteuid() == 0 else "sudo "

NEXO_CONF = "/etc/nexo-dns.conf"
UNBOUND_CONF = "/etc/unbound/unbound.conf.d/pi-hole.conf"

def run(cmd):
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return out.stdout.strip()
    except Exception:
        return ""

def service_active(name):
    return run("{}systemctl is-active {}".format(SUDO, name)).strip() == "active"

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
    m = re.search(r'^\s*port:\s*(\d+)', run("cat {} 2>/dev/null".format(UNBOUND_CONF)), re.M)
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
    p = "-p {}".format(port) if port else ""
    out = run("dig +short +time=2 google.com @{} {} 2>/dev/null | head -1".format(server, p))
    # dig +short escribe ";; communications error" por stdout, no por stderr
    if out and not out.startswith(";;") and "." in out:
        return out
    return ""

def count_gravity():
    try:
        return run('{}pihole-FTL sqlite3 /etc/pihole/gravity.db "SELECT COUNT(*) FROM gravity;"'.format(SUDO)).strip() or "0"
    except Exception:
        return "0"

def list_adlists():
    try:
        sql = "SELECT COALESCE(comment, 'sin nombre') || '|' || COALESCE(address, '?') FROM adlist;"
        raw = run('{}pihole-FTL sqlite3 /etc/pihole/gravity.db "{}"'.format(SUDO, sql)).strip()
        return [r for r in raw.splitlines() if r]
    except Exception:
        return []

def port_open(port):
    """Verifica si un puerto esta escuchando."""
    try:
        output = run("{}ss -tlnp 2>/dev/null".format(SUDO))
        return re.search(r':{}\s'.format(re.escape(str(port))), output) is not None
    except Exception:
        return False

def clients_24h():
    """Cuantos clientes usan de verdad este DNS. Si son muy pocos, casi seguro
    el router sigue repartiendo su propio DNS y esto esta de adorno."""
    sql = ("SELECT COUNT(DISTINCT client) FROM query_storage "
           "WHERE timestamp > strftime('%s','now','-1 day');")
    n = run('{}pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db "{}"'.format(SUDO, sql)).strip()
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
    servfail = "SERVFAIL" in run(
        "dig dnssec-failed.org @127.0.0.1 -p {} +time=3 2>/dev/null".format(uport))
    # Unbound debe escuchar solo en localhost, no ser un recursivo abierto
    localhost_only = "127.0.0.1" in run(
        "grep -E '^[[:space:]]*interface:' {} 2>/dev/null".format(UNBOUND_CONF))

    # En pihole.toml v6 el valor va en la linea SIGUIENTE a "upstreams = [",
    # asi que un grep simple nunca lo encuentra. Se usa la API de Pi-hole, y
    # solo se cae al fichero (con -A3) si no hay CLI v6.
    upstream_raw = run("{}pihole-FTL --config dns.upstreams 2>/dev/null".format(SUDO))
    if not upstream_raw:
        upstream_raw = run("{}grep -A3 upstreams /etc/pihole/pihole.toml 2>/dev/null".format(SUDO))
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
    run("{}systemctl restart unbound".format(SUDO))
    run("{}systemctl restart pihole-FTL".format(SUDO))

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
        '<div class="check"><span>{}</span><span class="dot {}"></span></div>'.format(k, "ok" if v else "bad")
        for k, v in data["verify"].items()
    )
    lists = "".join(
        '<div class="list-item">- {}</div>'.format(c) for c in data["adlists"]
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
        '  <form method="post" action="/restart"><button class="btn" type="submit">Reiniciar servicios</button></form>'
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
        len(data["adlists"]),
        lists
    )
    return html

# --- Autenticacion basica ---
AUTH_USER = None
AUTH_PASS = None

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

# --- Servidor HTTP ---
class Handler(http.server.BaseHTTPRequestHandler):
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
    args = ap.parse_args()

    global AUTH_USER, AUTH_PASS
    if args.auth:
        if ":" not in args.auth:
            print("Error: --auth debe ser usuario:password")
            sys.exit(1)
        AUTH_USER, AUTH_PASS = args.auth.split(":", 1)
        print("Autenticacion basica habilitada para el usuario: {}".format(AUTH_USER))
    elif args.host != "127.0.0.1":
        print("AVISO: lo estas exponiendo a la red SIN autenticacion.")
        print("       Usa --auth usuario:password")

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((args.host, args.port), Handler) as httpd:
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
