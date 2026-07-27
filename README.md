<div align="center">

<img src="assets/logo.svg" width="160" alt="Pi-hole + Unbound Manager logo">

# Pi-hole + Unbound Manager

Instalador y gestor todo-en-uno de Pi-hole + Unbound para tu propio DNS privado, sin anuncios y sin depender de terceros.

![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)
![Pi-hole](https://img.shields.io/badge/Pi--hole-red?style=flat-square&logo=pihole&logoColor=white)
![Unbound](https://img.shields.io/badge/Unbound-DNS_recursivo-3b82f6?style=flat-square)
![License](https://img.shields.io/badge/licencia-MIT-brightgreen?style=flat-square)

</div>

---

## 📌 ¿Qué es esto?

Este proyecto automatiza la instalación y administración de un servidor DNS privado basado en:

- [Pi-hole](https://pi-hole.net) → bloquea anuncios, rastreadores y dominios maliciosos a nivel de red (DNS sinkhole).
- [Unbound](https://nlnetlabs.nl/projects/unbound/about/) → resuelve las consultas de forma recursiva y privada, sin pasar por DNS de terceros (Google, Cloudflare, etc.).

Pensado originalmente para Raspberry Pi (incluye ajustes de memoria para equipos con 1 GB de RAM), pero funciona en cualquier host Debian/Ubuntu con systemd.

---

## 🧩 Scripts incluidos

| Script | Qué hace |
|--------|----------|
| `install.sh` | Instala Pi-hole (modo unattended) + Unbound, aplica el fix de puerto 53, descarga los root hints, conecta Pi-hole → Unbound, aplica tuning de memoria y carga listas de bloqueo. |
| `manage.sh` | Panel de gestión en terminal (TUI): estado de servicios, test de resolución DNS, verificación de instalación, reinicio de servicios, gestión del firewall (puerto 53) y listado de blocklists activas. |
| `dashboard.py` | Dashboard web con estado en vivo, verificación, listas y botón de reinicio. Soporta autenticación básica. |
| `push-to-github.sh` | Sube el proyecto a un repositorio de GitHub. |

---

## ⚙️ Qué hace exactamente install.sh

1. Actualiza el sistema (`apt-get update/upgrade`).
2. Instala Pi-hole en modo desatendido y define la contraseña del panel.
3. Instala Unbound + dnsutils.
4. **FIX de puerto 53**: comenta `interface:` y `port:` en `unbound.conf` para evitar conflicto con Pi-hole.
5. Escribe configuración de Unbound optimizada (puerto 5335, qname-minimisation, prefetch, caché para 1 GB RAM).
6. Descarga los *root hints* oficiales de IANA/InterNIC.
7. Conecta Pi-hole a Unbound como upstream (`127.0.0.1#5335`) editando `/etc/pihole/pihole.toml`.
8. Añade blocklists de calidad (OISD Full, HaGeZi Multi/TIF/Light, AdGuard DNS filter).
9. Reinicia servicios y ejecuta `pihole updateGravity`.
10. Verifica que Unbound resuelve, que Pi-hole bloquea, y cuenta los dominios cargados.

---

## 🚀 Instalación rápida

```bash
# En la Raspberry Pi
sudo bash install.sh [password]   # password por defecto: admin123
```

Esto deja:
- **Pi-hole** en `http://<IP-PI>/admin`
- **Unbound** en `127.0.0.1#5335`
- Bloqueo activado con ~2.7M+ dominios

---

## 🖥️ Gestión

```bash
# Panel interactivo en terminal
sudo bash manage.sh

# Dashboard web (puerto 8080)
sudo python3 dashboard.py --port 8080 --auth usuario:password
```

### Parámetros del dashboard

| Parámetro | Descripción | Default |
|-----------|-------------|---------|
| `--host` | IP de escucha | `127.0.0.1` |
| `--port` | Puerto | `8080` |
| `--auth` | Autenticación básica (usuario:password) | desactivada |

---

## 📤 Subir a GitHub

```bash
./push-to-github.sh <tu-usuario> [nombre-repo] [token]
```

---

## 📋 Requisitos

- Raspberry Pi OS (Bookworm/Bullseye) o Debian/Ubuntu con systemd
- Python 3 (para el dashboard)
- `dig` (dnsutils), `sqlite3`
- Conexión a internet

---

## 🔧 Notas técnicas

- **Fix puerto 53**: Unbound escucha en `5335` para no interferir con Pi-hole (puerto `53`)
- **Ajuste Pi 3B**: 4 threads, 128 MB RRset cache, 64 MB msg cache
- **Privacidad**: qname-minimisation, uso de root hints, sin DNS de terceros
- **Backup**: El instalador no borra configuraciones previas

---

<div align="center">
Creado por <b>nexo (Dark)</b>
</div>