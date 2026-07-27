<div align="center">

<img src="assets/logo.svg" width="140" alt="logo">

# Pi-hole + Unbound Manager

**Instalador y gestor de DNS privado para Raspberry Pi**

![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)
![Pi-hole](https://img.shields.io/badge/Pi--hole-F60?style=flat-square&logo=pihole&logoColor=white)
![Unbound](https://img.shields.io/badge/Unbound-3b82f6?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-brightgreen?style=flat-square)

</div>

---

## Descripción

Automatiza la instalación de **Pi-hole** (bloqueo de anuncios) + **Unbound** (DNS recursivo privado) en Raspberry Pi. Sin depender de DNS de terceros.

## Scripts

| Script | Función |
|--------|---------|
| `install.sh` | Instalación completa Pi-hole + Unbound |
| `manage.sh` | Panel de gestión en terminal |
| `dashboard.py` | Dashboard web con autenticación |

## Instalación

```bash
sudo bash install.sh [password]      # password por defecto: admin123
```

Resultado:
- Panel: `http://<IP-PI>/admin`
- DNS: `127.0.0.1#5335` (Unbound)
- Bloqueo: ~2.7M+ dominios

## Gestión

```bash
sudo bash manage.sh                   # Panel TUI interactivo
sudo python3 dashboard.py --port 8080 # Dashboard web
```

## Requisitos

- Raspberry Pi OS / Debian / Ubuntu
- Python 3, dnsutils

---

<div align="center"><sub>Creado por <b>nexo</b></sub></div>