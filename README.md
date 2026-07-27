# Pi-hole + Unbound Manager

Gestor para instalar y administrar **Pi-hole + Unbound** en Raspberry Pi con DNS privado.

## Scripts

| Script | Funcion |
|--------|---------|
| `install.sh` | Instala Pi-hole + Unbound automaticamente |
| `manage.sh` | Panel de gestion en terminal |
| `dashboard.py` | Dashboard web con estado en vivo |
| `push-to-github.sh` | Sube el proyecto a GitHub |

## Instalacion

```bash
sudo bash install.sh [password]   # password default: admin123
```

## Gestion

```bash
# Panel en terminal
sudo bash manage.sh

# Dashboard web
sudo python3 dashboard.py --port 8080 --auth usuario:password
```

## Subir a GitHub

```bash
./push-to-github.sh <usuario> [nombre-repo] [token]
```

## Requisitos

- Raspberry Pi OS (Bookworm/Bullseye)
- Python 3, dig (dnsutils), sqlite3
- Conexion a internet

Creado por **nexo (Dark)**.