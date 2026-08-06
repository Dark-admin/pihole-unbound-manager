<div align="center">

<img src="assets/logo.svg" width="140" alt="logo">

# nexo-dns

**DNS privado, filtrado y recursivo para Raspberry Pi**

Pi-hole + Unbound + Tailscale, en un solo script con panel de gestión.

![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)
![Pi-hole](https://img.shields.io/badge/Pi--hole%20v6-F60?style=flat-square&logo=pihole&logoColor=white)
![Unbound](https://img.shields.io/badge/Unbound-3b82f6?style=flat-square)
![Tailscale](https://img.shields.io/badge/Tailscale-242424?style=flat-square&logo=tailscale&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-brightgreen?style=flat-square)

</div>

---

## Qué es

Un servidor DNS para tu casa que **bloquea publicidad y rastreo** (Pi-hole) y que
**resuelve por su cuenta** preguntando a los servidores raíz (Unbound), en vez de
delegar en Google o Cloudflare.

La diferencia importa: con un DNS público, ese proveedor ve **todos** los dominios
que visitas. Con un resolver recursivo propio, ningún actor tiene la foto completa.

`nexo-dns.sh` lo instala, lo afina para tu hardware y te deja un panel para
gestionarlo. Un solo fichero, sin dependencias más allá de lo que ya trae el sistema.

## Instalación

```bash
curl -fsSLO https://raw.githubusercontent.com/Dark-admin/pihole-unbound-manager/main/nexo-dns.sh
sudo bash nexo-dns.sh install
```

Después, para todo lo demás:

```bash
sudo bash nexo-dns.sh
```

## El panel

```
  ┌────────────────────────────────────────────────────────┐
  │    .~.                                                 │
  │   ( o )  nexo-dns v3.2                                 │
  │    `~'   Pi-hole · Unbound · Tailscale                 │
  ├────────────────────────────────────────────────────────┤
  │ ● Pi-hole :53     ● Unbound :5335                      │
  │ raspbi · 192.168.1.10 · Debian GNU/Linux 13 (trixie)   │
  ├────────────────────────────────────────────────────────┤
  │ ◆ ESTADO                                               │
  │    1 Ver estado            2 Chequeo real              │
  ├────────────────────────────────────────────────────────┤
  │ ▣ CONFIGURACIÓN                                        │
  │    3 Puerto Unbound        4 Puerto Pi-hole            │
  │    5 Puerto web            6 IP del servidor           │
  │    7 Reoptimizar           8 Listas de bloqueo         │
  │    9 Precalentar caché                                 │
  ├────────────────────────────────────────────────────────┤
  │ ▲ TAILSCALE                                            │
  │   10 Instalar             11 Optimizar                 │
  ├────────────────────────────────────────────────────────┤
  │ ■ SISTEMA                                              │
  │   12 Red / BBR            13 Reiniciar servicios       │
  │   14 Copias / restaurar   15 Instalar todo             │
  ├────────────────────────────────────────────────────────┤
  │    0 Salir                                             │
  └────────────────────────────────────────────────────────┘
```

En terminales sin UTF-8 cae automáticamente a bordes ASCII sin descuadrarse.

## Órdenes directas

Sin abrir el panel, útiles para cron o scripts:

| Orden | Qué hace |
|---|---|
| `sudo bash nexo-dns.sh install` | Instalación completa |
| `sudo bash nexo-dns.sh status` | Estado de servicios, caché y recursos |
| `sudo bash nexo-dns.sh health` | Chequeo con consultas reales |
| `sudo bash nexo-dns.sh optimize` | Reaplica la optimización de Unbound |

## Qué optimiza, y por qué

La configuración de Unbound no es la de la guía oficial copiada tal cual. Cada
ajuste está ahí por una razón concreta:

| Ajuste | Motivo |
|---|---|
| `cache-min-ttl: 120` | Los CDN usan TTLs de 30-60 s para balancear y hacer failover. Forzarlos a una hora te deja clavado en una IP muerta cuando el CDN mueve el tráfico. |
| `serve-expired-ttl: 3600` + `client-timeout: 1800` | Sirve caducado solo si no consigue respuesta fresca en 1,8 s, y como mucho una hora. Sin acotar, un registro obsoleto se sirve indefinidamente. |
| `use-caps-for-id: no` | El 0x20 encoding es anti-spoofing, pero bastantes autoritativos y CDNs no preservan mayúsculas y devuelven SERVFAIL intermitentes. Con DNSSEC validando no compensa. |
| `module-config: "validator iterator"` | Sin `subnetcache`. ECS filtra tu subred a los servidores autoritativos —justo lo contrario de para qué montas un recursivo— y además desactiva `prefetch` y `serve-expired` para ese tráfico. |
| `private-address` (RFC1918) | Anti DNS-rebinding: un dominio público jamás debe resolver a una IP de tu red interna. |
| `aggressive-nsec: yes` | Responde NXDOMAIN desde caché usando registros NSEC ya validados. Menos tráfico al exterior. |
| `interface: 127.0.0.1` + `access-control` | Explícito, para que sea imposible acabar exponiendo un resolver recursivo abierto. |
| Caché dimensionada por RAM | 32m/64m en equipos de 1 GB, hasta 128m/256m con más de 4 GB. Unbound reserva de forma perezosa, pero conviene no pasarse donde también corre `pihole-FTL`. |
| `net.core.rmem_max` | Sin subirlo, Unbound no puede aplicar `so-rcvbuf` y lo registra como error en cada arranque. |

En el lado de Pi-hole: `dnssec = false` (ya valida Unbound, hacerlo dos veces
gasta CPU), `domainNeeded` y `bogusPriv` activos, y `EDNS0ECS` desactivado.

## Precalentado de caché

Un resolver recursivo paga un peaje la primera vez que ve un dominio: pregunta a
los raíz, al TLD y al autoritativo. Son 200-500 ms. Después queda en caché y baja
a 2-5 ms.

La opción **9** instala un temporizador que coge los dominios que *tú* más usas
—sacados del historial de Pi-hole— y los resuelve cada 30 minutos y 3 minutos
después de cada arranque, que es cuando la caché está vacía y más duele.

Medido en una Pi 3B con esto activo:

| | Antes | Después |
|---|---|---|
| `wikipedia.org` en frío | 465 ms | 30 ms |
| Mediana en caliente | — | 4,5 ms |
| Cloudflare `1.1.1.1` (mediana) | 60 ms | — |

## Sobre BBR

**BBR no acelera el DNS.** Es un algoritmo de control de congestión de **TCP**, y
el DNS va prácticamente todo por **UDP**.

Está en la opción 12 porque sí mejora el tráfico TCP —descargas, streaming, y lo
que pase por la máquina si hace de exit node de Tailscale—, pero el panel lo
etiqueta como lo que es. Lo que sí acelera el DNS son la caché, `prefetch`,
`serve-expired` y los buffers UDP del kernel, todo ello ya aplicado.

## Tailscale

La opción **11** aplica tres cosas:

- **`--accept-dns=false`** en esta máquina. Si la Pi es el DNS del tailnet y
  además acepta el DNS del tailnet, se resuelve a sí misma en bucle.
- **UDP GRO forwarding** (`rx-udp-gro-forwarding on`, `rx-gro-list off`), la
  optimización que documenta Tailscale para exit nodes y subnet routers. Se
  comprueba antes que tengas **Tailscale ≥ 1.54 y kernel ≥ 6.2**: por debajo
  puede empeorar el rendimiento, así que se omite. Se persiste con una unidad
  systemd porque `ethtool` no sobrevive a un reinicio.
- **`ip_forward`** si la máquina anuncia exit node o rutas.

Para usar Pi-hole fuera de casa, en `login.tailscale.com/admin/dns` pon la IP del
tailnet como nameserver global y marca *Override local DNS*. Ten en cuenta que
eso hace que tus equipos dependan de esa máquina **siempre**, también con datos
móviles: si se apaga, se quedan sin DNS en cualquier sitio.

## Seguridad al aplicar cambios

Todo cambio sigue el mismo patrón:

1. Copia previa en `/var/backups/nexo-dns/<fecha>/`
2. Validación con `unbound-checkconf`
3. Reinicio del servicio
4. Verificación real: que resuelva, y que DNSSEC acepte una firma válida y
   **rechace** una rota
5. Si algo falla, **revierte solo** y te lo dice

Las directivas que tu versión de Unbound no soporte se detectan y se eliminan
automáticamente, en vez de dejar el servicio sin arrancar.

Desde la opción **14** puedes restaurar cualquier copia anterior.

## El detector de "¿lo usa alguien?"

El fallo más común no es la configuración: es que el router siga repartiendo su
propio DNS y el servidor esté de adorno. El chequeo (opción 2) mira cuántos
clientes lo usan de verdad y avisa si son sospechosamente pocos.

Si te sale ese aviso, el arreglo está en el **DHCP de tu router**: pon la IP de
la Pi como **único** servidor DNS. Dejar uno público de secundario hace que el
filtrado se salte de forma intermitente y difícil de diagnosticar.

## Compatibilidad

| Sistema | Estado |
|---|---|
| Raspberry Pi OS (Debian 13) | Probado en Pi 3B |
| Debian 12 / 13 | Probado en contenedor |
| Ubuntu 20.04+ | Soportado — ver nota |

En **Ubuntu**, `systemd-resolved` ocupa el puerto 53 por defecto y Pi-hole no
podría arrancar. El instalador lo detecta y lo resuelve con un drop-in en
`/etc/systemd/resolved.conf.d/no-stub.conf`, desactivando solo el stub y
dejando el servicio funcionando para el resto del sistema.

El cambio de IP requiere **NetworkManager**. Con netplan o ifupdown el script se
niega y te indica dónde tocar, en vez de dejarte sin acceso a la máquina.

Pi-hole **v6**. Con v5 detecta la versión y avisa en lugar de romper cosas.

## Estado de las pruebas

Verificado ejecutándolo, no solo revisando el código:

- Panel en UTF-8 y en ASCII, detección de hardware en Pi y en x86, dimensionado
  por RAM, generación y validación de config, arranque real del servicio,
  **rollback automático**, rechazo de puertos en conflicto e inválidos, cambio
  de puerto aplicado y persistido, degradación correcta sin Pi-hole instalado.
- `shellcheck -S warning` limpio.

**Sin probar en vivo:** la instalación de Pi-hole de cero, la ruta de
`systemd-resolved` en un Ubuntu real, el cambio de IP y las opciones de
Tailscale. Llevan copia de seguridad y reversión, pero si puedes, pruébalas
antes en una máquina de repuesto.

## Panel web (opcional)

`dashboard.py` es un panel **web** de solo lectura, aparte del TUI:

```bash
sudo python3 dashboard.py --port 8080 --auth usuario:contraseña
```

Muestra estado de servicios, dominios bloqueados, listas activas y un botón para
reiniciar. Por defecto escucha solo en `127.0.0.1`; usa `--host 0.0.0.0` para
abrirlo a la red, y en ese caso **pon siempre `--auth`**.

## Desinstalar los añadidos

```bash
sudo systemctl disable --now dns-prewarm.timer tailscale-udp-gro.service
sudo rm -f /etc/systemd/system/dns-prewarm.{service,timer} \
           /etc/systemd/system/tailscale-udp-gro.service \
           /usr/local/bin/dns-prewarm.sh \
           /etc/sysctl.d/99-nexo-dns.conf /etc/sysctl.d/99-nexo-bbr.conf
sudo systemctl daemon-reload
```

Esto no toca Pi-hole ni Unbound, solo lo que añade este script.

## Requisitos

- Raspberry Pi OS, Debian 11+ o Ubuntu 20.04+
- `systemd`, `bash`, `curl`, `dnsutils`, `iproute2`
- Root
- Python 3 solo para `dashboard.py`

---

<div align="center"><sub>Creado por <b>nexo</b> · MIT</sub></div>
