<div align="center">

<img src="assets/logo.svg" width="140" alt="logo">

# nexo-dns

**DNS privado, filtrado y recursivo — en casa o en una VPS**

Pi-hole + Unbound + Tailscale, en un solo script con panel de gestión.

![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)
![Pi-hole](https://img.shields.io/badge/Pi--hole%20v6-F60?style=flat-square&logo=pihole&logoColor=white)
![Unbound](https://img.shields.io/badge/Unbound-2BC4DC?style=flat-square)
![Tailscale](https://img.shields.io/badge/Tailscale-242424?style=flat-square&logo=tailscale&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-brightgreen?style=flat-square)
[![CI](https://github.com/Dark-admin/pihole-unbound-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/Dark-admin/pihole-unbound-manager/actions/workflows/ci.yml)

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
  ╔══════════════════════════════════════════════╗
  ║       =++*=              =++=+ +=++=         ║
  ║        *++++=  ++*     ======= =======       ║
  ║         +*+**+==+      ======= =======       ║
  ║           +***#+       ======= =======       ║
  ║           +******      ======= =======       ║
  ║         +*******##*    ====++   ++====       ║
  ║       *####*===*####*  =+#%++   ++%#+=       ║
  ║       #####*   *#####   *%%%%%%%%%%%*        ║
  ║        *###*#**##***     +%%%%%%%%%+         ║
  ║          ********+          +%%%+            ║
  ║            +***+                             ║
  ║                nexo-dns v4.0                 ║
  ╠══════════════════════════════════════════════╣
  ║ ● Pi-hole :53   ● Unbound :5335   ● Tailsca… ║
  ║ ip-172-31-2-205 · 172.31.2.205               ║
  ║ ● Amazon EC2 · DNS cerrado a internet        ║
  ╠══════════════════════════════════════════════╣
  ║ ◆  ESTADO                                    ║
  ║    1 Ver estado                              ║
  ║    2 Chequeo real                            ║
  ╠══════════════════════════════════════════════╣
  ║ ▣  DNS                                       ║
  ║    3 Puerto Unbound 5335                     ║
  ║    4 Puerto Pi-hole 53                       ║
  ║    5 Puerto web 80                           ║
  ║    6 IP del servidor                         ║
  ║    7 Reoptimizar Unbound                     ║
  ║    8 Listas de bloqueo                       ║
  ║    9 Precalentar caché                       ║
  ╠══════════════════════════════════════════════╣
  ║ ▼  SEGURIDAD                                 ║
  ║   10 Exposición y cortafuegos                ║
  ╠══════════════════════════════════════════════╣
  ║ ▲  TAILSCALE                                 ║
  ║   11 Instalar                                ║
  ║   12 Optimizar                               ║
  ╠══════════════════════════════════════════════╣
  ║ ■  SISTEMA                                   ║
  ║   13 Red / BBR                               ║
  ║   14 Reiniciar servicios                     ║
  ║   15 Copias / restaurar                      ║
  ║   16 Instalar todo                           ║
  ╠══════════════════════════════════════════════╣
  ║  0 Salir                                     ║
  ╚══════════════════════════════════════════════╝
```

> Arriba, la talla mediana en una ventana de 50 columnas. En el terminal va
> coloreado: las hojas de Pi-hole en verde y la frambuesa en rojo, los brazos
> de Unbound en cian y el galón en azul.

### Los logotipos

Arte ASCII al estilo de **screenfetch** y **neofetch**, empotrado en el script
como arrays de texto que se pueden editar a mano: son literalmente el dibujo.

El carácter `@` es el **fondo** —el hueco del molinillo de Pi-hole, la
separación entre los brazos de Unbound— y no se pinta, igual que hace neofetch.
Para verlo dibujado, basta darle un color a `LOGO_BG`.

### El tema

El panel **no usa el color por defecto del terminal**. Si lo hiciera heredaría
el verde, el ámbar o lo que tenga el tema de cada uno, y no habría temática que
valga. Todo va explícito, tomado de los dos logotipos:

| Color | Dónde |
|---|---|
| **Rojo `#F0392B`** de Pi-hole | secciones de estado y DNS, y el `▶` del prompt |
| **Cian `#2BC4DC`** de Unbound | seguridad y sistema |
| Gris de Tailscale | su propia sección |
| Hueso sobre negro | las etiquetas |
| Pizarra apagada | bordes y valores |
| Blanco | **los números** |

Los números van en blanco a propósito: son lo único que se teclea, así que son
lo que más contraste tiene. La etiqueta va en texto normal y el valor actual
—el puerto de cada servicio— apagado al lado, que ahorra entrar en una opción
solo para mirar cómo está.

Las opciones van numeradas **del 1 al 16 en el orden en que se leen**. Antes la
16 salía entre la 9 y la 10 porque se añadió al final, y buscarla era un
ejercicio de paciencia.

La tercera línea de estado dice qué pasa, no solo si el servicio arranca:
`● Amazon EC2 · DNS cerrado a internet` en verde, o `▲ DNS abierto a internet`
en ámbar si no hay cortafuegos. Solo sale en máquinas expuestas.

### Se adapta a la ventana

Se mide el terminal en cada redibujado y se elige una de tres tallas. Lo que
manda es el **ancho**: si el cuadro no cabe, el terminal parte cada fila por la
mitad y el dibujo se deshace.

| Ventana | Qué sale |
|---|---|
| 68 columnas y 56 filas o más | Logotipos completos de 30 columnas, menú a dos columnas |
| 40 columnas o más | Los mismos logotipos reducidos a la mitad, 15 columnas |
| Menos | Sin dibujo y menú a una columna — **teléfono de pie** |

Los dibujos pequeños **salen del grande**: se promedia la densidad de cada
bloque de 2×2 y se vuelve a mapear a la misma rampa de caracteres. No son otro
dibujo, por eso se parecen.

Se puede forzar con `NEXO_LOGO=grande`, `mini` o `no`:

```bash
NEXO_LOGO=mini sudo -E bash nexo-dns.sh
```

El color se resuelve al arrancar según lo que soporte el terminal —truecolor,
256 colores, o ninguno— y respeta `NO_COLOR`. Al ser ASCII puro, los dibujos
funcionan igual en un terminal sin UTF-8; ahí los bordes pasan a `+ - |`.

## Órdenes directas

Sin abrir el panel, útiles para cron o scripts:

| Orden | Qué hace |
|---|---|
| `sudo bash nexo-dns.sh install` | Instalación completa |
| `sudo bash nexo-dns.sh status` | Estado de servicios, caché y recursos |
| `sudo bash nexo-dns.sh health` | Chequeo con consultas reales |
| `sudo bash nexo-dns.sh optimize` | Reaplica la optimización de Unbound |
| `sudo bash nexo-dns.sh security` | Qué tienes expuesto a internet |
| `sudo bash nexo-dns.sh firewall` | Cierra el DNS y el panel al exterior |
| `sudo bash nexo-dns.sh banner` | Portada |

## En una VPS

El script detecta si corre en una máquina doméstica o en una VPS pública
(Amazon EC2, DigitalOcean, Hetzner, Vultr, Azure, Google Cloud, OVH, Oracle,
Scaleway, Linode) y cambia lo que te cuenta y lo que comprueba.

**No es un detalle cosmético: el riesgo es otro.** En casa, detrás del router,
lo peor que pasa es quedarte sin internet. En una VPS con IP pública, un
Pi-hole que responda a cualquiera es un **resolver DNS abierto**: se usa para
amplificar ataques DDoS —una consulta de 60 bytes devuelve 4 KB— y acabas con
la máquina suspendida por abuso.

La opción **10** del panel:

- Enseña tu IP pública, todo lo que está escuchando y en qué interfaces
- Comprueba el `listeningMode` de Pi-hole, que es lo que de verdad decide si
  respondes al mundo entero o solo a tu subred
- Instala un cortafuegos con nftables que cierra el DNS y el panel web a
  internet, dejándolos abiertos para loopback, redes privadas y el tailnet

El cortafuegos **no puede dejarte fuera de la máquina**: la política de la
cadena es `accept` y solo se descartan los puertos del DNS y del panel. El SSH
no se toca. Después de cargarlo comprueba que la resolución sigue funcionando
y, si no, se retira solo.

> Esto es el cortafuegos del sistema. Si tu proveedor tiene además grupos de
> seguridad (AWS, Azure, GCP), revísalos: son una segunda puerta por delante
> de esta.

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

Está en la opción 13 porque sí mejora el tráfico TCP —descargas, streaming, y lo
que pase por la máquina si hace de exit node de Tailscale—, pero el panel lo
etiqueta como lo que es. Lo que sí acelera el DNS son la caché, `prefetch`,
`serve-expired` y los buffers UDP del kernel, todo ello ya aplicado.

## Tailscale

La opción **12** aplica tres cosas:

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

Desde la opción **15** puedes restaurar cualquier copia anterior.

## El detector de "¿lo usa alguien?"

El fallo más común no es la configuración: es que el router siga repartiendo su
propio DNS y el servidor esté de adorno. El chequeo (opción 2) mira cuántos
clientes lo usan de verdad y avisa si son sospechosamente pocos.

Si te sale ese aviso en una máquina de casa, el arreglo está en el **DHCP de tu
router**: pon la IP de la Pi como **único** servidor DNS. Dejar uno público de
secundario hace que el filtrado se salte de forma intermitente y difícil de
diagnosticar.

En una VPS no hay DHCP que tocar, así que el aviso te manda al sitio correcto:
revisar que en el panel del tailnet esté marcado *Override local DNS*.

## Compatibilidad

| Sistema | Estado |
|---|---|
| Raspberry Pi OS (Debian 13) | Probado en Pi 3B |
| Debian 12 / 13 | Probado en contenedor |
| Debian 13 en VPS | Probado en Amazon EC2 t3.small |
| Ubuntu 20.04+ | Soportado — ver nota |

En **Ubuntu**, `systemd-resolved` ocupa el puerto 53 por defecto y Pi-hole no
podría arrancar. El instalador lo detecta y lo resuelve con un drop-in en
`/etc/systemd/resolved.conf.d/no-stub.conf`, desactivando solo el stub y
dejando el servicio funcionando para el resto del sistema.

El cambio de IP requiere **NetworkManager**. Con netplan o ifupdown el script se
niega y te indica dónde tocar, en vez de dejarte sin acceso a la máquina.

Pi-hole **v6**. Con v5 detecta la versión y avisa en lugar de romper cosas.

## Estado de las pruebas

Verificado ejecutándolo, no solo revisando el código.

**Sobre una VPS real** — Amazon EC2 t3.small, Debian 13, Pi-hole v6.4.3,
Unbound 1.22:

- `status`, `health`, `security` y `banner`
- `health` con consultas reales: DNSSEC aceptando firma válida y **rechazando
  una rota**, filtrado activo, y github.com resolviendo normal
- Detección de plataforma e inventario de exposición
- El cortafuegos **cargado y retirado en caliente**, comprobando que ni el SSH
  ni la resolución se caen
- La instalación de Tailscale (opción 11), que completó correctamente

**El panel**, capturando la salida real y reconstruyéndola a imagen para
comprobarla, no a ojo:

- Seis tamaños de ventana, de 32×24 —teléfono de pie— a 80×60
- Truecolor, 256 colores, `NO_COLOR`, sin UTF-8 y `TERM=dumb`
- Los tres valores de `NEXO_LOGO`
- Que el despacho de las opciones renumeradas lleva a donde dice

**Lo demás:** dimensionado por RAM, generación y validación de config, arranque
real del servicio, **rollback automático**, rechazo de puertos en conflicto e
inválidos, cambio de puerto aplicado y persistido, degradación correcta sin
Pi-hole instalado. Cada cambio se comprueba además en GitHub Actions con
`bash -n`, `shellcheck -S warning`, compilación de Python y pruebas de seguridad
del panel.

**Sin probar en vivo:** la instalación de Pi-hole de cero, la ruta de
`systemd-resolved` en un Ubuntu real y el cambio de IP. Llevan copia de
seguridad y reversión, pero si puedes, pruébalas antes en una máquina de
repuesto.

## Panel web (opcional)

`dashboard.py` es un panel **web** de solo lectura, aparte del TUI:

```bash
sudo python3 dashboard.py --port 8080 --auth usuario:contraseña
```

Muestra estado de servicios, dominios bloqueados, listas activas y un botón para
reiniciar. Por defecto escucha solo en `127.0.0.1`; usa `--host 0.0.0.0` para
abrirlo a la red, y en ese caso **exige `--auth`**. Si se intenta abrir fuera
de localhost sin contraseña, el panel se niega a arrancar. Existe
`--allow-unauthenticated` para laboratorios aislados, pero no se recomienda.

Basic Auth autentica, pero no cifra el tráfico. Para administrarlo desde fuera
de la máquina, accede por Tailscale o colócalo detrás de un proxy HTTPS. El
panel también escapa los datos procedentes de las listas, protege el reinicio
contra peticiones de otros sitios y envía cabeceras de seguridad al navegador.

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
