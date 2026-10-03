# Cambios

## 4.4

- Firewall: incluye todos los puertos HTTP/HTTPS de Pi-hole y los puertos
  cifrados de AdGuard Home. Valida puertos, protege el puerto nuevo antes de
  cambiarlo y rechaza conflictos con SSH.
- Confianza: limita el acceso predeterminado a las redes privadas conectadas,
  loopback, IPv6 link-local y la interfaz Tailscale. Otras redes requieren
  configuración explícita en `/etc/nexo-dns-trusted.conf`.
- Aplicación: valida y carga reglas de forma atómica, conserva tablas ajenas,
  comprueba respuestas DNS reales y restaura el estado previo ante fallos.
  Guarda copias privadas y configura la carga del firewall antes de la red.
- Auditoría: comando `audit` y opción en Seguridad para revisar servicios,
  Unbound, firewall, SSH y paquetes pendientes sin cambiar la configuración.
- Panel web: solo lectura por defecto, reinicios explícitos, archivo privado
  para credenciales, validación de Host, defensa CSRF y escape de datos HTML.
  Limita conexiones y tiempo de lectura. Debe permanecer en una red privada.
- Instalador: detecta exposición IPv6 también en una Raspberry y evita
  interpolar nombres de conexiones de red en órdenes privilegiadas.
- Verificación: amplía las regresiones Python/Bash y añade tráfico real de
  firewall en namespaces aislados a GitHub Actions.

Actualizar el archivo del script no aplica reglas ni actualiza los paquetes
del sistema. Sigue la sección de actualización del README. Este firewall
protege DNS y paneles; SSH, NTP y otros servicios necesitan su propia política.
