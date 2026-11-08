# Cambios

## 4.5

- El cambio de motor, los cambios de puerto y las restauraciones comprueban
  la configuración final y recuperan el estado previo ante errores.
- AdGuard se configura con un único upstream local. El firewall cubre el
  puerto HTTPS por UDP si HTTP/3 está activo y verifica su integración con
  la recarga del servicio `nftables` estándar.
- `health` distingue respuestas de bloqueo de fallos de DNS. El precalentado
  usa el historial del motor activo, separa tipos de registro y comprueba el
  código de respuesta DNS.
- `bench --json` separa primer pase y repeticiones por capa, con percentiles y
  recuento de errores. `optimize` admite perfiles explícitos de referrals y
  TTL mínimo para ensayos comparativos con DNSSEC activo. Intenta recargar sin
  vaciar la caché de Unbound cuando la configuración lo permite.
- El panel web comparte una instantánea de estado entre visitas, valida el
  upstream y las interfaces de escucha con más rigor, y aplica un plazo de
  lectura HTTP por conexión. La ventana de clientes de AdGuard se basa en
  timestamps y la lectura del historial está acotada.

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
