# Seguridad

## Versiones con soporte

La rama `main` es la única versión que recibe correcciones de seguridad.

## Informar de una vulnerabilidad

No abras una incidencia pública si el problema puede exponer un resolver DNS,
ejecutar órdenes como `root`, evadir la autenticación o revelar credenciales.
Usa **Security → Report a vulnerability** en GitHub para enviar un informe
privado con:

- versión o commit afectado;
- sistema operativo y arquitectura;
- pasos mínimos para reproducirlo;
- impacto esperado;
- cualquier mitigación temporal conocida.

No incluyas contraseñas, claves de Tailscale, IP privadas ni copias completas
de `/etc/pihole` en el informe.

## Despliegue seguro del panel

El panel web debe permanecer en `127.0.0.1` siempre que sea posible. Para
acceso remoto, usa Tailscale o un proxy HTTPS. Basic Auth autentica, pero no
cifra el tráfico por sí sola.

Desde 4.4, el panel es de solo lectura salvo `--allow-restart`. Usa
`--auth-file` (archivo propio con permisos 600) en lugar de contraseñas en argv.
Los límites de conexión y lectura son defensas parciales: `http.server` no es
un servidor recomendado para producción pública. El acceso remoto recomendado
es un túnel SSH o Tailscale con permisos restringidos.
Se valida el encabezado Host; una escucha global exige nombres permitidos
explícitos mediante `--allowed-host`. No se aceptan Host arbitrarios del navegador.

El firewall `nexo_dns` protege los puertos del DNS y del panel del filtro,
incluyendo HTTPS de Pi-hole. No equivale a una política de bloqueo general:
SSH, NTP, mDNS y otros servicios requieren reglas específicas si el servidor
tiene acceso público. La IP de origen privada no sustituye una identidad:
para accesos remotos se verifica `tailscale0`, no el rango CGNAT completo.

Verifica accesibilidad desde otro equipo y persistencia después de reiniciar.
Las pruebas en un namespace local no prueban el router ni el proveedor.
Un CVE listado por versión no confirma explotación; contrasta los parches de
la distribución y los requisitos concretos. No ejecutes una prueba DoS sobre
el DNS que usa tu red para confirmar Slowloris.
