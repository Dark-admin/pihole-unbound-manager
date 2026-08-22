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
