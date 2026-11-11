# Reglas de WAF para Cloudflare

Fuentes (consultado 2026-11-11): https://developers.cloudflare.com/waf/rate-limiting-rules/ · https://developers.cloudflare.com/waf/custom-rules/ · https://developers.cloudflare.com/ruleset-engine/rules-language/

Dónde: panel de Cloudflare → el dominio → **Security → WAF**. Las reglas se aplican a una **zona** (dominio propio en Cloudflare); los `*.pages.dev` no tienen WAF configurable.
Para probar una regla: acción **Log** no existe en Free → usar **Managed Challenge** unos días antes de **Block**.

## Free (1 regla de rate limiting, periodo 10 s; 5 reglas personalizadas #por-verificar)

**Rate limiting — formulario**
- Expresión:
  ```
  (http.request.uri.path eq "/api/contacto" and http.request.method eq "POST")
  ```
- Contar por: IP · Periodo: 10 s · Solicitudes: 3 · Acción: Block · Duración: 10 s

**Regla personalizada — sondeos**
```
(http.request.uri.path contains "/wp-" or http.request.uri.path contains "xmlrpc.php"
 or http.request.uri.path contains "/.env" or http.request.uri.path contains "/.git/"
 or http.request.uri.path contains "phpmyadmin")
```
Acción: Block

**Regla personalizada — métodos raros en /api**
```
(starts_with(http.request.uri.path, "/api/") and not http.request.method in {"GET" "POST" "OPTIONS"})
```
Acción: Block

## Pro (2 reglas de rate limiting, periodo hasta 1 min, bloqueo hasta 1 h)
- Rate limiting — API: `(starts_with(http.request.uri.path, "/api/"))`, 60 por minuto por IP, Block 10 min.
- Rate limiting — login: `(http.request.uri.path eq "/api/login" and http.request.method eq "POST")`, 10 por minuto, Block 1 h.
  (Con 2 reglas, la del formulario entra en la de API o se usa el KV de la plantilla.)

## Alevate HQ (`alevate-hq.pages.dev`)
Al estar en `*.pages.dev` no hay WAF propio. Opciones: dominio propio en Cloudflare (p. ej. `hq.alevatestudio.com`) para usar estas reglas, o limitar en el código de `functions/_middleware.ts` (ya lo hace para el login). → Lista de arreglos del HQ en el vault.

## Turnstile
Gratis: 20 widgets, 10 hostnames por widget. Un widget por cliente; agregar su dominio y `localhost`.
