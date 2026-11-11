# Reglas de firewall para Vercel

Fuentes (consultado 2026-11-11): https://vercel.com/docs/vercel-firewall/vercel-waf/custom-rules · https://vercel.com/docs/vercel-firewall/vercel-waf/rate-limiting · https://vercel.com/docs/cli/firewall

Requisitos: `vercel link` en la carpeta del proyecto. Los cambios quedan como **borrador**: revisar con `vercel firewall diff` y publicar con `vercel firewall publish --yes` (lo corre una persona, no Claude).

**Siempre en etapas:** primero `log`, revisar el tráfico en `https://vercel.com/<equipo>/<proyecto>/firewall/traffic?filter=<rule_id>` por unos días, después bloquear.

## Hobby (máx. 3 reglas, 1 de rate limiting) — solo sitios NO comerciales

```bash
# 1. Rate limiting del formulario (la única permitida en Hobby)
vercel firewall rules add "Formulario: 5 por IP cada 10 min" \
  --condition '{"type":"path","op":"eq","value":"/api/contacto"}' \
  --condition '{"type":"method","op":"eq","value":"POST"}' \
  --action rate_limit --rate-limit-window 600 --rate-limit-requests 5 \
  --rate-limit-keys ip --rate-limit-action log --yes

# 2. Bloquear sondeos comunes (no existen en nuestros sitios)
vercel firewall rules add "Sondeos" \
  --condition '{"type":"path","op":"re","value":"^/(wp-admin|wp-login\\.php|xmlrpc\\.php|\\.env|\\.git/|phpmyadmin)"}' \
  --action log --yes

# 3. Métodos que el sitio no usa
vercel firewall rules add "Métodos raros en /api" \
  --condition '{"type":"path","op":"pre","value":"/api/"}' \
  --condition '{"type":"method","op":"inc","neg":true,"value":["GET","POST","OPTIONS"]}' \
  --action log --yes
```
Cuando el tráfico se vea bien: `vercel firewall rules edit "<nombre>" --action deny --yes` (o en la 1, `--rate-limit-action rate_limit`).

## Pro (hasta 40 reglas) — lo de Hobby, más:

```bash
# API de sistemas (pedidos, citas): 60 por IP por minuto
vercel firewall rules add "API: 60 por minuto" \
  --condition '{"type":"path","op":"pre","value":"/api/"}' \
  --action rate_limit --rate-limit-window 60 --rate-limit-requests 60 \
  --rate-limit-keys ip --rate-limit-action log --yes

# Login: 10 por IP por minuto, bloqueo 15 min (duración solo en Pro)
vercel firewall rules add "Login: 10 por minuto" \
  --condition '{"type":"path","op":"eq","value":"/api/login"}' \
  --condition '{"type":"method","op":"eq","value":"POST"}' \
  --action rate_limit --rate-limit-window 60 --rate-limit-requests 10 \
  --rate-limit-keys ip --rate-limit-action log --yes

# Panel solo desde Costa Rica (si el cliente lo pide; ojo con quien viaja)
vercel firewall rules add "Admin solo CR" \
  --condition '{"type":"path","op":"pre","value":"/admin"}' \
  --condition '{"type":"geo_country","op":"eq","neg":true,"value":"CR"}' \
  --action log --yes
```

Notas
- Los contadores son **por región**: el límite real puede ser varias veces mayor. Por eso el código también limita (`servidor/contacto.js` de plantilla-web).
- En Hobby, la doc permite responder 429, pero hay reportes de que abre el aviso de pasar a Pro #por-verificar.
- **Modo ataque** (`vercel firewall attack-mode enable`) lo activa una persona durante un incidente.
