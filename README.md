# alevate-seguridad

Workflows y reglas de seguridad de Alevate Studio. **Repo público: aquí no va ningún secreto, nombre de cliente ni hallazgo.** La documentación completa está en el vault privado (`11-Seguridad-Legal/`).

## Qué hay
| Archivo | Para qué |
|---|---|
| `.github/workflows/revision.yml` | Workflow **reutilizable**: gitleaks (todo el historial), `npm audit` y cabeceras de seguridad |
| `.github/workflows/auditoria.yml` + `auditoria/auditar.mjs` | Auditoría **reutilizable**. No corre aquí: la llama con su cron el repo privado `javi0889/alevate-auditoria`, donde viven los secretos y los registros |
| `reglas/vercel.md`, `reglas/cloudflare.md` | Reglas de firewall y rate limiting listas para copiar, por plan |
| `hooks/bloquear-secretos.mjs` | Hook de Claude Code que bloquea escribir o commitear secretos |
| `scripts/verificar-cabeceras.mjs` | Revisa las cabeceras de un sitio publicado |

## Usar la revisión en un repo (de cualquiera de las dos cuentas)
Crear `.github/workflows/seguridad.yml` en el repo:
```yaml
name: Seguridad
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 13 * * 1' # lunes 7 a. m. CR
permissions:
  contents: read
jobs:
  seguridad:
    uses: javi0889/alevate-seguridad/.github/workflows/revision.yml@main
    with:
      url: https://dominio-del-cliente.com # opcional
      nivel-audit: high
```
Funciona entre cuentas porque este repo es público. No necesita secretos.
Para fijar una versión exacta, cambiar `@main` por el SHA de un commit.

## Auditoría
Este repo **no tiene secretos ni cron**. La auditoría la dispara el repo privado `javi0889/alevate-auditoria`
(cron mensual + secretos), y los registros de Actions quedan allá. El script igual imprime solo totales.
La lista de repos y URLs a revisar vive en el vault privado (`11-Seguridad-Legal/auditorias/repos.json`).

## Instalar el hook de Claude Code
Copiar `hooks/bloquear-secretos.mjs` a `%USERPROFILE%\.claude\hooks\` y agregar a `%USERPROFILE%\.claude\settings.json`:
```json
"hooks": {
  "PreToolUse": [
    {
      "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash|PowerShell",
      "hooks": [{ "type": "command", "command": "node \"%USERPROFILE%\\.claude\\hooks\\bloquear-secretos.mjs\"", "timeout": 15 }]
    }
  ]
}
```
