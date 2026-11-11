// Auditoría mensual de Alevate Studio.
// Lee la lista de repos del vault (privado), revisa secretos, dependencias y cabeceras,
// escribe el reporte en el vault y avisa por Telegram si hay hallazgos críticos.
//
// ESTE REPO ES PÚBLICO y sus logs de Actions también: el script NO imprime nombres de repos,
// rutas ni hallazgos. Solo totales. El detalle va únicamente al reporte del vault.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const VAULT = process.env.VAULT_DIR || 'vault';
const LISTA = join(VAULT, '11-Seguridad-Legal/auditorias/repos.json');
const SALIDA = join(VAULT, '11-Seguridad-Legal/auditorias');
const tokens = { javier: process.env.TOKEN_JAVIER, franco: process.env.TOKEN_FRANCO };
const hoy = new Date().toISOString().slice(0, 10);

const correr = (cmd, args, opts = {}) => {
  try {
    return { ok: true, out: execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 << 20, ...opts }) };
  } catch (e) {
    return { ok: false, out: String(e.stdout || ''), code: e.status };
  }
};

const hallazgos = []; // { severidad, repo, tipo, detalle }
const agregar = (severidad, repo, tipo, detalle) => hallazgos.push({ severidad, repo, tipo, detalle });

async function revisarRepo({ repo, token, url, directorio = '.' }) {
  const dir = mkdtempSync(join(tmpdir(), 'aud-'));
  try {
    const t = tokens[token];
    if (!t) { agregar('alto', repo, 'auditoría', `Falta el token "${token}" para clonar`); return; }
    const clon = correr('git', ['clone', '--quiet', `https://x-access-token:${t}@github.com/${repo}.git`, dir]);
    if (!clon.ok) { agregar('alto', repo, 'auditoría', 'No se pudo clonar (¿token vencido o sin acceso?)'); return; }

    // Secretos: --redact para que el reporte nunca tenga el valor.
    const informe = join(dir, '..', `${repo.replace('/', '_')}-gitleaks.json`);
    correr('gitleaks', ['git', '--redact', '--no-banner', '--exit-code', '0', '--report-format', 'json', '--report-path', informe, dir]);
    if (existsSync(informe)) {
      for (const f of JSON.parse(readFileSync(informe, 'utf8') || '[]')) {
        agregar('crítico', repo, 'secreto', `${f.RuleID} en \`${f.File}\` línea ${f.StartLine} (commit ${String(f.Commit).slice(0, 7)}) — **rotar la llave**, no copiar el valor`);
      }
      rmSync(informe, { force: true });
    }

    // Dependencias.
    const lock = join(dir, directorio, 'package-lock.json');
    if (existsSync(lock)) {
      const r = correr('npm', ['audit', '--package-lock-only', '--json'], { cwd: join(dir, directorio) });
      try {
        const v = JSON.parse(r.out).metadata?.vulnerabilities || {};
        if (v.critical) agregar('crítico', repo, 'dependencias', `${v.critical} vulnerabilidades críticas (npm audit)`);
        if (v.high) agregar('alto', repo, 'dependencias', `${v.high} vulnerabilidades altas (npm audit)`);
        if (v.moderate) agregar('medio', repo, 'dependencias', `${v.moderate} moderadas`);
        if (v.low) agregar('bajo', repo, 'dependencias', `${v.low} bajas`);
      } catch {
        agregar('medio', repo, 'dependencias', 'No se pudo leer npm audit');
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  if (url) await revisarSitio(repo, url);
}

async function revisarSitio(repo, url) {
  let r;
  try { r = await fetch(url, { redirect: 'follow' }); } catch { agregar('alto', repo, 'sitio', `${url} no responde`); return; }
  if (!r.ok) agregar('alto', repo, 'sitio', `${url} responde ${r.status}`);
  const h = (n) => r.headers.get(n);
  if (!h('strict-transport-security')) agregar('medio', repo, 'cabeceras', 'Falta HSTS');
  if (!h('content-security-policy')) agregar('medio', repo, 'cabeceras', 'Falta CSP');
  if (!h('x-frame-options') && !(h('content-security-policy') || '').includes('frame-ancestors')) agregar('medio', repo, 'cabeceras', 'Falta protección contra iframes');
  if (h('x-content-type-options') !== 'nosniff') agregar('bajo', repo, 'cabeceras', 'Falta X-Content-Type-Options');
  try {
    const st = await fetch(new URL('/.well-known/security.txt', url));
    const texto = st.ok ? await st.text() : '';
    const exp = texto.match(/^Expires:\s*(.+)$/mi);
    if (!st.ok) agregar('bajo', repo, 'security.txt', 'No existe');
    else if (exp && new Date(exp[1]) < new Date(Date.now() + 30 * 864e5)) agregar('bajo', repo, 'security.txt', `Vence ${exp[1].slice(0, 10)}`);
  } catch { /* ya reportado arriba si el sitio no responde */ }
}

const orden = ['crítico', 'alto', 'medio', 'bajo'];
const lista = JSON.parse(readFileSync(LISTA, 'utf8'));
for (const item of lista) await revisarRepo(item);

const conteo = Object.fromEntries(orden.map((s) => [s, hallazgos.filter((h) => h.severidad === s).length]));
const filas = hallazgos
  .sort((a, b) => orden.indexOf(a.severidad) - orden.indexOf(b.severidad))
  .map((h) => `| ${h.severidad} | ${h.repo} | ${h.tipo} | ${h.detalle.replace(/\|/g, '\\|')} |`);

const reporte = `---
tipo: auditoria
estado: ${conteo['crítico'] ? 'critico' : 'ok'}
servicios: [web, sistema, hq]
plataforma: ambas
actualizado: ${hoy}
fuentes:
  - https://github.com/gitleaks/gitleaks
  - https://docs.npmjs.com/cli/commands/npm-audit
criticos: ${conteo['crítico']}
altos: ${conteo.alto}
medios: ${conteo.medio}
bajos: ${conteo.bajo}
---
# Auditoría mensual ${hoy}
#seguridad · Volver a [[00-Indice]] · Generada por \`javi0889/alevate-seguridad\` (Actions)

**Resumen:** ${conteo['crítico']} críticos · ${conteo.alto} altos · ${conteo.medio} medios · ${conteo.bajo} bajos · ${lista.length} repos revisados.

${filas.length ? '| Severidad | Repo | Tipo | Detalle |\n|---|---|---|---|\n' + filas.join('\n') : 'Sin hallazgos. ✅'}

> Los secretos se reportan sin su valor. Si aparece uno: rotarlo primero → [[seguridad/secretos-y-api-keys]].
`;
mkdirSync(SALIDA, { recursive: true });
writeFileSync(join(SALIDA, `${hoy}-auditoria-mensual.md`), reporte);

console.log(`Repos: ${lista.length} · críticos ${conteo['crítico']} · altos ${conteo.alto} · medios ${conteo.medio} · bajos ${conteo.bajo}`);

const { TELEGRAM_BOT_TOKEN: bot, TELEGRAM_CHAT_ID: chat } = process.env;
if (bot && chat) {
  const texto = conteo['crítico']
    ? `🚨 Auditoría mensual ${hoy}: ${conteo['crítico']} hallazgo(s) CRÍTICO(S). Detalle en el vault: 11-Seguridad-Legal/auditorias/${hoy}-auditoria-mensual.md`
    : `✅ Auditoría mensual ${hoy}: 0 críticos, ${conteo.alto} altos, ${conteo.medio} medios, ${conteo.bajo} bajos. Reporte en el vault.`;
  await fetch(`https://api.telegram.org/bot${bot}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chat, text: texto }),
  }).catch(() => console.log('No se pudo avisar por Telegram'));
}
if (conteo['crítico']) process.exitCode = 1; // el run queda en rojo y GitHub avisa por correo
