#!/usr/bin/env node
// Hook PreToolUse de Claude Code (Alevate Studio).
// 1) Write/Edit/MultiEdit/NotebookEdit: bloquea escribir algo con forma de secreto en un
//    archivo que Git NO ignora. (En .env.local o .dev.vars sí se permite: están en .gitignore.)
// 2) Bash/PowerShell con "git commit" o "git push": revisa lo que está en stage
//    (o los commits sin subir) y bloquea si encuentra un secreto.
// Salida 2 = bloquear; el motivo va por stderr y Claude lo ve. Nunca imprime el valor.
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { existsSync } from 'node:fs';

const PATRONES = [
  ['llave privada', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['token de GitHub', /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/],
  ['llave de Anthropic', /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ['llave de OpenAI', /\bsk-(proj-)?[A-Za-z0-9_-]{32,}/],
  ['llave de AWS', /\bAKIA[0-9A-Z]{16}\b/],
  ['llave de Google', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['llave de Stripe', /\b[sr]k_live_[0-9A-Za-z]{20,}/],
  ['llave de Resend', /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/],
  ['token de Slack', /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ['token de bot de Telegram', /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/],
  ['secreto de Turnstile', /\b0x4AAAAAA[A-Za-z0-9_-]{20,}/],
  ['token de Vercel', /\bvc[pk]_[A-Za-z0-9]{24,}/],
  ['cadena de conexión con clave', /\b(mongodb(\+srv)?|postgres(ql)?|mysql|redis):\/\/[^:\s/]+:[^@\s<]{6,}@/],
  ['asignación de secreto', /\b(api[_-]?key|secret|token|password|contrase(ñ|n)a|passwd)["']?\s*[:=]\s*["'][^"'\s<>{}$]{16,}["']/i],
];
// Valores públicos o de ejemplo que no son secretos.
const PERMITIDOS = [/1x0{20,}AA/, /<TOKEN>|<URL>|<ID[_A-Z]*>/, /x{8,}/i, /ejemplo|example|dummy|placeholder/i];

const buscar = (texto) => {
  const hallados = new Set();
  for (const linea of String(texto || '').split(/\r?\n/)) {
    if (PERMITIDOS.some((p) => p.test(linea))) continue;
    for (const [nombre, re] of PATRONES) if (re.test(linea)) hallados.add(nombre);
  }
  return [...hallados];
};

const git = (args, cwd) => {
  try { return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 32 << 20 }); }
  catch (e) { return e.status === 1 ? '' : null; }
};

const bloquear = (motivo) => {
  process.stderr.write(`🔒 Bloqueado por el hook de secretos de Alevate: ${motivo}\n` +
    'Los secretos van en .env.local / .dev.vars (en .gitignore) o en la plataforma (Vercel, Cloudflare, GitHub). ' +
    'En archivos versionados usá <TOKEN>. Si es un falso positivo, avisale a Javier.\n');
  process.exit(2);
};

let entrada = '';
for await (const trozo of process.stdin) entrada += trozo;
let datos;
try { datos = JSON.parse(entrada); } catch { process.exit(0); }
const { tool_name: herramienta, tool_input: e = {}, cwd = process.cwd() } = datos;

if (['Write', 'Edit', 'MultiEdit', 'NotebookEdit'].includes(herramienta)) {
  const ruta = e.file_path || e.notebook_path;
  const texto = [e.content, e.new_string, e.new_source, ...(e.edits || []).map((x) => x.new_string)].join('\n');
  const hallados = buscar(texto);
  if (!hallados.length || !ruta) process.exit(0);
  const carpeta = dirname(resolve(cwd, ruta));
  const enRepo = existsSync(carpeta) && git(['rev-parse', '--is-inside-work-tree'], carpeta)?.trim() === 'true';
  // Fuera de un repo (p. ej. scratchpad) o en un archivo ignorado por Git → permitido.
  if (!enRepo) process.exit(0);
  let ignorado = false;
  try { execFileSync('git', ['check-ignore', '-q', resolve(cwd, ruta)], { cwd: carpeta, stdio: 'ignore' }); ignorado = true; } catch { /* 1 = no ignorado */ }
  if (ignorado) process.exit(0);
  bloquear(`${hallados.join(', ')} en ${ruta}, que Git versiona.`);
}

if (['Bash', 'PowerShell'].includes(herramienta)) {
  const cmd = String(e.command || '');
  if (!/\bgit\b[^\n|;&]*\b(commit|push)\b/.test(cmd)) process.exit(0);
  const dir = cmd.match(/\bgit\s+-C\s+("([^"]+)"|'([^']+)'|(\S+))/);
  const repo = dir ? resolve(cwd, dir[2] || dir[3] || dir[4]) : cwd;
  let diff = '';
  if (/\bcommit\b/.test(cmd)) {
    // "commit -a/-am" incluye lo modificado sin stage.
    diff = git(['diff', '--cached', '-U0'], repo) || '';
    if (/\bcommit\b[^\n]*\s-[a-zA-Z]*a/.test(cmd)) diff += git(['diff', '-U0'], repo) || '';
  } else {
    diff = git(['log', '-p', '-U0', '@{u}..HEAD'], repo) || git(['log', '-p', '-U0', '-20'], repo) || '';
  }
  const agregadas = diff.split('\n').filter((l) => l.startsWith('+') && !l.startsWith('+++')).join('\n');
  const hallados = buscar(agregadas);
  if (hallados.length) bloquear(`${hallados.join(', ')} en los cambios que se van a ${/push/.test(cmd) ? 'subir' : 'commitear'}.`);
}
process.exit(0);
