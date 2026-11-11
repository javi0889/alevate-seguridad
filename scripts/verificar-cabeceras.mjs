// Revisa que un sitio publicado tenga las cabeceras de seguridad de la plantilla.
// Uso: node scripts/verificar-cabeceras.mjs https://ejemplo.com
// Sale con código 1 si falta alguna (lo usa el CI de alevate-seguridad en la Fase 3).
const url = process.argv[2];
if (!url) {
  console.error('Uso: node scripts/verificar-cabeceras.mjs <url>');
  process.exit(2);
}

const requeridas = {
  'strict-transport-security': (v) => /max-age=(\d+)/.test(v) && Number(v.match(/max-age=(\d+)/)[1]) >= 31536000,
  'content-security-policy': (v) => v.includes("default-src") && v.includes("frame-ancestors"),
  'x-frame-options': (v) => /deny|sameorigin/i.test(v),
  'x-content-type-options': (v) => v.toLowerCase() === 'nosniff',
  'referrer-policy': (v) => v.length > 0,
  'permissions-policy': (v) => v.length > 0,
};

const r = await fetch(url, { redirect: 'follow' });
let fallas = 0;
for (const [nombre, ok] of Object.entries(requeridas)) {
  const valor = r.headers.get(nombre);
  const bien = valor !== null && ok(valor);
  if (!bien) fallas++;
  console.log(`${bien ? 'OK   ' : 'FALTA'} ${nombre}${valor ? '' : ' (no está)'}`);
}
const st = await fetch(new URL('/.well-known/security.txt', url));
console.log(`${st.ok ? 'OK   ' : 'AVISO'} /.well-known/security.txt (${st.status})`);
process.exit(fallas ? 1 : 0);
