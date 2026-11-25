// Bildschirmfotos der Admin-Seite in mehreren Groessen (Handy, Tablet, PC) – optional aus tests/e2e.sh (SHOT_DIR=...)
//   node tests/shot.js <url> <ordner> [geraet fuer die Bewegungs-Karte]
const { chromium } = require(require.resolve('playwright', { paths: [process.cwd(), '/usr/lib/node_modules', '/usr/local/lib/node_modules'] }));
(async () => {
  const [url, dir, geraet] = process.argv.slice(2);
  const b = await chromium.launch();
  // echte Antworten des Servers aufheben (fuer Layout-Arbeit ohne laufenden Server)
  const fs = require('fs');
  fs.mkdirSync(`${dir}/daten`, { recursive: true });
  for (const f of ['data.json', 'settings.json', 'users.json', `verlauf.json?geraet=${geraet || ''}&tage=0`]) {
    try { const r = await fetch(url + f); fs.writeFileSync(`${dir}/daten/${f.split('?')[0]}`, await r.text()); } catch (e) { console.log('nicht gespeichert:', f, e.message); }
  }
  let fehler = 0;
  for (const [name, w, h] of [['klein', 320, 640], ['handy', 390, 844], ['tablet', 820, 1180], ['pc', 1440, 900]]) {
    const p = await b.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: 1 });
    await p.goto(url, { waitUntil: 'networkidle' });
    await p.waitForTimeout(1500);
    const breit = await p.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    console.log(name, 'waagerecht ueberstehend:', breit, 'px');
    if (breit > 0) fehler++;
    await p.screenshot({ path: `${dir}/admin-${name}.png`, fullPage: true });
    if (geraet && name !== 'tablet') {
      await p.evaluate(g => showMap(g, 0), geraet);
      await p.waitForTimeout(2500);
      await p.screenshot({ path: `${dir}/karte-${name}.png` });
    }
    await p.close();
  }
  await b.close();
  if (fehler) { console.error('Seite ist auf', fehler, 'Bildschirmgroesse(n) breiter als der Bildschirm'); process.exit(1); }
})().catch(e => { console.error(e); process.exit(1); });
